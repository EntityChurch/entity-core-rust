#!/usr/bin/env python3
"""Run a browser probe under WebKitGTK and print what it reported.

Why this exists
---------------
The probes answer runtime questions a compile cannot ("does this API exist and
work *here*"), and a result is only ever claimed for the engine it was measured
on. Firefox was measured 2026-08-02. **WebKitGTK was not**, and it is a live
shipping target: `entity-browser-rust`'s Tauri desktop path runs on it, and that
repo's AGENTS.md records the exact failure class these probes exist for — "green
in Firefox/Selenium != works in WebKitGTK (Tauri Linux lags Apple WebKit by
years; missing WorkerNavigator.storage bit us)."

Two deliberate choices
----------------------
**Served over http://127.0.0.1, not file://.** Several WebRTC and storage APIs
are gated on a secure context. `file://` is treated inconsistently across
engines, so a refusal there would look exactly like "the engine lacks WebRTC"
while actually being "the origin wasn't trustworthy." localhost is a secure
context everywhere, which removes that whole class of false negative.

**console.log, not dump().** `dump()` is Firefox-only and pref-gated. WebKitGTK
writes console messages to stdout when
`WebKitSettings:enable-write-console-messages-to-stdout` is set, so the probes
emit both and one file serves every engine.

Exit status is the probe's verdict where it has one: 0 if a `result=PASS` line
was seen, 1 otherwise. A harness failure (no output at all) is also 1 — a probe
that could not run is not a probe that passed.
"""

import functools
import http.server
import os
import socket
import socketserver
import sys
import threading

import gi

# WebKit 6.0 (GTK4) is the newer binding; WebKit2 4.1 (GTK3) is what Debian
# bookworm and Tauri's own dependency carry. Try new first, fall back — the
# probe cares about the engine, not the toolkit generation.
_API = None
try:
    gi.require_version("WebKit", "6.0")
    gi.require_version("Gtk", "4.0")
    from gi.repository import WebKit as WebKitAPI  # type: ignore
    from gi.repository import Gtk

    _API = "WebKit 6.0 / GTK4"
except (ValueError, ImportError):
    gi.require_version("WebKit2", "4.1")
    gi.require_version("Gtk", "3.0")
    from gi.repository import WebKit2 as WebKitAPI  # type: ignore
    from gi.repository import Gtk

    _API = "WebKit2 4.1 / GTK3"

from gi.repository import GLib


def serve(directory):
    """Serve `directory` on an ephemeral loopback port; return the port."""
    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=directory
    )

    class Quiet(socketserver.TCPServer):
        allow_reuse_address = True

        def handle_error(self, request, client_address):
            pass  # a probe closing its window mid-request is not an error

    with socket.socket() as probe_sock:
        probe_sock.bind(("127.0.0.1", 0))
        port = probe_sock.getsockname()[1]

    httpd = Quiet(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return port


def main():
    if len(sys.argv) < 2:
        print("usage: webkit-harness.py <probe.html> [timeout_seconds]", file=sys.stderr)
        return 1
    probe = sys.argv[1]
    timeout_s = int(sys.argv[2]) if len(sys.argv) > 2 else 40

    here = os.path.dirname(os.path.abspath(__file__))
    if not os.path.exists(os.path.join(here, probe)):
        print(f"no such probe: {probe}", file=sys.stderr)
        return 1

    port = serve(here)
    url = f"http://127.0.0.1:{port}/{probe}"

    print(f"===HARNESS=== engine=WebKitGTK api={_API} url={url}", flush=True)

    view = WebKitAPI.WebView()
    settings = view.get_settings()
    # Route console.log to stdout — this is the reporting channel.
    settings.set_property("enable-write-console-messages-to-stdout", True)
    # Best-effort enable of the media/WebRTC surface. Property names differ
    # across WebKitGTK versions, so each is attempted independently: a missing
    # property must not abort the run, because "this build has no such knob" is
    # itself part of what we are measuring.
    for prop in ("enable-media-stream", "enable-webrtc", "enable-mock-capture-devices"):
        try:
            settings.set_property(prop, True)
        except (TypeError, ValueError):
            print(f"===HARNESS=== note: settings property absent: {prop}", flush=True)

    # WebKitGTK 2.42+ moved experimental/development toggles out of plain
    # GObject properties into a WebKitFeature list. A `enable-webrtc` property
    # that accepts True while `RTCPeerConnection` stays undefined is exactly the
    # symptom of the real switch living here instead, so enumerate and report —
    # "the feature exists but is off" and "the build has no such feature" are
    # very different answers and only this distinguishes them.
    try:
        flist = WebKitAPI.Settings.get_all_features()
        matched = 0
        for i in range(flist.get_length()):
            feat = flist.get(i)
            ident = (feat.get_identifier() or "")
            if any(k in ident.lower() for k in ("webrtc", "peerconnection", "rtc")):
                matched += 1
                print(
                    f"===HARNESS=== feature {ident} default={feat.get_default_value()}",
                    flush=True,
                )
                try:
                    settings.set_feature_enabled(feat, True)
                    print(f"===HARNESS=== feature {ident} -> enabled", flush=True)
                except Exception as exc:  # noqa: BLE001 - reporting, not handling
                    print(f"===HARNESS=== feature {ident} enable failed: {exc}", flush=True)
        print(f"===HARNESS=== rtc-related features found: {matched}", flush=True)
    except (AttributeError, TypeError) as exc:
        print(f"===HARNESS=== note: feature API unavailable: {exc}", flush=True)

    loop = GLib.MainLoop()

    def stop(reason):
        print(f"===HARNESS=== stopping: {reason}", flush=True)
        if loop.is_running():
            loop.quit()

    # The probes call window.close() when done; honour it as the success path.
    view.connect("close", lambda *_: stop("probe closed its window"))
    view.connect(
        "load-failed",
        lambda *_: (stop("load-failed"), False)[1],
    )
    GLib.timeout_add_seconds(timeout_s, lambda: (stop("timeout"), False)[1])

    # A window is required for the view to actually run in some builds; keep it
    # offscreen-ish under Xvfb rather than trying to be headless natively.
    if _API.startswith("WebKit 6.0"):
        win = Gtk.Window()
        win.set_child(view)
        win.present()
    else:
        win = Gtk.Window()
        win.add(view)
        win.show_all()

    view.load_uri(url)
    loop.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
