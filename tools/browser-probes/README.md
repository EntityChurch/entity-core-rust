# Browser runtime probes

Runtime facts about the browser platform that a **compile cannot establish**. This directory
exists because of the S1 lesson: `web-sys` exposing a binding proves nothing about runtime
availability — bindings compile whether or not the API exists in the scope you need it in.

Each probe is a self-contained HTML file with no dependencies beyond a browser. They report
via `dump()` to stdout, which needs one pref, so run them against a throwaway profile:

```bash
PROFILE=$(mktemp -d)
printf 'user_pref("browser.dom.window.dump.enabled", true);\n' > "$PROFILE/user.js"
firefox --headless --no-remote --profile "$PROFILE" \
    "file://$PWD/tools/browser-probes/rtc-worker-scope.html" 2>&1 \
  | sed -n '/===PROBE-BEGIN===/,/===PROBE-END===/p'
```

Substitute `rtc-datachannel-transfer.html` (and `PROBE2`) for the second probe.

| Probe | Question it answers |
|---|---|
| `rtc-worker-scope.html` | Is `RTCPeerConnection` constructible in a dedicated Worker? |
| `rtc-datachannel-transfer.html` | Can a live `RTCDataChannel` be transferred into a Worker? |

Results and what they mean for the WebRTC transport (S3) are summarised in the engine-coverage
table below. (The full 2026-08-02 measurement report is internal dev history and is not part of
the published tree.)

**These are engine-specific by nature.** A result is only claimed for the engine and version it
was measured on — record both. Firefox and Chromium can and do differ here.

## Engine coverage — what is measured, and what is not

The browser leg targets browsers on Android / Linux / Windows / macOS, which is three engines:
**Blink** (Chrome, Edge, Android WebView, WebView2), **Gecko** (Firefox, incl. Android), and
**WebKit** (Safari/macOS, WKWebView, and **WebKitGTK** — the Tauri Linux WebView).

| Runtime | Engine | Probed? |
|---|---|---|
| Firefox 144.0.2 headless | Gecko | ✅ both probes, 2026-08-02 |
| Chrome / Edge / Android | Blink | ❌ not measured |
| Safari / macOS | WebKit | ❌ not measurable in a Linux container — needs a Mac |
| **WebKitGTK 2.50.6 (Debian bookworm / Tauri)** | WebKit | ⛔ **measured 2026-08-03 — NO WebRTC** |

**WebKitGTK result:** `RTCPeerConnection` is **undefined** — absent from the build, not disabled. Secure
context, all WebRTC settings accepted, full GStreamer `webrtcbin` + `libnice` stack installed, and both
RTC-related `WebKitFeature` toggles enabled; still undefined. `MessagePort` **is** available, so the brokered
`MessageChannel` path works there — it is the WebRTC substrate itself that is missing. Four false-negative
explanations were eliminated before the result was recorded: a secure-context refusal (the probe is served over
`http://127.0.0.1`, not `file://`), a missing settings knob (`enable-webrtc` / `enable-media-stream` /
`enable-mock-capture-devices` were all set and all accepted), a missing GStreamer backend (rebuilt with
`gstreamer1.0-plugins-{base,good,bad}`, `gstreamer1.0-nice`, `libnice10` — no change), and a disabled
experimental feature (the `WebKitFeature` list carries no `PeerConnection` master toggle at all). Peripheral
tuning knobs surviving while the constructor is absent is the signature of the feature being compiled out.
(The full 2026-08-03 write-up is internal dev history and is not part of the published tree.) This is a claim about
**that build**, not about WebKitGTK generally and emphatically not about Apple's WebKit.

**WebKitGTK is in scope, deliberately** (`entity-browser-rust`, 2026-08-03). It is not a hypothetical
port: `make tauri-run` is that repo's live desktop path. Their `AGENTS.md` records the exact failure
class these probes exist for — *"green in Firefox/Selenium ≠ works in WebKitGTK (Tauri Linux lags
Apple WebKit by years; missing `WorkerNavigator.storage` bit us)"* — a **Worker API**, green
everywhere else, absent there. `rtc-datachannel-transfer.html` measures a Worker API. Do not read the
Firefox result as covering it.

**The load-bearing question there is not transfer.** A brokered `MessageChannel` fallback already
covers a missing transfer (`core/peer/src/transport.rs::connection_from_port`). Nothing covers
`RTCPeerConnection` being absent or broken, so `rtc-worker-scope.html`'s companion question — does it
construct and complete a DTLS handshake on the main thread at all — is the one to answer first.

**Reporting channel.** The probes emit via both `dump()` (Firefox, pref-gated) and `console.log`
(everything else), so one file serves every engine. `make probe-webkit` runs any of them under
WebKitGTK in a container; `PROBE=<file.html>` selects which.
