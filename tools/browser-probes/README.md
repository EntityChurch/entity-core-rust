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

Results and what they mean for the WebRTC transport (S3):
`docs/validation/reports/2026-08-02-rtcpeerconnection-worker-scope.md`.

**These are engine-specific by nature.** A result is only claimed for the engine and version it
was measured on — record both. Firefox and Chromium can and do differ here.
