# Local source provenance

Source: https://github.com/SagerNet/sing-vmess

Pinned version: `v0.2.9-0.20260929152519-9b95ab8c9478`, copied unchanged from the Go module cache before local edits.
The upstream `LICENSE` remains included. No upstream wire format or cryptographic primitive was changed.

Local changes publish VMess and VLESS authentication tables as immutable atomic snapshots.
Each handshake reads matching credentials, identity and flow/key data from one generation.
VMess periodic legacy-key generation uses compare-and-swap so it cannot overwrite a newer user update.
The existing instance-level replay filter is retained across user updates.

VLESS also has an opt-in node-level client-flow policy, stored in the same user snapshot.
It accepts the client's empty/Vision flow, with an optional Vision requirement that exempts
the exact `sp.mux.sing-box.arpa` carrier. The parent inbound uses this for managed users and
explicit `force_vision` settings. Existing static configurations with no `force_vision`
continue to match each user's configured flow. This changes admission policy, not encryption.

Validation on Linux with Go 1.26.5: `go test -race github.com/sagernet/sing-vmess
./protocol/vmess ./route -count=1 -timeout=45s` passed from the parent module.
The integration tests exercise actual VMess and VLESS handshakes while user tables change,
and assert that credentials and accounting identities remain associated with the same user.
The module test also covers concurrent legacy-key refresh and replay-filter continuity.

`go vet` reports the upstream `vless/vision.go:89-90` unsafe.Pointer conversions.
That file is byte-for-byte identical to the pinned upstream source; this patch does not
change Vision/TLS internals or suppress the diagnostics. Vet is therefore not a clean check.

The real TLS/VLESS flow matrix (six policy modes, empty and Vision clients: 12 combinations)
passes without race instrumentation. With `-race`, the unchanged upstream Vision constructor
fails automatic checkptr at `vless/vision.go:89`. The actual Vision integration test therefore
has an explicit `!race` build constraint; no checkptr suppression or Vision code modification
was applied. This is not a claim that real Vision handshakes pass race checks.

`go test -race github.com/sagernet/sing-vmess/vless ./protocol/vmess -count=1 -timeout=40s`
passes for the remaining suite, including real TLS with empty flow, exact SingMux exceptions,
concurrent policy/credential snapshots and actual VMess/VLESS authentication during user updates.
The retained upstream `vless/vision.go` is byte-identical to the pinned module cache copy;
SHA-256: `f8856ae87df2204a40fa11707cf38f447b9b3eb4c4f439a8a00ea0b51226cbdd`.

VMess AEAD authentication now tries a published hot-user subset before the remaining full
user table. Every candidate is tried at most once; cold users remain authorized, and CRC,
timestamp and replay checks remain unchanged. Hot and full tables belong to one immutable
generation. Credential updates rebuild the hot subset using the new ciphers, never old keys.
This changes candidate selection cost, not the protocol wire format. VMess has no successful
authentication hot callback; its managed hot list is maintained from traffic reporting.

Linux Go 1.26.5 checks passed: `go test -race github.com/sagernet/sing-vmess
github.com/sagernet/sing-shadowsocks/shadowaead -count=1 -timeout=35s` and
`go test -race ./protocol/vmess ./protocol/shadowsocks ./service/xboard -count=1 -timeout=45s`.
Hot tests verify ordering, one attempt per candidate, cold fallback, credential rotation,
replay/expiry checks, concurrent publication and real managed authentication during reordering.

## Optional source authentication-failure hooks

`SetAuthenticationFailureHooks(report, blocked)` publishes an immutable callback pair.
TCP checks the source before reading a request and reports only when identity lookup finds
no matching user. Short initial reads, recognized-but-expired identities, replay rejection,
encrypted-header errors and subsequent protocol/business errors do not report failures.
This matches the analyzed `d06a00` unknown-identity branch, not a generic connection-error
counter. The box layer connects the optional callbacks to the same process-wide source policy
as legacy Shadowsocks. Callback publication is safe during concurrent authentication.

Linux race tests passed three times for this package, legacy Shadowsocks, both inbound
packages and `common/authban`. Tests include real TCP clients behind PROXY headers, shared
cross-protocol failure counts, unrelated-source success and disabled-policy behavior.
The original executable was not run; this does not claim a runtime wire comparison.
