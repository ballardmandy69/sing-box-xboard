# Local source provenance

Source: https://github.com/SagerNet/sing-shadowsocks

Pinned version: `v0.2.9-0.20260929204512-65740e0f0e3e`, copied from the Go module cache
before local edits. The upstream `LICENSE` remains included. This local replacement changes
legacy Shadowsocks multi-user candidate selection and fixes Shadowsocks 2022 server response
concurrency. It does not change wire formats or cryptographic primitives.

Legacy AEAD multi-user services publish full and hot method maps under their existing mutex.
Authentication tries hot candidates first, then the remaining full table without retrying
hot candidates. Cold users remain authorized. Credential changes rebuild hot entries from
the new full table, preventing stale keys from remaining valid in the hot subset.

A successful cold-table header authentication can notify an optional callback asynchronously.
It passes the immutable authenticated user value before reading the destination, matching
the observed nyafw ordering. Hot matches and explicitly hinted matches do not invoke it.

`ContextWithUserHint` carries a typed user identity for wrappers that have already selected
a candidate. The legacy service still decrypts and validates the supplied password. Unknown
or incorrect hints fail without falling back to another user. This is a candidate selection
hint, never an authentication bypass. Shadowsocks 2022 ignores it and retains identity-header
lookup; its original nyafw hot-list methods are no-ops.

Linux Go 1.26.5 validation passed:

- `go test -race github.com/sagernet/sing-vmess github.com/sagernet/sing-shadowsocks/shadowaead -count=1 -timeout=35s`
- `go test -race ./protocol/vmess ./protocol/shadowsocks ./service/xboard -count=1 -timeout=45s`
- `go test -race ./protocol/shadowsocks -count=1 -timeout=30s` after adding the managed hot-user integration test.

Tests use actual legacy Shadowsocks encrypted streams. They cover hot/cold ordering,
wrong and unknown hints, immutable callback/routing identities, concurrent user reordering,
password rotation and old-password rejection. They do not claim a runtime comparison against
the original nyafw executable, which was never executed during this analysis.

## Shadowsocks 2022 server response concurrency

The real shared-password SS-obfs integration exposed a race between the first response's
writer assignment and `serverConn.Close` inspecting that pointer. The pinned AEAD reader and
writer do not implement Close or own independently closable resources. `serverConn.Close`
now closes only the underlying connection and never waits for the write mutex, so it can
interrupt blocked I/O.

All `serverConn.Write` and `WriteVectorised` calls hold the existing write mutex for their
complete operation. Atomic publication alone would not suffice: the pinned AEAD writer
unlocks its shared ciphertext buffer before sending it to the underlying writer. Full
serialization prevents another concurrent call from modifying that buffer or reordering
AEAD nonces before transmission. This does not serialize reads with writes. Empty vectors
return successfully, matching the underlying writer's existing empty-vector behavior.

Regression tests cover first-write/Close overlap, closing a genuinely blocked net.Pipe,
and mixed concurrent scalar/vector writes whose complete ciphertext is authenticated and
decrypted to verify every payload. The fix is a robustness correction in the reconstruction,
not a claim that the original nyafw binary had identical synchronization.

- `go test -race github.com/sagernet/sing-shadowsocks/shadowaead_2022 -run TestServerConn -count=5 -timeout=45s` passed.
