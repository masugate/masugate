# MasuGate protected filesystem operation pack

This independently versioned pack exposes only two `reference-effect`
operations on the logical `/workspace` namespace:

- `fs.write` creates a missing regular file when `expected_prior_digest` is
  the empty string, or atomically replaces one regular file when that field is
  its current lowercase SHA-256 digest.
- `fs.delete` moves one regular file to connector-owned quarantine only when
  `expected_current_digest` is its current lowercase SHA-256 digest.

`content` is a required sealed-artifact field. Hosts stage its UTF-8 bytes
through MasuGate before calling the action; a model never chooses an artifact
reference, certified content digest, byte count, physical root, or quarantine
path. The public empty-string create sentinel is intentionally not a digest.
All non-empty expected digest values are validated by the exact connector.

The pack contains no filesystem path, deployment binding, worker configuration,
host framework code, or connector implementation. Its maturity applies only to
the separately documented Linux/ext4 reference profile.
