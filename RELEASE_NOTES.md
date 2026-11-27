## Daily-driver ergonomics

This release adds five workflow and validation improvements for inspecting, verifying, and scripting JWT and JWE tokens.

## What's new

**Copy-paste cleanup for token input.** `jwtd` now strips optional `Authorization:` and `Bearer ` prefixes (case-insensitive) as well as matching surrounding single or double quotes, so tokens copied from browser DevTools, `curl -v`, or logs decode directly without manual trimming. Prefix-only input such as `Authorization: Bearer` is still rejected as `no token provided`.

**Expanded claim validation and algorithm pinning.** Alongside `--verify-claims`, `--aud`, and `--iss`:
- `--sub` requires an exact `sub` claim match (and implies `--verify-claims`).
- `--leeway` configures clock-skew tolerance (for example, `30s`) on `exp` and `nbf` checks.
- `--require-exp` requires the `exp` claim to be present.
- `--alg` pins the expected token `alg` header and fails closed before key loading, verification, or decryption if a JWT or JWE uses another algorithm.
- `--at` evaluates both timestamp annotations and claim validation at a given RFC3339 timestamp or Unix second count.

**Quiet exit-code mode.** `-q` / `--quiet` suppresses stdout while keeping exit codes and stderr diagnostics unchanged for scripting and CI checks.

**Timezone display and OIDC timestamps.** Human output now formats `auth_time` and `updated_at` alongside `iat`, `exp`, and `nbf`. Pass `--local` for the system timezone or `--tz <IANA-zone>` (backed by embedded `time/tzdata`) to override the default UTC display; `--json` continues to emit raw numeric timestamps.

**JWK Set disambiguation by `use` and `alg`.** When multiple JWK Set entries share a `kid` (or when a token carries no `kid`), `jwtd` now narrows candidates by expected `use` (`sig` for JWS, `enc` for JWE) and header `alg` before falling back to the first matching entry.
