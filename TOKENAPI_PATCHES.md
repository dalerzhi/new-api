# TokenAPI patch inventory for new-api

Upstream: [QuantumNous/new-api](https://github.com/QuantumNous/new-api)

Locked release: `v1.0.0-rc.49`, commit `48a6c87f9e7757fdc58e5be9bcb4f8281ad0dfd0`.

This public fork retains the upstream new-api and QuantumNous attribution,
licenses, module names, interface branding, and release workflows unchanged.
The private platform is a separate repository and communicates over APIs and a
read-only connection to the gateway log database.

## Applied runtime patches

### CP-02: internal provisioning and cumulative quota grants

Enabled only by a `TOKENAPI_INTERNAL_SECRET` of at least 32 bytes; Redis is
required. The internal prefix is `/internal/tokenapi/v1`. Disabling the patch
leaves routes, schema and quota-cache behavior unchanged.

- HMAC-SHA256 binds method, original path/query, timestamp, UUID nonce and raw
  body digest. Duplicate auth headers, expired signatures and nonce replays are
  rejected. Redis `SET NX EX 601` covers the full ±300-second acceptance window
  including its integer-second boundary. Responses are not cacheable.
- Internal token CRUD scopes every operation to the supplied user. Only token
  creation returns a usable key; list/update responses are masked. PATCH writes
  only supplied columns and reuses the upstream cache invalidation mechanism.
- `batch-get` reads relay quota through its cache-first model function.
  `batch-grant` compare-and-sets absolute totals with additive wallet updates,
  preserving concurrent relay deductions. The grant table stores a pending
  delta and revision so cache synchronization can be retried after failures.
- Cache initialization reads wallet quota and grant revision in one SQL
  snapshot. Lua applies each revision once and rejects delayed cache snapshots.
  This is necessary even when cache rebuilding overlaps a negative grant.

New runtime code lives in `controller/tokenapi_internal.go`,
`middleware/tokenapi_internal.go`, and `model/tokenapi_*.go`. Upstream hooks are
the route call in `router/main.go` and the minimal quota snapshot/version checks
in `model/user_auth_cache.go`. No provider, pricing, settlement, branding or
license logic is replaced. The extra cache hook is required because internal
routes alone cannot control cold cache fills from concurrent public requests.

Regression coverage is consolidated in `router/tokenapi_router_test.go`.
`.github/workflows/tokenapi-contract.yml` runs it against real SQLite,
MySQL 8.4, PostgreSQL 16 and Redis, including startup/migration repetition,
existing rc.49 data/index preservation, G23/G24, replay/concurrency, key ownership
and lifecycle, and cache-failure/cold-fill recovery. Production internal traffic
must use TLS/mTLS or an equivalent encrypted transport and must not be public.

### CP-06: complete billing and procurement log components

Enabled only by `TOKENAPI_BILLING_LOG_ENABLED=true`, independently of CP-02.
When disabled, upstream settlement inputs and log fields are unchanged.
Ordinary expressions otherwise omit their normalized billing token inputs;
read-only log access cannot reconstruct inputs that were never persisted.

- Successful token settlements retain their exact `billing_tokens` input vector.
- `cost_tokens` retains the same twelve token dimensions with every component
  separated by the existing upstream normalizer, independently of the retail
  expression. This preserves cache TTL and image-cache categories that a retail
  expression may fold into its base input. Request-priced leaves also retain
  this cost snapshot when usage is available.
- Realtime retail inputs remain aggregate P/C as upstream defines them; its cost
  snapshot additionally uses the reported modality details. No charge, tier,
  reservation, refund, or expression rule changes.
- Failed evaluations and asynchronous task facts do not fabricate a zero-token
  snapshot. Historical, legacy/non-expression, missing-usage, or unavailable
  provider breakdowns must not be presented as fully measured procurement data.

New runtime files: `pkg/billingexpr/tokenapi_log.go` and
`service/tokenapi_billing_log.go`. Upstream hooks only attach settlement metadata,
wrap the existing normalizer, add the procurement log field, and capture realtime
usage. There are no schema migrations or calls to the platform.
`service/text_quota_test.go` verifies actual reservation/settlement/log persistence,
repeat settlement, flag-off behavior, ordinary/stream/audio/realtime/image inputs,
cache TTLs, and task/error exclusions. The database workflow exercises the same
billing cases with separate real main/log databases on SQLite, MySQL and PostgreSQL.

## Planned patches

| Patch | Milestone | Purpose | Enablement | Status |
| --- | --- | --- | --- | --- |
| CP-02 | M0 / M1 | Internal token provisioning and cumulative quota grants | `TOKENAPI_INTERNAL_SECRET` | Implemented above |
| CP-06 | M1 prerequisite | Complete billing and procurement log components | `TOKENAPI_BILLING_LOG_ENABLED=true` | Implemented above |
| CP-03 | M2 | Account-level rate limits | Internal interface | Not implemented |
| CP-05 | M2 | Model and account access policies | `TOKENAPI_POLICY_HOOK` | Not implemented |
| CP-04 | M4 | End-user tag in logs | To be specified | Not implemented |

Usage is read from the existing log database. There is no usage-push patch.
Every future runtime patch must be independently switchable, preserve upstream
behavior while disabled, and have contract tests in the platform repository.
