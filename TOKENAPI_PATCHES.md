# TokenAPI patch inventory for new-api

Upstream: [QuantumNous/new-api](https://github.com/QuantumNous/new-api)

Locked release: `v1.0.0-rc.49`, commit `48a6c87f9e7757fdc58e5be9bcb4f8281ad0dfd0`.

This public fork retains the upstream new-api and QuantumNous attribution,
licenses, module names, interface branding, and release workflows unchanged.
The private platform is a separate repository and communicates over APIs and a
read-only connection to the gateway log database.

## Applied runtime patches

None. This baseline adds only this inventory, `UPSTREAM_VERSION`, and a separate
image-validation workflow. The original Dockerfile and application sources are
unchanged.

## Planned patches

| Patch | Milestone | Purpose | Enablement | Status |
| --- | --- | --- | --- | --- |
| CP-02 | M0 / M1 | Internal token provisioning and cumulative quota grants | `TOKENAPI_INTERNAL_SECRET` | Not implemented |
| CP-03 | M2 | Account-level rate limits | Internal interface | Not implemented |
| CP-05 | M2 | Model and account access policies | `TOKENAPI_POLICY_HOOK` | Not implemented |
| CP-04 | M4 | End-user tag in logs | To be specified | Not implemented |

Usage is read from the existing log database. There is no usage-push patch.
Every future runtime patch must be independently switchable, preserve upstream
behavior while disabled, and have contract tests in the platform repository.
