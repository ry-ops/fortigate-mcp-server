# ADR-0002: One server for free and licensed FortiGates

**Status:** Accepted
**Date:** 2026-10-11
**Deciders:** ry-ops (maintainer)

## Context

The server was built and tested against the free FortiGate-VM evaluation license. That license
runs the same FortiOS as a paid unit, but with no FortiGuard services, at most 1 vCPU, 2 GB RAM, 3
interfaces, 3 firewall policies and 3 static routes, and low-encryption certificates.

Users outgrow it quickly, and the security features worth automating (IPS, antivirus, web and DNS
filtering, FortiToken MFA, FortiAnalyzer logging, firmware updates) only work with a license. A
server that stops being useful on a licensed unit is a toy.

Coverage today, measured against the FortiOS 7.6.7 API schema: dedicated tools exist for 27 of 666
configuration endpoints and 17 of 269 monitor endpoints. The rest are reachable only through the
unvalidated `fortigate_api` tool.

## Decision

1. **One server that adapts to the license, not a separate paid edition.** A shared helper
   (`tools/_license.py`) reads `monitor/license/status` once per minute and records:
   - the edition: free evaluation VM, licensed VM or hardware
   - whether the unit is connected to FortiGuard
   - each FortiGuard service's status and expiry
   - signature versions

   Tools use it to apply evaluation limits only on the evaluation license. A tool that needs an
   unlicensed service raises a clear error naming the service, instead of failing with a 401 or
   returning stale data. `get_license_features` exposes the same information.
2. **Breadth through schema-driven tools.** FortiOS publishes its own schema
   (`/api/v2/cmdb/?action=schema`, and the monitor directory). A small set of generic tools will
   use it:
   - search the schema
   - describe an endpoint's fields, allowed values and defaults
   - read config
   - validated, dry-run-by-default writes
   - read monitor endpoints

   Together they reach every endpoint on both free and licensed units, without hundreds of
   hand-written tools.
3. **Dedicated tools only where they add something:** FortiOS traps the server should handle
   (as it already does for log filters and evaluation limits), and the workflows that matter once
   licensed:
   - FortiGuard status and updates
   - IPS, antivirus, web and DNS filter profiles
   - FortiToken assignment
   - FortiAnalyzer and FortiGuard Cloud logging
   - HA
   - the firmware upgrade path
4. **Audits adapt.** On the evaluation license, `audit_hardening` marks the FortiGuard features
   that can't apply. On a licensed unit it should check what a license makes possible: stale
   signatures, unenforced MFA, and policies without security profiles.
5. **Hardware-only features stay generic.** FortiAP, FortiSwitch and FortiExtender management (116
   configuration endpoints) needs physical devices, so it is left to the schema-driven tools until
   someone asks for more.

## Options considered

| Option | Verdict |
|---|---|
| Stay free-only | Rejected: the server stops being useful when a user buys a license |
| A separate "paid" server or plugin | Rejected: the API is the same, so two code bases would drift, and users would have to choose up front |
| **One license-aware server** | **Chosen** |
| One hand-written tool per endpoint | Rejected: about 900 tools, beyond what MCP clients handle well, and impossible to test |

## Consequences

- **Easier:** the same tools work on both kinds of unit. Licensed users get real security
  workflows, and evaluation users get clear explanations instead of silent failures.
- **Harder: testing paid-only behaviour.** The maintainer has only the evaluation VM. Paid-only
  tools are tested against fixtures built from the schema and Fortinet's documented responses,
  and the README marks them "not yet verified on a licensed unit" until a user with a licensed
  unit confirms them.
- **Unverified assumptions, to confirm on a licensed unit:**
  - per-service `status` values: `licensed` and `expires_soon` count as active; the evaluation VM
    reports `no_support`, and Fortinet documents `expired`, `no_license`, `not_registered`,
    `pending` and `unavailable`
  - the `expires` field (epoch seconds)
  - `fortiguard.supported` being true on licensed units

## Action items

1. [x] License helper and `get_license_features`, with `get_license_limits` and `audit_hardening` using it (v0.6.0).
2. [x] Schema-driven tools: search, describe, get, set (validated, dry run) and get_monitor.
3. [x] Licensed-feature tools: FortiGuard status and updates, firmware (v0.8.0); security profiles (v0.9.0); FortiToken, logging targets, HA (v0.10.0).
4. [x] `audit_hardening` checks for licensed units: FortiGuard, policy protection, log targets and HA (v0.11.0).
5. [x] README section on free vs licensed units, with the "not yet verified" markers.
