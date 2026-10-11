# Checking a FortiGate against a security advisory

The server deliberately has no built-in IOC lists. Advisories go stale quickly, IP addresses get
reassigned, and two agencies' lists for the same campaign rarely match. Instead, give Claude the
advisory and let it run the checks with the existing read-only tools. This page covers the steps
and the FortiOS details that matter.

## Steps

1. **Firmware.** `get_system_status` returns the firmware version and whether a log disk exists.
   Compare the version with the advisory's fixed releases.
2. **Admin access.** `audit_admin_access` covers most credential-campaign advisories: admins
   without trusted hosts or MFA, admin access on WAN interfaces, API keys, and SHA-256 password
   hashes. `audit_hardening` adds the rest of the baseline (logging, crypto, SSL VPN, LAN-side
   admin access) and orders the fixes so the ones that can lock you out come last.
3. **Accounts the advisory names.** `fortigate_api` GET on `/api/v2/cmdb/system/admin`,
   `/api/v2/cmdb/system/api-user`, `/api/v2/cmdb/user/local` and `/api/v2/cmdb/user/ldap`.
   An admin you don't recognise matters more than an exact name match.
4. **Live state.** `list_admin_sessions`, and `list_sessions` with `dstaddr`/`dstport` for C2
   addresses and ports.
5. **Logs.** `get_logs` on `event/system` (admin logins and config changes), `event/vpn` and
   `event/user` (VPN logins), `traffic/local` (connections to the FortiGate itself) and
   `traffic/forward` (connections out).
6. **Config drift.** Run `backup_config` and diff the file against a known-good backup.

## Log filter rules

FortiOS **silently ignores** a filter it can't apply and returns unfiltered rows. `get_logs`
refuses the known cases, but keep these rules in mind:

- A comma ORs values of **one field**: `srcip==203.0.113.5,srcip==198.51.100.7`.
- To AND terms, pass a list: `["srcip==203.0.113.5", "dstport==443"]`.
- To check IPs and ports, make one call per field. `dstip==X,dstport==Y` is ignored.
- Memory logs on a FortiGate-VM without a log disk cover only a few days. If the advisory's
  activity window is older than that, say so instead of reporting the box clean. Older events
  need FortiAnalyzer, FortiCloud or an upstream device's logs.

## Reporting

Before blocking an IP from an advisory, vet it, because the address may have been reassigned.
Report what was checked, what came back clean, what was found, and what the logs could not cover.
