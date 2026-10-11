# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2026-10-11

### Added
- `get_fortiguard_status`: whether FortiGuard updates are actually arriving. It reports the
  connection state, each server's reachability and packet loss, the update schedule, licensed
  services and signature ages. On licensed units it flags failing servers, stale signatures on
  licensed services and a disabled update schedule. On the evaluation license it explains that
  FortiGuard is unavailable by design.
- `update_fortiguard`: ask the FortiGate to contact FortiGuard now. It defaults to a dry run and
  refuses with a clear message when there is no FortiGuard subscription.
- `get_firmware_status`: the running firmware, newer images in version order, the supported
  upgrade path and the automatic firmware upgrade settings. It handles the HTTP 500 FortiOS
  returns for upgrade paths without FortiGuard.
- README: "On a licensed FortiGate", marking licensed-unit behaviour as not yet verified.

### Changed
- License errors name "a FortiGuard subscription" when the whole service is missing.

## [0.7.0] - 2026-10-11

### Added
- Schema-driven tools that reach every FortiOS setting and monitor endpoint, using the schema
  the FortiGate publishes about itself (`/api/v2/cmdb/?action=schema` and the monitor
  directory), so they match its firmware:
  - `search_api`: find configuration and monitor endpoints by keyword.
  - `describe_config`: a table or settings object's fields, types, allowed values, ranges and
    defaults.
  - `get_config`: read any configuration endpoint. Password and key fields show as `<set>`.
  - `set_config`: update, create or delete, validated against the schema first (field names,
    options, integer ranges, string lengths, table vs settings rules). It defaults to a dry run
    that shows each field's current and new value. References take plain names.
  - `get_monitor`: read any GET monitor endpoint. POST monitor endpoints, which act on the
    device, are refused.

## [0.6.0] - 2026-10-11

### Added
- `get_license_features`: what the FortiGate is licensed for. It reports the edition (free
  evaluation VM, licensed VM or hardware), the FortiGuard connection, which FortiGuard services
  are licensed, not licensed or expiring within 30 days, and each signature database's version
  and age.
- A shared license helper that reads the license once a minute. Tools that need an unlicensed
  FortiGuard service say which service is missing instead of failing with a 401.
- ADR-0002: one license-aware server for free and licensed FortiGates, with schema-driven tools
  for breadth.

### Changed
- `get_license_limits` and `audit_hardening` use the shared license helper.

## [0.5.0] - 2026-10-11

### Added
- `audit_admin_access`: a read-only audit of how the FortiGate can be administered. It flags
  admins without trusted hosts or MFA, the default `admin` account, API keys without trusted
  hosts or with super_admin rights, HTTPS/SSH/HTTP/telnet admin access on WAN interfaces,
  firmware older than the PBKDF2 releases (7.2.11, 7.4.8, 7.6.1), and admin passwords still
  stored as SHA-256 (read from a config backup; `check_hashes=false` skips it). Findings are
  graded critical/warn/info with a suggested fix.
- `audit_hardening`: a read-only hardening audit that runs `audit_admin_access` and adds admin
  access on LAN interfaces, local-in coverage, global telnet, FortiCloud SSO, `strong-crypto` and
  TLS minimums, SSL VPN state, logging (implicit deny, local-in denies, remote targets), password
  policy, and NTP (including DHCP handing out the FortiGate as NTP server where it doesn't answer).
  Every finding carries a fix order and a `lockout_risk` flag, and `fix_plan` lists the fixes so
  the changes that can't affect access come first. On the evaluation license it lists the
  FortiGuard features that don't apply and what to rely on instead.

### Changed
- `get_logs` takes a list of filter terms, sent as separate `filter` parameters, which FortiOS
  ANDs together.
- `list_sessions` returns `{sessions, matched, total_sessions}` and explains an empty list.
  Sessions to the FortiGate itself are counted but not listed.

### Fixed
- `get_logs` on `event/*` types returned other subtypes' rows. FortiOS does not scope those
  endpoints, so with no matching events it stopped part-way through and returned unrelated
  system events. A `subtype==` term is now added, and any rows that don't match the filter are dropped
  with a warning.
- `get_logs` passed through filters that FortiOS silently ignores and then returned unfiltered
  rows: a comma OR across different fields, or `&` inside a filter. These are now refused with
  an explanation. A warning is added when FortiOS reports it searched less than the whole log.

## [0.4.1] - 2026-10-03

### Fixed
- The server reported the MCP SDK's version (1.30.0) to clients instead of its own.

## [0.4.0] - 2026-10-03

### Added
- `get_license_limits`: policies, static routes and interfaces in use against the free
  FortiGate-VM evaluation license's limits of 3 each (applied only on `vm_eval`).
- Port forwards: `list_port_forwards`, `create_port_forward`, `delete_port_forward`.
  `create_port_forward` can attach the VIP to an existing policy instead of needing a new one,
  checks first that the policy takes traffic from the VIP's interface and does not mix VIPs
  with ordinary addresses (`replace_destinations=true` converts it on purpose), deletes the VIP
  again if the policy refuses it, and says when no policy slot is free. `delete_port_forward`
  can detach the VIP from policies first.
- `get_top_traffic` (FortiView realtime statistics by source, destination, application,
  country, interface, policy or protocol, with application names) and `get_arp_table`.
- Application control: `search_applications`, `list_app_categories`,
  `list_app_control_profiles`, `add_app_control_rule` (by application or category name; new
  rules go above the built-in catch-all pass rule) and `delete_app_control_rule`.
- Service groups: `list_service_groups`, `create_service_group`, `update_service_group`,
  `delete_service_group`.
- Optional Kubernetes integration (`K8S_KUBECONFIG`): `k8s_cluster_overview`,
  `k8s_sync_ingress_dns` (Ingress and Traefik IngressRoute hostnames become FortiGate DNS
  records, standing in for the wildcard records FortiOS cannot hold) and
  `k8s_sync_node_addresses` (node IPs kept in an address range or group). Both sync tools
  default to `dry_run=true`; the cluster is only read.
- Optional Proxmox VE integration (`PROXMOX_*`, a PVEAuditor token is enough):
  `identify_clients`, plus `resolve_vms=true` on `get_logs`, `list_sessions`,
  `get_top_traffic` and `list_dhcp_leases` to label IPs and MACs with the owning VM.
- README rebuilt with animated visuals, a tool catalog generated from the code, and a
  [zero to firewall](README.md#zero-to-firewall) walkthrough; `CHANGELOG.md`; CI running ruff,
  the tests on Python 3.10 to 3.13 and a README catalog check.

## [0.3.0] - 2026-10-03

### Added
- `get_logs`: traffic, app-ctrl, event, IPS, web filter and other logs from memory, disk or
  FortiAnalyzer, with filters, paging and field selection.
- Policy tools take security profiles (`ssl_ssh_profile`, `application_list`, `ips_sensor`,
  `av_profile`, `webfilter_profile`), enable `utm-status` when one is attached, and warn when an
  SSL profile sits on a policy with no security profile (it inspects nothing in flow mode).
- `list_ssl_ssh_profiles` and `update_ssl_ssh_profile` (built-in read-only profiles refused).
- `list_certificates` with key type and size, flagging RSA keys under 2048 bits, and
  `download_certificate` (PEM and SHA-256 fingerprint).
- `activate_vm_eval_license`: activates the free permanent evaluation license through
  FortiCloud. Credentials come from `FORTICLOUD_ACCOUNT`/`FORTICLOUD_PASSWORD` only, it needs
  `confirm=true`, and it does nothing on a licensed VM.

## [0.2.0] - 2026-10-03

### Added
- `forticonverter_setup_prompt`: reads or hides the GUI setup popup's "Migrate Config with
  FortiConverter" step, which never completes on evaluation VMs, through the undocumented
  `POST /api/v2/monitor/forticonverter/show-in-startup/set`.

## [0.1.0] - 2026-10-03

Initial release: 48 tools for FortiOS 7.6 (system, firewall policies, addresses, services,
routing, DNS and DHCP, and a raw `/api/v2/` tool), API-token or session auth with the 7.6 JSON
login, `FORTIGATE_READ_ONLY`, and FortiOS error details in every failure.

[Unreleased]: https://github.com/ry-ops/fortigate-mcp-server/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/ry-ops/fortigate-mcp-server/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/ry-ops/fortigate-mcp-server/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/ry-ops/fortigate-mcp-server/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/ry-ops/fortigate-mcp-server/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/ry-ops/fortigate-mcp-server/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ry-ops/fortigate-mcp-server/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ry-ops/fortigate-mcp-server/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ry-ops/fortigate-mcp-server/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ry-ops/fortigate-mcp-server/releases/tag/v0.1.0
