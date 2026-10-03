# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/ry-ops/fortigate-mcp-server/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/ry-ops/fortigate-mcp-server/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ry-ops/fortigate-mcp-server/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ry-ops/fortigate-mcp-server/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ry-ops/fortigate-mcp-server/releases/tag/v0.1.0
