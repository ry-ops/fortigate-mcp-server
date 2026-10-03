# FortiGate MCP Server

An [MCP](https://modelcontextprotocol.io) server for managing Fortinet FortiGate firewalls through the FortiOS REST API. It is a companion to [proxmox-mcp-server](https://github.com/ry-ops/proxmox-mcp-server) and is built and tested against **FortiOS 7.6** (FortiGate-VM on KVM/Proxmox).

## Tools

| Area | Tools |
|---|---|
| System | `get_system_status`, `get_license_status`, `get_resource_usage`, `list_interfaces`, `get_interface`, `get_interface_status`, `update_interface`, `list_admin_sessions`, `backup_config`, `forticonverter_setup_prompt`, `activate_vm_eval_license` |
| Firewall | `list_firewall_policies`, `get_firewall_policy`, `create_firewall_policy`, `update_firewall_policy`, `delete_firewall_policy`, `move_firewall_policy`, `get_policy_stats`, `list_sessions`, `list_addresses`, `get_address`, `create_address`, `update_address`, `delete_address`, `list_address_groups`, `create_address_group`, `update_address_group`, `delete_address_group`, `list_services`, `create_service`, `delete_service` |
| Inspection & certificates | `list_ssl_ssh_profiles`, `update_ssl_ssh_profile`, `list_certificates` (key type/size, weak keys flagged), `download_certificate` (PEM + SHA-256) |
| Logs | `get_logs`: traffic, app-ctrl (HTTPS hostnames under certificate inspection), event, IPS, web filter and more, from memory, disk or FortiAnalyzer |
| Routing | `get_routing_table`, `list_static_routes`, `create_static_route`, `delete_static_route` |
| DNS & DHCP | `get_dns_settings`, `list_dns_servers`, `set_dns_server`, `delete_dns_server`, `list_dns_zones`, `create_dns_zone`, `delete_dns_zone`, `add_dns_record`, `delete_dns_record`, `list_dhcp_servers`, `list_dhcp_leases`, `update_dhcp_server`, `add_dhcp_reservation`, `delete_dhcp_reservation` |
| Anything else | `fortigate_api`, a raw call to any `/api/v2/` endpoint |

Tools take friendly arguments and build the FortiOS body for you: CIDR (`10.0.0.0/24`) instead of `ip mask`, plain lists (`["port1"]`) instead of `[{"name": "port1"}]`, and booleans instead of `enable`/`disable`. Policy tools take security profiles directly (`ssl_ssh_profile`, `application_list`, `ips_sensor`, `av_profile`, `webfilter_profile`) and turn on `utm-status` when you attach one. Every create/update tool also accepts `extra`, a dict merged into the body as-is, for attributes the tool does not model.

## Configuration

| Variable | Default | |
|---|---|---|
| `FORTIGATE_HOST` | (required) | Hostname or IP |
| `FORTIGATE_PORT` | `443` | HTTPS admin port |
| `FORTIGATE_API_TOKEN` | | REST API admin token (recommended) |
| `FORTIGATE_USERNAME` / `FORTIGATE_PASSWORD` | | Session login, used when no token is set |
| `FORTIGATE_VDOM` | `root` | VDOM for every call (tools also take `vdom`) |
| `FORTIGATE_VERIFY_SSL` | `false` | Verify the TLS certificate |
| `FORTIGATE_READ_ONLY` | `false` | Refuse every POST/PUT/DELETE before it reaches the FortiGate |
| `FORTIGATE_TIMEOUT` | `30` | Request timeout (seconds) |
| `FORTICLOUD_ACCOUNT` / `FORTICLOUD_PASSWORD` | | Only for `activate_vm_eval_license`. Read from the environment, never from tool arguments |

### Creating an API token

1. **System > Administrators > Create New > REST API Admin.**
2. Pick an admin profile (`super_admin` for full control, or a custom read-only profile), and set **Trusted Hosts** to the machine that runs this server.
3. Save. FortiOS shows the API key once; put it in `FORTIGATE_API_TOKEN`.

### Claude Code / Claude Desktop

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "uv",
      "args": ["--directory", "/path/to/fortigate-mcp-server", "run", "fortigate-mcp-server"],
      "env": {
        "FORTIGATE_HOST": "192.168.1.99",
        "FORTIGATE_API_TOKEN": "...",
        "FORTIGATE_READ_ONLY": "true"
      }
    }
  }
}
```

Start with `FORTIGATE_READ_ONLY=true` and turn it off when you want Claude to make changes.

## FortiOS gotchas this server handles

- **7.6 dropped `/logincheck`.** Session login is a JSON `POST /api/v2/authentication`, and the CSRF cookie is named `ccsrf_token_<port>_<hash>`. The client does both and logs in again once if the session times out.
- **Errors say why.** FortiOS explains failures in the response body (`cli_error`). Error messages include it instead of a bare HTTP status.
- **DHCP reservations need `action=reserved`.** With the default `assign`, the `ip` field does not exist. `add_dhcp_reservation` always uses `reserved`.
- **DHCP `vci-match`.** New DHCP servers can default to answering only FortiSwitch/FortiExtender vendor classes, which silently ignores normal clients. `update_dhcp_server` takes `vci_match=false`.
- **No wildcard DNS records.** FortiOS rejects `*` hostnames in local zones. `add_dns_record` refuses them up front with a clear message.
- **The "FortiGate Setup" popup never goes away on evaluation VMs.** Its "Migrate Config with FortiConverter" step checks FortiConverter eligibility, which evaluation licenses never pass, so the step spins forever and the popup returns at every login. There is no CLI setting. `forticonverter_setup_prompt` with `hide=true` calls the undocumented endpoint the GUI itself uses (`POST /api/v2/monitor/forticonverter/show-in-startup/set` with `{"hide": true}`).
- **An SSL inspection profile does nothing on its own in flow mode.** Traffic is only inspected once a security profile (e.g. application control `default`) is attached. Policy tools return a `warning` when a policy has an SSL profile but no security profile.
- **Certificate inspection works on evaluation licenses; deep inspection does not.** Evaluation VMs run in low-encryption mode: the factory CA is 512-bit, and even with your own 2048-bit CA, sites with RSA keys (Docker Hub, Quay, GHCR...) are re-signed with 512-bit keys that curl, Go and containerd reject. `certificate-inspection` needs no CA trust and still logs each HTTPS hostname in the app-ctrl log.
- **Evaluation licenses** (FortiGate-VM) allow 1 vCPU/2 GB and at most 3 interfaces, 3 firewall policies and 3 static routes. An **unlicensed** VM answers most API calls with 401, and its GUI goes blank after login. Activate it with `activate_vm_eval_license` and a FortiCloud account (main account, no 2FA); use session auth on a fresh VM, since the API token admin cannot be created until the VM is licensed.

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
```

## License

MIT
