import subprocess
import os
import json
import ipaddress

INBOUND_BLOCK_RULE = "Jinkero_Block_Ips"
OUTBOUND_BLOCK_RULE = "Jinkero_Outbound_Block"
PORT_BLOCK_RULE = "Jinkero_Block_Ports"

ALLOWED_RULE_NAMES = {
    INBOUND_BLOCK_RULE,
    OUTBOUND_BLOCK_RULE,
    PORT_BLOCK_RULE,
    "AntigravityShield_Master_Inbound_Block",
    "AntigravityShield_Master_Port_Block"
}

LEGACY_RULES = [
    "AntigravityShield_Master_Inbound_Block",
    "AntigravityShield_Master_Port_Block"
]


def _sanitize_firewall_ips(ip_set: set) -> list:
    """
    [시큐어 코딩] 명령어 삽입(Command Injection) 및 로컬 네트워크 자가 격리(Self-Lockout) 방지를 위해
    표준 IPv4/IPv6 공인 주소만 엄격히 필터링합니다.
    """
    valid_ips = []
    for raw in ip_set:
        s = str(raw).strip()
        try:
            net = ipaddress.ip_network(s, strict=False)
            if net.is_loopback or net.is_private or net.is_unspecified or net.is_link_local or net.is_multicast:
                continue
            valid_ips.append(str(net.network_address) if net.prefixlen in (32, 128) else str(net))
        except Exception:
            continue
    return sorted(list(set(valid_ips)))


def _sanitize_firewall_ports(port_set: set) -> list:
    valid_ports = []
    for p in port_set:
        try:
            p_int = int(p)
            if 1 <= p_int <= 65535:
                valid_ports.append(str(p_int))
        except Exception:
            continue
    return sorted(list(set(valid_ports)), key=lambda x: int(x))


def run_cmd(cmd_list):
    try:
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        res = subprocess.run(cmd_list, capture_output=True, text=True, check=False, shell=False, startupinfo=startupinfo)
        return res.returncode == 0, res.stdout, res.stderr
    except Exception as e:
        return False, "", str(e)


def cleanup_legacy_rules():
    for old_name in LEGACY_RULES:
        delete_shield_rule(old_name)


def sync_inbound_block_rule(ip_set: set, sync_outbound: bool = True) -> bool:
    """
    인바운드('Jinkero_Block_Ips') 및 아웃바운드('Jinkero_Outbound_Block') 양방향 마스터 규칙에
    검증된 차단 IP 목록 전체를 콤마(,)로 결합하여 누적 동기화합니다.
    """
    cleanup_legacy_rules()
    sanitized_ips = _sanitize_firewall_ips(ip_set)

    if not sanitized_ips:
        delete_shield_rule(INBOUND_BLOCK_RULE)
        delete_shield_rule(OUTBOUND_BLOCK_RULE)
        return True

    ip_list_str = ",".join(sanitized_ips)

    delete_shield_rule(INBOUND_BLOCK_RULE)
    cmd_in = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={INBOUND_BLOCK_RULE}",
        "dir=in",
        "action=block",
        f"remoteip={ip_list_str}",
        "description=Accumulated Inbound Blocked IPs by JWAF Jinkero Shield Pro AI"
    ]
    success_in, _, _ = run_cmd(cmd_in)

    delete_shield_rule(OUTBOUND_BLOCK_RULE)
    if sync_outbound:
        cmd_out = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={OUTBOUND_BLOCK_RULE}",
            "dir=out",
            "action=block",
            f"remoteip={ip_list_str}",
            "description=Accumulated Outbound C2 Blocked IPs by JWAF Jinkero Shield Pro AI"
        ]
        run_cmd(cmd_out)

    return success_in


def sync_port_block_rule(port_set: set) -> bool:
    cleanup_legacy_rules()
    sanitized_ports = _sanitize_firewall_ports(port_set)
    if not sanitized_ports:
        delete_shield_rule(PORT_BLOCK_RULE)
        return True

    port_list_str = ",".join(sanitized_ports)
    delete_shield_rule(PORT_BLOCK_RULE)

    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={PORT_BLOCK_RULE}",
        "dir=in",
        "action=block",
        "protocol=TCP",
        f"localport={port_list_str}",
        "description=Accumulated Blocked Ports by JWAF Jinkero Shield Pro AI"
    ]
    success, _, _ = run_cmd(cmd)
    return success


def delete_shield_rule(rule_name: str) -> bool:
    clean_name = str(rule_name).strip()
    if clean_name not in ALLOWED_RULE_NAMES and not clean_name.startswith("Jinkero_"):
        return False
    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={clean_name}"
    ]
    success, _, _ = run_cmd(cmd)
    return success


def get_shield_firewall_details() -> list:
    ps_cmd = (
        "Get-NetFirewallRule -DisplayName 'Jinkero_*' -ErrorAction SilentlyContinue | "
        "ForEach-Object { "
        "  $rule = $_; "
        "  $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue; "
        "  $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue; "
        "  [PSCustomObject]@{ "
        "    Name = $rule.Name; "
        "    DisplayName = $rule.DisplayName; "
        "    Enabled = $rule.Enabled; "
        "    Direction = $rule.Direction; "
        "    Action = $rule.Action; "
        "    RemoteAddress = ($addr.RemoteAddress -join ','); "
        "    LocalPort = ($port.LocalPort -join ','); "
        "    Protocol = $port.Protocol "
        "  } "
        "} | ConvertTo-Json -Depth 3"
    )
    success, out, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd])
    if success and out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                return [data]
            elif isinstance(data, list):
                return data
        except Exception:
            pass
    return []
