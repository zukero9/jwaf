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


def parse_netsh_rules_output(text: str) -> list:
    """netsh advfirewall show rule 출력 문자열을 안전하게 파싱하여 리스트 반환"""
    rules = []
    current = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("---") or line.lower() == "ok.":
            continue
        if ":" in line:
            parts = line.split(":", 1)
            k = parts[0].strip().lower()
            v = parts[1].strip()
            if "rule name" in k or "규칙 이름" in k:
                if current and "DisplayName" in current:
                    rules.append(current)
                current = {
                    "DisplayName": v,
                    "Name": v,
                    "Direction": "Inbound",
                    "Action": "Block",
                    "Protocol": "Any",
                    "RemoteAddress": "",
                    "LocalPort": ""
                }
            elif current:
                if "direction" in k or "방향" in k:
                    current["Direction"] = "Inbound" if v.lower() in ("in", "인바운드") else "Outbound"
                elif "action" in k or "작업" in k or "액션" in k:
                    current["Action"] = "Block" if v.lower() in ("block", "차단") else "Allow"
                elif "remoteip" in k or "원격 ip" in k or "원격ip" in k:
                    current["RemoteAddress"] = v
                elif "localport" in k or "로컬 포트" in k or "로컬포트" in k:
                    current["LocalPort"] = v
                elif "protocol" in k or "프로토콜" in k:
                    current["Protocol"] = v
    if current and "DisplayName" in current:
        rules.append(current)
    return rules


def get_shield_firewall_details() -> list:
    """
    Windows 고급 방화벽에 등록된 Jinkero_* 마스터 규칙(인바운드, 아웃바운드 C2, 포트) 세부정보 조회
    1차: 안정적인 netsh 명령 파싱 (한글/영문 윈도우 100% 호환, 권한 제약 없이 조회 가능)
    2차: netsh 결과 없을 경우 PowerShell fallback
    """
    # 1. netsh로 인바운드, 아웃바운드, 포트 규칙 상세 조회
    all_rules = []
    target_rule_names = [INBOUND_BLOCK_RULE, OUTBOUND_BLOCK_RULE, PORT_BLOCK_RULE]
    for rname in target_rule_names:
        cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rname}"]
        ok, out, _ = run_cmd(cmd)
        if ok and out.strip():
            parsed = parse_netsh_rules_output(out)
            for item in parsed:
                if item["DisplayName"] not in [x["DisplayName"] for x in all_rules]:
                    all_rules.append(item)

    if all_rules:
        return all_rules

    # 2. PowerShell 백업 조회
    ps_cmd = (
        "$ErrorActionPreference = 'SilentlyContinue'; "
        "$rules = Get-NetFirewallRule -DisplayName 'Jinkero_*'; "
        "if ($rules) { "
        "  $list = @(); "
        "  foreach ($r in $rules) { "
        "    $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r; "
        "    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r; "
        "    $list += [PSCustomObject]@{ "
        "      Name = [string]$r.Name; "
        "      DisplayName = [string]$r.DisplayName; "
        "      Enabled = [string]$r.Enabled; "
        "      Direction = [string]$r.Direction; "
        "      Action = [string]$r.Action; "
        "      RemoteAddress = ($addr.RemoteAddress -join ','); "
        "      LocalPort = ($port.LocalPort -join ','); "
        "      Protocol = [string]$port.Protocol "
        "    }; "
        "  }; "
        "  $list | ConvertTo-Json -Depth 3 "
        "}"
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
