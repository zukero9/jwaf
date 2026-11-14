import subprocess
import os
import json
import logging

INBOUND_BLOCK_RULE = "Jinkero_Block_Ips"
PORT_BLOCK_RULE = "Jinkero_Block_Ports"

LEGACY_RULES = [
    "AntigravityShield_Master_Inbound_Block",
    "AntigravityShield_Master_Port_Block"
]

def run_cmd(cmd_list):
    try:
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        res = subprocess.run(cmd_list, capture_output=True, text=True, check=False, startupinfo=startupinfo)
        return res.returncode == 0, res.stdout, res.stderr
    except Exception as e:
        return False, "", str(e)

def cleanup_legacy_rules():
    """구버전 방화벽 규칙이 남아있을 경우 자동 정리"""
    for old_name in LEGACY_RULES:
        delete_shield_rule(old_name)

def sync_inbound_block_rule(ip_set: set) -> bool:
    """
    단일 마스터 규칙 'Jinkero_Block_Ips'에
    차단 IP 목록 전체를 콤마(,)로 결합하여 누적 동기화합니다.
    """
    cleanup_legacy_rules()

    if not ip_set:
        delete_shield_rule(INBOUND_BLOCK_RULE)
        return True

    # netsh remoteip 형식: 1.1.1.1,2.2.2.2,...
    ip_list_str = ",".join(sorted(list(ip_set)))

    # 먼저 기존 단일 규칙 삭제 후 재생성 (안정적 갱신)
    delete_shield_rule(INBOUND_BLOCK_RULE)
    
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={INBOUND_BLOCK_RULE}",
        "dir=in",
        "action=block",
        f"remoteip={ip_list_str}",
        "description=Accumulated Blocked IPs by Jinkero Shield AI Firewall"
    ]
    success, out, err = run_cmd(cmd)
    return success

def sync_port_block_rule(port_set: set) -> bool:
    """
    단일 마스터 규칙 'Jinkero_Block_Ports'에
    차단 포트 목록 전체를 콤마(,)로 결합하여 누적 동기화합니다.
    """
    cleanup_legacy_rules()

    if not port_set:
        delete_shield_rule(PORT_BLOCK_RULE)
        return True

    port_list_str = ",".join(str(p) for p in sorted(list(port_set)))
    delete_shield_rule(PORT_BLOCK_RULE)

    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={PORT_BLOCK_RULE}",
        "dir=in",
        "action=block",
        "protocol=TCP",
        f"localport={port_list_str}",
        "description=Accumulated Blocked Ports by Jinkero Shield AI Firewall"
    ]
    success, out, err = run_cmd(cmd)
    return success

def delete_shield_rule(rule_name: str) -> bool:
    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ]
    success, _, _ = run_cmd(cmd)
    return success

def get_shield_firewall_details() -> list:
    """
    Jinkero_Block* 관련 등록된 윈도우 방화벽 규칙의 세부 설정값 조회 (JSON 파싱)
    """
    ps_cmd = (
        "Get-NetFirewallRule -DisplayName 'Jinkero_Block*' -ErrorAction SilentlyContinue | "
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
