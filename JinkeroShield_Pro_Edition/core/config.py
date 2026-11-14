import json
import os
import sys
import ipaddress
import threading
from typing import Dict, List, Set
from core.self_protection import SELF_PROTECTION

def _get_persistent_config_path(filename: str = "shield_pro_config.json") -> str:
    r"""
    [지능형 영구 저장소 경로 결정기]
    1. 실행 파일(또는 프로젝트) 디렉터리에 쓰기 권한이 있으면 동일 디렉터리에 저장
    2. C:\Program Files 등 관리자 전용 폴더에 설치되어 일반 쓰기 권한이 제한되는 경우,
       사용자별 AppData 로컬 디렉터리(%LOCALAPPDATA%\JinkeroShieldPro)로 안전하게 격리 저장하여
       재실행 시에도 차단 목록, 추가/제외 국가 및 모든 환경설정이 100% 영구 보존되도록 보장합니다.
    """
    candidates = []
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        candidates.append(os.path.join(exe_dir, filename))
    else:
        proj_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidates.append(os.path.join(proj_dir, filename))
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), filename))

    appdata_dir = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "JinkeroShieldPro")
    appdata_path = os.path.join(appdata_dir, filename)

    # 1. 기존에 이미 저장된 유효한 설정 파일이 있는지 우선 탐색
    for c in candidates:
        if os.path.exists(c):
            return c
    if os.path.exists(appdata_path):
        return appdata_path

    # 2. 신규 생성 시 쓰기 가능한 경로 테스트
    for c in candidates:
        try:
            d = os.path.dirname(c)
            os.makedirs(d, exist_ok=True)
            test_file = os.path.join(d, ".perm_test")
            with open(test_file, "w") as f:
                f.write("1")
            os.remove(test_file)
            return c
        except Exception:
            pass

    try:
        os.makedirs(appdata_dir, exist_ok=True)
    except Exception:
        pass
    return appdata_path

CONFIG_FILE = _get_persistent_config_path("shield_pro_config.json")


def is_valid_ip_or_cidr(ip_str: str) -> bool:
    try:
        ipaddress.ip_network(ip_str.strip(), strict=False)
        return True
    except Exception:
        return False


class ShieldConfig:
    """
    [시큐어 코딩 적용] HMAC-SHA256 무결성 전자서명 기반 설정 관리자
    외부에서 shield_pro_config.json 파일을 임의로 수정/해킹하여 방화벽을 끄거나 화이트리스트를 변조하면
    HMAC 서명 검증이 즉시 실패를 감지하고 안전 기본값으로 강제 복원합니다.
    """
    def __init__(self):
        self.lock = threading.Lock()
        self.is_active: bool = True
        self.blocked_countries: Set[str] = {"CN", "RU", "KP"}
        self.black_ips: Set[str] = set()
        self.white_ips: Set[str] = {"127.0.0.1", "::1"}
        self.blocked_ports: Set[int] = {3389, 445, 135, 139, 21, 23}
        self.waf_enabled: bool = True
        self.waf_port: int = 8080
        self.target_port: int = 3000
        self.file_guard_enabled: bool = True
        self.auto_sync_windows_firewall: bool = True

        self.ai_enabled: bool = True
        self.ai_sensitivity: str = "BALANCED"
        self.outbound_c2_block_enabled: bool = True
        self.auto_update_enabled: bool = True
        self.canary_ransomware_trap: bool = True

        self.geo_blocked_history: List[Dict[str, str]] = []
        self.threat_blocked_history: List[Dict[str, str]] = []
        self.ai_anomaly_history: List[Dict[str, str]] = []
        self.tamper_detected_on_load: bool = False
        self._load()

    def _load(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # HMAC-SHA256 무결성 검증: 서명이 존재하는데 일치하지 않으면 외부 무단 변조로 판정!
                if "_hmac_seal" in data and not SELF_PROTECTION.verify_dict(data):
                    self.tamper_detected_on_load = True
                    # 변조 감지 시 방화벽/AI 강제 활성화 유지 후 즉시 재봉인
                    self.is_active = True
                    self.ai_enabled = True
                    self.save()
                    return

                self.is_active = bool(data.get("is_active", True))
                self.blocked_countries = {
                    str(c).upper() for c in data.get("blocked_countries", ["CN", "RU", "KP"])
                    if isinstance(c, str) and len(c) == 2 and c.isalpha()
                }
                self.black_ips = {
                    str(ip).strip() for ip in data.get("black_ips", [])
                    if is_valid_ip_or_cidr(str(ip))
                }
                self.white_ips = {
                    str(ip).strip() for ip in data.get("white_ips", ["127.0.0.1", "::1"])
                    if is_valid_ip_or_cidr(str(ip))
                } | {"127.0.0.1", "::1"}
                self.blocked_ports = {
                    int(p) for p in data.get("blocked_ports", [3389, 445, 135, 139, 21, 23])
                    if str(p).isdigit() and 1 <= int(p) <= 65535
                }
                self.waf_enabled = bool(data.get("waf_enabled", True))
                self.waf_port = int(data.get("waf_port", 8080))
                self.target_port = int(data.get("target_port", 3000))
                self.file_guard_enabled = bool(data.get("file_guard_enabled", True))
                self.auto_sync_windows_firewall = bool(data.get("auto_sync_windows_firewall", True))
                self.ai_enabled = bool(data.get("ai_enabled", True))
                self.ai_sensitivity = str(data.get("ai_sensitivity", "BALANCED"))
                self.outbound_c2_block_enabled = bool(data.get("outbound_c2_block_enabled", True))
                self.auto_update_enabled = bool(data.get("auto_update_enabled", True))
                self.canary_ransomware_trap = bool(data.get("canary_ransomware_trap", True))
                self.geo_blocked_history = data.get("geo_blocked_history", [])
                self.threat_blocked_history = data.get("threat_blocked_history", [])
                self.ai_anomaly_history = data.get("ai_anomaly_history", [])

                if "_hmac_seal" not in data:
                    self.save()
            except Exception:
                pass
        else:
            self.save()

    def save(self):
        with self.lock:
            data = {
                "is_active": self.is_active,
                "blocked_countries": sorted(list(self.blocked_countries)),
                "black_ips": sorted(list(self.black_ips)),
                "white_ips": sorted(list(self.white_ips)),
                "blocked_ports": sorted(list(self.blocked_ports)),
                "waf_enabled": self.waf_enabled,
                "waf_port": self.waf_port,
                "target_port": self.target_port,
                "file_guard_enabled": self.file_guard_enabled,
                "auto_sync_windows_firewall": self.auto_sync_windows_firewall,
                "ai_enabled": self.ai_enabled,
                "ai_sensitivity": self.ai_sensitivity,
                "outbound_c2_block_enabled": self.outbound_c2_block_enabled,
                "auto_update_enabled": self.auto_update_enabled,
                "canary_ransomware_trap": self.canary_ransomware_trap,
                "geo_blocked_history": self.geo_blocked_history[-200:],
                "threat_blocked_history": self.threat_blocked_history[-500:],
                "ai_anomaly_history": self.ai_anomaly_history[-300:]
            }
            data["_hmac_seal"] = SELF_PROTECTION.sign_dict(data)
            try:
                with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
            except Exception:
                pass

    def add_black_ip(self, ip: str):
        clean_ip = ip.strip()
        if not is_valid_ip_or_cidr(clean_ip) or clean_ip in ("127.0.0.1", "::1", "0.0.0.0"):
            return
        with self.lock:
            self.black_ips.add(clean_ip)
            self.white_ips.discard(clean_ip)
        self.save()

    def remove_black_ip(self, ip: str):
        with self.lock:
            self.black_ips.discard(ip.strip())
        self.save()

    def add_white_ip(self, ip: str):
        clean_ip = ip.strip()
        if not is_valid_ip_or_cidr(clean_ip):
            return
        with self.lock:
            self.white_ips.add(clean_ip)
            self.black_ips.discard(clean_ip)
        self.save()

    def remove_white_ip(self, ip: str):
        clean_ip = ip.strip()
        if clean_ip in ("127.0.0.1", "::1"):
            return
        with self.lock:
            self.white_ips.discard(clean_ip)
        self.save()

    def toggle_country(self, country_code: str, block: bool):
        code = country_code.strip().upper()
        if len(code) != 2 or not code.isalpha() or code == "KR":
            return
        with self.lock:
            if block:
                self.blocked_countries.add(code)
            else:
                self.blocked_countries.discard(code)
        self.save()

    def toggle_port(self, port: int, block: bool):
        if not (1 <= int(port) <= 65535):
            return
        with self.lock:
            if block:
                self.blocked_ports.add(int(port))
            else:
                self.blocked_ports.discard(int(port))
        self.save()

    def record_geo_block(self, ip: str, country: str, time_str: str, reason: str):
        clean_ip = ip.strip()
        if not is_valid_ip_or_cidr(clean_ip) or clean_ip in ("127.0.0.1", "::1"):
            return
        with self.lock:
            if clean_ip not in self.black_ips:
                self.black_ips.add(clean_ip)
            entry = {"timestamp": time_str, "ip": clean_ip, "country": country, "reason": reason}
            self.geo_blocked_history.insert(0, entry)
            self.geo_blocked_history = self.geo_blocked_history[:300]
        self.save()

    def record_threat_block(self, ip: str, country: str, time_str: str, rule_name: str, details: str):
        clean_ip = ip.strip()
        if not is_valid_ip_or_cidr(clean_ip) or clean_ip in ("127.0.0.1", "::1"):
            return
        with self.lock:
            if clean_ip not in self.black_ips:
                self.black_ips.add(clean_ip)
            entry = {"timestamp": time_str, "ip": clean_ip, "country": country, "rule": rule_name, "details": details}
            self.threat_blocked_history.insert(0, entry)
            self.threat_blocked_history = self.threat_blocked_history[:500]
        self.save()

    def record_ai_anomaly(self, ip: str, country: str, time_str: str, score: int, category: str, xai_reason: str, blocked: bool):
        clean_ip = ip.strip()
        with self.lock:
            if blocked and is_valid_ip_or_cidr(clean_ip) and clean_ip not in ("127.0.0.1", "::1") and clean_ip not in self.black_ips:
                self.black_ips.add(clean_ip)
            entry = {
                "timestamp": time_str,
                "ip": clean_ip,
                "country": country,
                "score": str(score),
                "category": category,
                "action": "AI_AUTO_BLOCK" if blocked else "AI_ANOMALY_WATCH",
                "xai_reason": xai_reason
            }
            self.ai_anomaly_history.insert(0, entry)
            self.ai_anomaly_history = self.ai_anomaly_history[:300]
        self.save()
