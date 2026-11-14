import json
import os
import threading
from typing import Dict, List, Set

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "shield_config.json")

class ShieldConfig:
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

        # AI 자율 방어 설정
        self.ai_enabled: bool = True
        self.ai_sensitivity: str = "BALANCED"  # CONSERVATIVE, BALANCED, AGGRESSIVE
        self.ai_precision_v2_migrated: bool = False

        # 국가별 차단에 의해 자동 차단/방화벽 동기화된 IP 기록 목록
        self.geo_blocked_history: List[Dict[str, str]] = []
        
        # 지능형 침해 시도로 탐지/차단되어 방화벽에 영구 반영되는 내역 저장소 (재실행 시에도 유지)
        self.threat_blocked_history: List[Dict[str, str]] = []

        # AI 자율 방어 엔진이 탐지/차단한 이상 징후 내역 저장소
        self.ai_anomaly_history: List[Dict[str, str]] = []
        self._load()

    def _load(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.is_active = data.get("is_active", True)
                    self.blocked_countries = set(data.get("blocked_countries", ["CN", "RU", "KP"]))
                    self.black_ips = set(data.get("black_ips", []))
                    self.white_ips = set(data.get("white_ips", ["127.0.0.1", "::1"]))
                    self.blocked_ports = set(data.get("blocked_ports", [3389, 445, 135, 139, 21, 23]))
                    self.waf_enabled = data.get("waf_enabled", True)
                    self.waf_port = data.get("waf_port", 8080)
                    self.target_port = data.get("target_port", 3000)
                    self.file_guard_enabled = data.get("file_guard_enabled", True)
                    self.auto_sync_windows_firewall = data.get("auto_sync_windows_firewall", True)
                    self.ai_enabled = data.get("ai_enabled", True)
                    self.ai_sensitivity = data.get("ai_sensitivity", "BALANCED")
                    self.ai_precision_v2_migrated = data.get("ai_precision_v2_migrated", False)
                    self.geo_blocked_history = data.get("geo_blocked_history", [])
                    self.threat_blocked_history = data.get("threat_blocked_history", [])
                    self.ai_anomaly_history = data.get("ai_anomaly_history", [])

                    # 이전 AI 초기 버전에서 과민 차단된 일반 소켓 오탐 IP 자동 정화 (1회 마이그레이션)
                    if not self.ai_precision_v2_migrated:
                        fp_rules = {"AI_PORT_SCAN_ANOMALY", "AI_C2_BEACON_SUSPECT", "AI_CONNECTION_FLOOD"}
                        fp_ips = set()
                        for item in self.threat_blocked_history:
                            if item.get("rule") in fp_rules:
                                fp_ips.add(item.get("ip", ""))
                        for item in self.ai_anomaly_history:
                            if item.get("category") in fp_rules:
                                fp_ips.add(item.get("ip", ""))
                        self.threat_blocked_history = [
                            x for x in self.threat_blocked_history if x.get("rule") not in fp_rules
                        ]
                        self.ai_anomaly_history = [
                            x for x in self.ai_anomaly_history if x.get("category") not in fp_rules
                        ]
                        self.black_ips -= fp_ips
                        self.ai_precision_v2_migrated = True
                        self.save()
            except Exception:
                pass

    def save(self):
        with self.lock:
            data = {
                "is_active": self.is_active,
                "blocked_countries": list(self.blocked_countries),
                "black_ips": list(self.black_ips),
                "white_ips": list(self.white_ips),
                "blocked_ports": list(self.blocked_ports),
                "waf_enabled": self.waf_enabled,
                "waf_port": self.waf_port,
                "target_port": self.target_port,
                "file_guard_enabled": self.file_guard_enabled,
                "auto_sync_windows_firewall": self.auto_sync_windows_firewall,
                "ai_enabled": self.ai_enabled,
                "ai_sensitivity": self.ai_sensitivity,
                "ai_precision_v2_migrated": self.ai_precision_v2_migrated,
                "geo_blocked_history": self.geo_blocked_history[-200:],
                "threat_blocked_history": self.threat_blocked_history[-500:],
                "ai_anomaly_history": self.ai_anomaly_history[-300:]
            }
            try:
                with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
            except Exception:
                pass

    def add_black_ip(self, ip: str):
        with self.lock:
            self.black_ips.add(ip)
            if ip in self.white_ips:
                self.white_ips.remove(ip)
        self.save()

    def remove_black_ip(self, ip: str):
        with self.lock:
            self.black_ips.discard(ip)
        self.save()

    def add_white_ip(self, ip: str):
        with self.lock:
            self.white_ips.add(ip)
            self.black_ips.discard(ip)
        self.save()

    def remove_white_ip(self, ip: str):
        with self.lock:
            self.white_ips.discard(ip)
        self.save()

    def toggle_country(self, country_code: str, block: bool):
        with self.lock:
            if block:
                self.blocked_countries.add(country_code)
            else:
                self.blocked_countries.discard(country_code)
        self.save()

    def toggle_port(self, port: int, block: bool):
        with self.lock:
            if block:
                self.blocked_ports.add(port)
            else:
                self.blocked_ports.discard(port)
        self.save()

    def record_geo_block(self, ip: str, country: str, time_str: str, reason: str):
        """국가별 차단에 의해 탐지된 IP를 기록하고 BlackIP에 자동 등록"""
        with self.lock:
            if ip not in self.black_ips:
                self.black_ips.add(ip)
            
            entry = {
                "timestamp": time_str,
                "ip": ip,
                "country": country,
                "reason": reason
            }
            self.geo_blocked_history.insert(0, entry)
            if len(self.geo_blocked_history) > 300:
                self.geo_blocked_history = self.geo_blocked_history[:300]
        self.save()

    def record_threat_block(self, ip: str, country: str, time_str: str, rule_name: str, details: str):
        """지능형 침해 시도(APT, Log4j, Fastjson, SQLi, AI 자율차단 등) 차단 IP를 영구 보존하고 BlackIP/방화벽에 누적"""
        with self.lock:
            if ip not in self.black_ips:
                self.black_ips.add(ip)
            
            entry = {
                "timestamp": time_str,
                "ip": ip,
                "country": country,
                "rule": rule_name,
                "details": details
            }
            self.threat_blocked_history.insert(0, entry)
            if len(self.threat_blocked_history) > 500:
                self.threat_blocked_history = self.threat_blocked_history[:500]
        self.save()

    def record_ai_anomaly(self, ip: str, country: str, time_str: str, score: int, category: str, xai_reason: str, blocked: bool):
        """AI 이상 징후 및 자율 차단 내역을 영구 기록"""
        with self.lock:
            if blocked and ip not in ("127.0.0.1", "::1") and ip not in self.black_ips:
                self.black_ips.add(ip)
            entry = {
                "timestamp": time_str,
                "ip": ip,
                "country": country,
                "score": str(score),
                "category": category,
                "action": "AI_AUTO_BLOCK" if blocked else "AI_ANOMALY_WATCH",
                "xai_reason": xai_reason
            }
            self.ai_anomaly_history.insert(0, entry)
            if len(self.ai_anomaly_history) > 300:
                self.ai_anomaly_history = self.ai_anomaly_history[:300]
        self.save()
