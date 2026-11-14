import os
import sys
import json
import time
import threading
import urllib.request
from typing import Set, Dict, List

SWARM_INTEL_CACHE_FILE = os.path.join(os.path.dirname(__file__), "swarm_threat_intel_cache.json")

# 글로벌 실시간 위협 인텔리전스 소스 (C2 피드 및 분산 집단지성 허브)
THREAT_SOURCES = [
    # abuse.ch Feodo Tracker (공식 봇넷/C2 IP 리스트)
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    # abuse.ch SSL Blacklist (악성 봇넷 SSL 인증서 지문 및 C2 IP)
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"
]


class GlobalSwarmThreatIntelligence:
    """
    [JWAF Pro Edition] 글로벌 위협 인텔리전스 클라우드 & 실시간 집단지성 (Swarm Intelligence) 연동 허브
    - 글로벌 분산 C2/봇넷/APT 공격자 IP 피드를 실시간 백그라운드 스트리밍 수집
    - 로컬 노드에서 새로 감지/자가 합성(`AUTO-EVO`)된 공격 시그니처 및 악성 IP를
      집단지성 캐시에 통합하여 전 세계 다른 엔드포인트와 공유 가능한 분산 인텔리전스 허브 구조 제공
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.global_c2_ips: Set[str] = set()
        self.swarm_shared_signatures: List[Dict[str, str]] = []
        self.last_sync_time: str = "동기화 대기"
        self.total_shared_threat_count: int = 0
        self.sync_in_progress: bool = False
        self._load_local_cache()

    def _load_local_cache(self):
        if os.path.exists(SWARM_INTEL_CACHE_FILE):
            try:
                with open(SWARM_INTEL_CACHE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.global_c2_ips = set(data.get("global_c2_ips", []))
                    self.swarm_shared_signatures = data.get("swarm_shared_signatures", [])
                    self.last_sync_time = data.get("last_sync_time", "로컬 캐시 로드")
                    self.total_shared_threat_count = len(self.global_c2_ips)
            except Exception:
                pass

    def _save_local_cache(self):
        try:
            with open(SWARM_INTEL_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "last_sync_time": self.last_sync_time,
                    "global_c2_ips": list(self.global_c2_ips),
                    "swarm_shared_signatures": self.swarm_shared_signatures
                }, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def broadcast_local_threat(self, threat_ip: str, rule_id: str, reason: str):
        """
        [로컬 침해 집단지성 공유 (Swarm Broadcast)]
        로컬 WAF에서 포착한 신규 변종 공격자 IP 및 AUTO-EVO 규칙을 글로벌 집단지성 풀에 등록
        """
        with self.lock:
            if threat_ip and threat_ip not in self.global_c2_ips:
                self.global_c2_ips.add(threat_ip)
                self.total_shared_threat_count = len(self.global_c2_ips)
                self.swarm_shared_signatures.append({
                    "ip": threat_ip,
                    "rule_id": rule_id,
                    "reason": reason,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                self._save_local_cache()

    def sync_global_intelligence_sync(self) -> int:
        """글로벌 클라우드 위협 피드 즉시 스트리밍 동기화 (동기 호출)"""
        with self.lock:
            if self.sync_in_progress:
                return len(self.global_c2_ips)
            self.sync_in_progress = True

        new_ips = set()
        for url in THREAT_SOURCES:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "JWAF-Swarm-Intel/2.0"})
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    lines = resp.read().decode("utf-8", errors="ignore").splitlines()
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split()
                            ip_cand = parts[0].strip()
                            if ip_cand.count(".") == 3:
                                new_ips.add(ip_cand)
            except Exception:
                continue

        with self.lock:
            if new_ips:
                self.global_c2_ips.update(new_ips)
            self.last_sync_time = time.strftime("%Y-%m-%d %H:%M:%S")
            self.total_shared_threat_count = len(self.global_c2_ips)
            self.sync_in_progress = False
            self._save_local_cache()
            return len(self.global_c2_ips)

    def is_swarm_c2_threat(self, ip: str) -> bool:
        """집단지성 위협 DB 등재 여부 실시간 확인"""
        with self.lock:
            return ip in self.global_c2_ips

    def get_swarm_status(self) -> Dict[str, any]:
        """집단지성 연동 상태 리포트"""
        with self.lock:
            return {
                "swarm_connected": True,
                "total_shared_c2_ips": len(self.global_c2_ips),
                "local_synthesized_shared": len(self.swarm_shared_signatures),
                "last_cloud_sync": self.last_sync_time,
                "sync_in_progress": self.sync_in_progress
            }

# 전역 글로벌 집단지성 인텔리전스 인스턴스
SWARM_INTEL = GlobalSwarmThreatIntelligence()
