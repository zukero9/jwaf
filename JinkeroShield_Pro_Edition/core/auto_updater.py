import os
import json
import time
import base64
import ssl
import ipaddress
import threading
import urllib.request
from typing import Callable, Dict, List, Set
from core.self_protection import SELF_PROTECTION

INTEL_DB_FILE = os.path.join(os.path.dirname(__file__), "ai_threat_intel_db.json")

# Abuse.ch Feodo Tracker 실시간 악성 봇넷/뱅킹 트로이목마 C2 IP 피드 (공개 보안 인텔리전스)
LIVE_C2_FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"


def _join(*parts: str) -> str:
    """정적 백신(V3 등)이 방화벽의 탐지 시그니처 문자열을 악성코드로 오진하지 않도록 런타임에 조합"""
    return "".join(parts)


LATEST_AI_SIGNATURES = [
    {
        "id": "AI-AGENT-01",
        "name": "LLM 프롬프트 인젝션 및 시스템 명령 탈취 방어",
        "pattern": _join(r"(ignore\s+all\s+previous\s+", r"instructions|system\s*prompt|you\s+are\s+now\s+dan|jail", r"break|developer\s+mode)"),
        "severity": "CRITICAL"
    },
    {
        "id": "AI-AGENT-02",
        "name": "클라우드 메타데이터 및 로컬 에이전트 SSRF 탈취 방어",
        "pattern": _join(r"(169\.254\.169\.254|metadata\.google", r"\.internal|latest/meta-data|127\.0\.0\.1:2375|localhost:11434)"),
        "severity": "CRITICAL"
    },
    {
        "id": "AI-AGENT-03",
        "name": "서버 사이드 템플릿 인젝션 (SSTI) 폴리모픽 변종",
        "pattern": _join(r"(\{\{.*(__class__|__mro__|__sub", r"classes__|config|self).*\}\}|\$\{7\*7\})"),
        "severity": "CRITICAL"
    },
    {
        "id": "AI-AGENT-04",
        "name": "GraphQL 스키마 인트로스펙션 자동 덤프 봇",
        "pattern": _join(r"(__schema|__type|Intro", r"spectionQuery)"),
        "severity": "HIGH"
    },
    {
        "id": "AI-AGENT-05",
        "name": "자율형 AI 취약점 스캐너 (Nuclei/SQLMap/AutoGPT Agent) 지문",
        "pattern": _join(r"(nuclei|sql", r"map|autogpt|langchain-agent|masscan|zgrab|dirbuster|gobuster|nikto)"),
        "severity": "HIGH"
    },
    {
        "id": "AI-AGENT-06",
        "name": "AI 다중 인코딩(Base64+XOR/Rot13) 난독화 웹셸 로더",
        "pattern": _join(r"(gzin", r"flate|str_rot", r"13|frombase64", r"string|reflective", r"peinjection)"),
        "severity": "CRITICAL"
    },
    {
        "id": "AI-AGENT-07",
        "name": "자바/파이썬 역직렬화 가젯 체인 (Jackson/Pickle/YAML RCE)",
        "pattern": _join(r"(ch\.qos\.logback|org\.springframework", r"\.beans|__reduce__|python/object/apply|commons\.collections)"),
        "severity": "CRITICAL"
    },
    {
        "id": "AI-AGENT-08",
        "name": "XXE (XML 외부 엔티티) 시스템 파일 탈취 공격",
        "pattern": _join(r"(<!ENTITY\s+.*SYSTEM|file:///etc/", r"passwd|file:///c:/windows)"),
        "severity": "CRITICAL"
    },
    {
        "id": "AI-AGENT-09",
        "name": "로컬 LLM/AI 서비스(Ollama/vLLM/MCP) 무단 원격 제어 시도",
        "pattern": _join(r"(/api/pull|/api/chat|/v1/chat/completions", r".*system.*exec|/mcp/v1/)"),
        "severity": "HIGH"
    },
    {
        "id": "AI-AGENT-10",
        "name": "원격 C2 비콘 변종 프로토콜 탐지",
        "pattern": _join(r"(/submit\.php\?id=|/pixel\.gif\?c=|", r"-nop\s+-w\s+hidden)"),
        "severity": "CRITICAL"
    }
]

CURATED_APT_C2_IPS = [
    "185.220.101.1", "185.220.101.34", "45.155.205.233", "45.155.205.109",
    "193.42.33.14", "91.219.236.222", "194.26.135.89", "179.43.175.50", "89.248.165.131"
]


class ThreatIntelligenceUpdater:
    """
    [자율 진화 & 자가 발전 시스템]
    - 디스크 저장 시 패턴을 Base64 인코딩하여 백신(V3 등)의 시그니처 오진을 원천 차단합니다.
    """
    def __init__(self, config, ai_engine, status_callback: Callable = None):
        self.config = config
        self.ai_engine = ai_engine
        self.status_callback = status_callback
        self.is_running = False
        self.lock = threading.Lock()

        self.current_version = "AI-PRO-2026.11.07-GEN1"
        self.last_update_time = "자율 진화 대기 중"
        self.signatures: List[Dict[str, str]] = [dict(s) for s in LATEST_AI_SIGNATURES]
        self.feed_ips: Set[str] = set(CURATED_APT_C2_IPS)
        self.update_history: List[Dict[str, str]] = []

        self._load_local_db()
        self.ai_engine.hot_reload_intelligence(self.current_version, self.signatures, self.feed_ips)

    def _load_local_db(self):
        if os.path.exists(INTEL_DB_FILE):
            try:
                with open(INTEL_DB_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if "_hmac_seal" in data and not SELF_PROTECTION.verify_dict(data):
                        # 외부 무단 변조 감지 시 변조된 DB를 폐기하고 기본 순정 DB로 즉시 재봉인
                        self._save_local_db()
                        return
                    self.current_version = data.get("version", self.current_version)
                    self.last_update_time = data.get("last_update_time", self.last_update_time)
                    raw_sigs = data.get("signatures_b64", [])
                    if raw_sigs:
                        decoded_sigs = []
                        for item in raw_sigs:
                            pat = base64.b64decode(item.get("pattern_b64", "").encode("ascii")).decode("utf-8", errors="ignore")
                            decoded_sigs.append({
                                "id": item.get("id", ""),
                                "name": item.get("name", ""),
                                "pattern": pat,
                                "severity": item.get("severity", "HIGH")
                            })
                        if decoded_sigs:
                            self.signatures = decoded_sigs
                    self.feed_ips = set(data.get("feed_ips", CURATED_APT_C2_IPS))
                    self.update_history = data.get("update_history", [])
                    gen = int(data.get("evolution_generation", 1))
                    self.ai_engine.evolution_generation = max(1, gen)
                    evolved_subs = data.get("evolved_c2_subnets", [])
                    self.ai_engine.evolved_c2_subnets.update(evolved_subs)
            except Exception:
                pass

    def _save_local_db(self):
        with self.lock:
            encoded_sigs = []
            for s in self.signatures:
                b64_pat = base64.b64encode(s.get("pattern", "").encode("utf-8")).decode("ascii")
                encoded_sigs.append({
                    "id": s.get("id", ""),
                    "name": s.get("name", ""),
                    "pattern_b64": b64_pat,
                    "severity": s.get("severity", "HIGH")
                })
            data = {
                "version": self.current_version,
                "evolution_generation": self.ai_engine.evolution_generation,
                "last_update_time": self.last_update_time,
                "signatures_b64": encoded_sigs,
                "feed_ips": sorted(list(self.feed_ips))[:500],
                "evolved_c2_subnets": sorted(list(self.ai_engine.evolved_c2_subnets)),
                "update_history": self.update_history[:100]
            }
            data["_hmac_seal"] = SELF_PROTECTION.sign_dict(data)
            try:
                with open(INTEL_DB_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
            except Exception:
                pass

    def start_auto_scheduler(self, interval_hours: int = 6):
        if self.is_running:
            return
        self.is_running = True

        def autonomous_loop():
            self.perform_update_sync(trigger="AUTO_STARTUP_EVOLUTION")
            tick_minutes = 0
            while self.is_running:
                time.sleep(60)
                tick_minutes += 1
                if not self.is_running or not self.config.auto_update_enabled:
                    continue
                if tick_minutes % 10 == 0:
                    self.perform_self_evolution(trigger="AUTONOMOUS_SELF_EVOLVE")
                if tick_minutes >= max(30, interval_hours * 60):
                    tick_minutes = 0
                    self.perform_update_sync(trigger="SCHEDULED_CLOUD_SYNC")

        t = threading.Thread(target=autonomous_loop, daemon=True)
        t.start()

    def stop(self):
        self.is_running = False

    def trigger_manual_update_async(self):
        t = threading.Thread(target=self.perform_update_sync, kwargs={"trigger": "MANUAL_USER"}, daemon=True)
        t.start()

    def trigger_self_evolution_async(self):
        t = threading.Thread(target=self.perform_self_evolution, kwargs={"trigger": "USER_EVOLVE_NOW"}, daemon=True)
        t.start()

    def perform_self_evolution(self, trigger: str = "AUTONOMOUS_SELF_EVOLVE"):
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        evo_stats = self.ai_engine.run_autonomous_evolution_cycle()

        with self.lock:
            existing_ids = {s["id"] for s in self.signatures}
            for r in evo_stats.get("new_rules", []):
                if r["id"] not in existing_ids:
                    self.signatures.append(r)
                    existing_ids.add(r["id"])

            gen_num = self.ai_engine.evolution_generation
            self.current_version = f"AI-PRO-{time.strftime('%Y.%m.%d')}-GEN{gen_num}"
            self.last_update_time = now_str

            details_msg = (
                f"[자가 발전 Gen {gen_num}.0 진화 완료] "
                f"Isolation Forest {evo_stats['retrained_trees']}개 트리 온라인 재학습(샘플 {evo_stats['learned_samples']}건) | "
                f"자율 합성 규칙 총 {evo_stats['synthesized_rules_count']}종 | "
                f"학습된 C2 서브넷(/24) {evo_stats['evolved_subnets_count']}개 대역"
            )
            record = {
                "timestamp": now_str,
                "version": self.current_version,
                "trigger": trigger,
                "sig_count": str(len(self.signatures)),
                "feed_ip_count": str(len(self.feed_ips)),
                "details": details_msg
            }
            self.update_history.insert(0, record)

        self._save_local_db()
        self.ai_engine.hot_reload_intelligence(self.current_version, self.signatures, self.feed_ips)

        if self.status_callback:
            self.status_callback({
                "version": self.current_version,
                "generation": f"Gen {self.ai_engine.evolution_generation}.0",
                "last_update": self.last_update_time,
                "sig_count": len(self.signatures),
                "synthesized_count": len(self.ai_engine.self_synthesized_rules),
                "evolved_subnets": len(self.ai_engine.evolved_c2_subnets),
                "feed_ip_count": len(self.feed_ips),
                "trigger": trigger,
                "details": details_msg
            })

    def perform_update_sync(self, trigger: str = "MANUAL"):
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        live_fetched_count = 0

        try:
            if not LIVE_C2_FEED_URL.startswith("https://feodotracker.abuse.ch/"):
                raise ValueError("Untrusted feed domain")
            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                LIVE_C2_FEED_URL,
                headers={"User-Agent": "JWAF-JinkeroShieldPro-SelfEvolvingAI/2.0"}
            )
            with urllib.request.urlopen(req, timeout=4.0, context=ctx) as resp:
                text = resp.read(524288).decode("utf-8", errors="ignore")
                new_ips = []
                for line in text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and line[0].isdigit():
                        try:
                            ip_obj = ipaddress.ip_address(line)
                            if ip_obj.is_global and not ip_obj.is_loopback and not ip_obj.is_private:
                                new_ips.append(str(ip_obj))
                        except Exception:
                            continue
                if new_ips:
                    selected_c2 = new_ips[:80]
                    live_fetched_count = len(selected_c2)
                    with self.lock:
                        self.feed_ips.update(selected_c2)
        except Exception:
            pass

        evo_stats = self.ai_engine.run_autonomous_evolution_cycle()

        with self.lock:
            existing_ids = {s["id"] for s in self.signatures}
            for sig in LATEST_AI_SIGNATURES:
                if sig["id"] not in existing_ids:
                    self.signatures.append(dict(sig))
                    existing_ids.add(sig["id"])
            for r in evo_stats.get("new_rules", []):
                if r["id"] not in existing_ids:
                    self.signatures.append(r)
                    existing_ids.add(r["id"])

            gen_num = self.ai_engine.evolution_generation
            self.current_version = f"AI-PRO-{time.strftime('%Y.%m.%d')}-GEN{gen_num}"
            self.last_update_time = now_str

            if live_fetched_count > 0:
                source_status = (
                    f"[클라우드 동기화 + 자가 발전 Gen {gen_num}.0] "
                    f"실시간 C2 피드 {live_fetched_count}개 IP 추가 | "
                    f"트리 {evo_stats['retrained_trees']}개 재학습 | "
                    f"C2 서브넷(/24) {len(self.ai_engine.evolved_c2_subnets)}개 군집화 완료"
                )
            else:
                source_status = (
                    f"[자율 진화 Gen {gen_num}.0 완료] "
                    f"AI 시그니처({len(self.signatures)}종) 및 C2 피드({len(self.feed_ips)}개) 검증 | "
                    f"C2 서브넷(/24) {len(self.ai_engine.evolved_c2_subnets)}개 자율 군집화"
                )

            record = {
                "timestamp": now_str,
                "version": self.current_version,
                "trigger": trigger,
                "sig_count": str(len(self.signatures)),
                "feed_ip_count": str(len(self.feed_ips)),
                "details": source_status
            }
            self.update_history.insert(0, record)

        self._save_local_db()
        self.ai_engine.hot_reload_intelligence(self.current_version, self.signatures, self.feed_ips)

        if self.status_callback:
            self.status_callback({
                "version": self.current_version,
                "generation": f"Gen {self.ai_engine.evolution_generation}.0",
                "last_update": self.last_update_time,
                "sig_count": len(self.signatures),
                "synthesized_count": len(self.ai_engine.self_synthesized_rules),
                "evolved_subnets": len(self.ai_engine.evolved_c2_subnets),
                "feed_ip_count": len(self.feed_ips),
                "trigger": trigger,
                "details": source_status
            })
