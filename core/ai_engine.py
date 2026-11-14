import math
import time
import re
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Set

@dataclass
class AIAssessment:
    score: int                     # 0 ~ 100 AI 종합 위협 점수
    is_blocked: bool               # 자율 차단 여부 (확실한 고위험 공격만 True)
    is_suspicious: bool            # 주의/관찰 대상 여부 (70점 이상)
    category: str                  # AI 탐지 분류 코드
    xai_reason: str                # 설명 가능한 AI (XAI) 한글 판정 사유
    metrics: Dict[str, float] = field(default_factory=dict)


class AIBehavioralEngine:
    """
    온디바이스 하이브리드 AI 위협 탐지 및 자율 방어 엔진 (Jinkero AI Core - 오탐 방지 정밀 튜닝 버전)
    - 일반 웹 브라우징, 메신저, 클라우드/CDN 에페메럴(임시) 포트 통신은 정상 트래픽으로 안전하게 통과
    - 실제 난독화 쉘코드/웹셸, 원격 코드 실행(RCE) 변종 페이로드, 명백한 서비스 포트 스윕 등
      보안적으로 확실한 고위험 공격(기본 90점 이상)만 정밀 차단합니다.
    """
    SENSITIVITY_THRESHOLDS = {
        "CONSERVATIVE": 95,  # 보수적 (오탐 제로 지향 - 95점 이상 확실한 공격만 차단)
        "BALANCED": 90,      # 균형 (권장 기본값 - 90점 이상 확실한 공격만 차단)
        "AGGRESSIVE": 82     # 공격적 (금융권 고강도 보안 - 82점 이상 차단)
    }

    # 정상 사용자 애플리케이션 화이트리스트 (소켓 행위 오탐 원천 배제)
    TRUSTED_PROCESSES = {
        "chrome.exe", "msedge.exe", "firefox.exe", "whale.exe", "brave.exe",
        "kakaotalk.exe", "discord.exe", "slack.exe", "teams.exe", "zoom.exe",
        "svchost.exe", "system", "lsass.exe", "services.exe", "explorer.exe",
        "onedrive.exe", "code.exe", "antigravity.exe", "python.exe", "jinkeroshield.exe"
    }

    def __init__(self, sensitivity: str = "BALANCED", auto_block: bool = True):
        self.lock = threading.Lock()
        self.sensitivity = sensitivity if sensitivity in self.SENSITIVITY_THRESHOLDS else "BALANCED"
        self.auto_block = auto_block

        # IP별 최근 접속 타임스탬프 큐 (슬라이딩 윈도우 60초)
        self.ip_timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=120))
        # IP별 접근한 로컬 '서비스' 포트 집합 (임시 포트 49152~65535 제외)
        self.ip_service_ports: Dict[str, Set[int]] = defaultdict(set)
        # IP별 접근한 URI 경로 집합
        self.ip_paths: Dict[str, Set[str]] = defaultdict(set)
        # IP별 확실한 공격 위반 횟수
        self.ip_violation_count: Dict[str, int] = defaultdict(int)

        # 전체 트래픽 통계 베이스라인 (Z-Score 계산용)
        self.rate_history: deque = deque(maxlen=200)
        self.total_ai_analyzed: int = 0
        self.total_ai_blocked: int = 0
        self.total_ai_anomalies: int = 0

        # 확실한 공격성 난독화/변종 침투 토큰 패턴
        self.high_risk_tokens = [
            "eval(", "base64_decode", "fromcharcode", "getruntime", "exec(",
            "processbuilder", "powershell", "invoke-expression", "downloadstring",
            "cmd.exe", "/bin/sh", "/bin/bash", "wscript.shell", "xp_cmdshell",
            "union select", "Waitfor delay", "${jndi:", "0x4141", "\\x90\\x90"
        ]

    @property
    def block_threshold(self) -> int:
        return self.SENSITIVITY_THRESHOLDS.get(self.sensitivity, 90)

    def set_sensitivity(self, mode: str):
        if mode in self.SENSITIVITY_THRESHOLDS:
            self.sensitivity = mode

    @staticmethod
    def compute_shannon_entropy(data: str) -> float:
        """문자열의 샤넌 정보 엔트로피 H(X) = -sum(p * log2(p)) 계산 (0.0 ~ 8.0)"""
        if not data or len(data) < 12:
            return 0.0
        length = len(data)
        freq = defaultdict(int)
        for ch in data:
            freq[ch] += 1
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    def compute_ngram_anomaly_score(self, payload: str) -> float:
        """
        페이로드의 특수문자 밀도, 비정상 인코딩 비율, 고위험 공격 토큰 출현 빈도를
        결합하여 0.0 ~ 100.0 사이의 변종 공격 점수를 산출합니다.
        (단순 긴 URL이나 일반 파라미터는 낮은 점수가 나오도록 보정)
        """
        if not payload or len(payload) < 8:
            return 0.0

        lower_p = payload.lower()
        length = len(payload)

        # 1. 공격용 특수 기호 밀도 (일반 URL 구분자 /, ?, &, =, - 는 제외!)
        attack_chars = sum(1 for c in payload if c in "';\"`$(){}[]<>|\\^~")
        special_ratio = attack_chars / length

        # 2. Hex / Unicode 이스케이프 시퀀스 밀도 (\xXX, \uXXXX, %24%7B 등)
        hex_escapes = len(re.findall(r"(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|%2[247]|%3[bBcCeE]|%7[bBdD])", payload))
        encoding_score = min(35.0, hex_escapes * 6.0)

        # 3. 확실한 공격 N-gram 토큰 매칭
        token_hits = sum(1 for tok in self.high_risk_tokens if tok in lower_p)
        token_score = min(65.0, token_hits * 28.0)

        raw_score = (special_ratio * 120.0) + encoding_score + token_score
        return round(min(100.0, raw_score), 1)

    def _compute_rate_zscore(self, current_rate: float) -> float:
        """전체 트래픽 베이스라인 대비 현재 IP 요청 속도의 통계적 Z-Score 계산"""
        self.rate_history.append(current_rate)
        if len(self.rate_history) < 15:
            return 0.0
        mean = sum(self.rate_history) / len(self.rate_history)
        var = sum((r - mean) ** 2 for r in self.rate_history) / len(self.rate_history)
        std = math.sqrt(var)
        if std < 2.0:
            std = 2.0
        z = max(0.0, (current_rate - mean) / std)
        return round(z, 2)

    def analyze_http_request(self, ip: str, method: str, path: str, headers: Dict[str, str], body: str = "") -> AIAssessment:
        """
        인라인 WAF HTTP 트래픽에 대한 정밀 AI 분석:
        고엔트로피(난독화)와 공격성 N-gram 패턴이 동시에 확인되는 확실한 변종 공격만 차단합니다.
        """
        now = time.time()
        target_inspect = f"{path} {body}".strip()

        with self.lock:
            self.total_ai_analyzed += 1
            ts_dq = self.ip_timestamps[ip]
            ts_dq.append(now)
            self.ip_paths[ip].add(path.split("?")[0])

            recent_60s = [t for t in ts_dq if now - t <= 60.0]
            req_per_min = len(recent_60s)
            unique_paths = len(self.ip_paths[ip])
            prior_violations = self.ip_violation_count[ip]

        # 1. 샤넌 엔트로피 측정
        entropy = self.compute_shannon_entropy(target_inspect)
        # 2. N-gram 변종 공격 패턴 점수
        ngram_score = self.compute_ngram_anomaly_score(target_inspect)

        # 엔트로피 단독으로는 정상 토큰/쿠키일 수 있으므로 N-gram 공격 징후가 동반될 때만 고점수 부여
        payload_risk = ngram_score
        if entropy >= 5.1 and ngram_score >= 45.0:
            payload_risk = min(100.0, ngram_score + 30.0)
        elif entropy >= 5.5 and len(target_inspect) > 60 and ngram_score >= 25.0:
            payload_risk = max(payload_risk, 78.0)

        # 3. 극단적인 디렉터리 스캐닝 폭주 (분당 120회 이상 + 30개 이상 상이한 경로)
        z_score = self._compute_rate_zscore(float(req_per_min))
        burst_score = 0.0
        if req_per_min >= 120 and unique_paths >= 25:
            burst_score = min(92.0, 65.0 + (req_per_min / 10.0))

        history_bonus = min(10.0, prior_violations * 5.0) if payload_risk >= 60 else 0.0
        composite_score = int(min(100, round(max(payload_risk, burst_score) + history_bonus)))

        reasons = []
        category = "AI_NORMAL"

        if payload_risk >= 75.0:
            reasons.append(f"확실한 변종 쉘코드/난독화 침투 패턴(엔트로피 H={entropy:.2f}, N-gram={ngram_score:.0f}%)")
            category = "AI_ZERO_DAY_OBFUSCATION"
        elif payload_risk >= 50.0:
            reasons.append(f"의심 특수문자/인코딩 페이로드 포함(N-gram={ngram_score:.0f}%)")
            category = "AI_SUSPICIOUS_PAYLOAD"

        if burst_score >= 70.0:
            reasons.append(f"대규모 자동화 웹 스캐닝 폭주(분당 {req_per_min}회, 경로 {unique_paths}개)")
            if category == "AI_NORMAL":
                category = "AI_WEB_SCANNER_FLOOD"

        is_blocked = self.auto_block and (composite_score >= self.block_threshold)
        is_suspicious = composite_score >= 70

        with self.lock:
            if is_blocked:
                self.ip_violation_count[ip] += 1
                self.total_ai_blocked += 1
                self.total_ai_anomalies += 1
            elif is_suspicious:
                self.total_ai_anomalies += 1

        if not reasons:
            xai_reason = f"[AI 위협점수 {composite_score}점] 정상 웹 요청 (엔트로피 H={entropy:.2f})"
        else:
            status_tag = "확실한 위협 차단됨" if is_blocked else "주의 관찰"
            xai_reason = f"[AI 위협점수 {composite_score}점 | {status_tag}] " + ", ".join(reasons)

        return AIAssessment(
            score=composite_score,
            is_blocked=is_blocked,
            is_suspicious=is_suspicious,
            category=category,
            xai_reason=xai_reason,
            metrics={
                "entropy": entropy,
                "ngram_score": ngram_score,
                "req_per_min": float(req_per_min),
                "z_score": z_score
            }
        )

    def analyze_socket_connection(self, remote_ip: str, remote_port: int, local_port: int, proc_name: str) -> AIAssessment:
        """
        로컬 PC 소켓 연결에 대한 정밀 AI 분석:
        - 일반 브라우저/메신저/시스템의 외부 HTTPS(443), HTTP(80), DNS(53) 및 임시 포트(>=10000) 통신은
          절대 오탐하거나 차단하지 않습니다.
        - 외부 IP가 내 PC의 주요 서버/시스템 포트(< 10000)를 다수 스캔하거나,
          위험 시스템 도구(certutil, mshta 등)가 비정상 외부 포트와 다량 통신할 때만 고위험으로 판정합니다.
        """
        if remote_ip in ("127.0.0.1", "::1", "0.0.0.0") or remote_ip.startswith(("192.168.", "10.", "172.")):
            return AIAssessment(0, False, False, "AI_LOCAL", "[AI 위협점수 0점] 내부/로컬 안전 네트워크 통신")

        proc_lower = (proc_name or "").lower()

        # 신뢰 프로세스 또는 일반적인 웹/DNS 아웃바운드 통신(443, 80, 53)이고 로컬 포트가 임시 포트(>=10000)인 경우 정상 통과
        if proc_lower in self.TRUSTED_PROCESSES and local_port >= 10000:
            return AIAssessment(2, False, False, "AI_NORMAL", f"[AI 위협점수 2점] 신뢰 프로세스({proc_name})의 정상 외부 통신")

        if remote_port in (80, 443, 53, 8443, 5228) and local_port >= 10000 and proc_lower not in ("certutil.exe", "mshta.exe", "bitsadmin.exe"):
            return AIAssessment(5, False, False, "AI_NORMAL", f"[AI 위협점수 5점] 표준 웹/보안 프로토콜(포트 {remote_port}) 정상 통신")

        now = time.time()
        with self.lock:
            self.total_ai_analyzed += 1
            ts_dq = self.ip_timestamps[remote_ip]
            ts_dq.append(now)

            # 오직 시스템/서비스 포트(1 ~ 9999)에 대한 인입만 포트 스캔 집계에 반영 (임시 클라이언트 포트 제외!)
            if 0 < local_port < 10000:
                self.ip_service_ports[remote_ip].add(local_port)

            recent_60s = [t for t in ts_dq if now - t <= 60.0]
            conn_rate = len(recent_60s)
            service_port_spread = len(self.ip_service_ports[remote_ip])

        # 1. 서비스 포트 스캐닝(Port Sweep): 동일 외부 IP가 내 PC의 10000번 미만 서비스 포트를 8개 이상 스캔한 확실한 경우
        port_scan_score = 0.0
        if service_port_spread >= 10:
            port_scan_score = 94.0
        elif service_port_spread >= 5:
            port_scan_score = 72.0

        # 2. 고위험 해킹 악용 도구(LoLBin)가 직접 외부 비표준 포트로 접속하는 경우
        lolbin_risk = 0.0
        if any(p in proc_lower for p in ("certutil", "mshta", "bitsadmin", "regsvr32", "wscript", "cscript")):
            lolbin_risk = 88.0 if remote_port not in (80, 443) else 72.0

        # 3. 비정상적인 대규모 소켓 폭주 (분당 150회 이상 단일 IP 연결)
        flood_score = 0.0
        if conn_rate >= 150 and service_port_spread >= 2:
            flood_score = 91.0

        composite_score = int(min(100, round(max(port_scan_score, lolbin_risk, flood_score))))

        reasons = []
        category = "AI_NORMAL"

        if port_scan_score >= 70.0:
            reasons.append(f"내부 서비스 포트 집중 스캐닝 감지({service_port_spread}개 서비스 포트 탐색)")
            category = "AI_PORT_SCAN_ANOMALY"
        if lolbin_risk >= 70.0:
            reasons.append(f"시스템 유틸리티({proc_name})의 비정상 외부 원격 통신 감지")
            category = "AI_LOLBIN_NETWORK"
        if flood_score >= 85.0:
            reasons.append(f"단일 IP 대규모 세션 플러딩 공격(분당 {conn_rate}회)")
            category = "AI_CONNECTION_FLOOD"

        is_blocked = self.auto_block and (composite_score >= self.block_threshold)
        is_suspicious = composite_score >= 70

        with self.lock:
            if is_blocked:
                self.ip_violation_count[remote_ip] += 1
                self.total_ai_blocked += 1
                self.total_ai_anomalies += 1
            elif is_suspicious:
                self.total_ai_anomalies += 1

        if not reasons:
            xai_reason = f"[AI 위협점수 {composite_score}점] 정상 소켓 통신 (프로세스: {proc_name})"
        else:
            status_tag = "확실한 위협 자율 격리" if is_blocked else "주의 관찰"
            xai_reason = f"[AI 위협점수 {composite_score}점 | {status_tag}] " + ", ".join(reasons)

        return AIAssessment(
            score=composite_score,
            is_blocked=is_blocked,
            is_suspicious=is_suspicious,
            category=category,
            xai_reason=xai_reason,
            metrics={
                "conn_rate": float(conn_rate),
                "service_port_spread": float(service_port_spread)
            }
        )
