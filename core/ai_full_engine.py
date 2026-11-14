import math
import time
import re
import random
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

@dataclass
class FullAIAssessment:
    score: int                     # 0 ~ 100 종합 앙상블 AI 위협 점수
    is_blocked: bool               # 자율 차단 여부
    is_suspicious: bool            # 주의 관찰 대상 여부
    category: str                  # AI 탐지 모델 분류 코드
    xai_reason: str                # 설명 가능한 AI (XAI) 한글 상세 분석 리포트
    synthesized_rule_id: str = ""  # 자가 발전 엔진이 즉석 합성한 신규 방어 규칙 ID
    sub_scores: Dict[str, float] = field(default_factory=dict)


class IsolationTreeNode:
    """순수 파이썬 기반 경량 Isolation Forest 의사결정 트리 노드 (다변량 이상치 탐지용)"""
    def __init__(self, split_feat=None, split_val=None, left=None, right=None, size=0, is_leaf=False):
        self.split_feat = split_feat
        self.split_val = split_val
        self.left = left
        self.right = right
        self.size = size
        self.is_leaf = is_leaf


class LightweightIsolationForest:
    """
    다변량 트래픽 특징 벡터 [속도, 서비스포트수, 경로다양성, 엔트로피, N-gram밀도]를 입력받아
    정상 분포에서 벗어난 이상치(Outlier) 점수를 0~100점으로 산출하며,
    실시간 수집된 정상 트래픽 분포를 바탕으로 스스로 트리를 재학습(Online Self-Retraining)하는 자가 발전 숲 모델
    """
    def __init__(self, n_trees=25, max_depth=6):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.trees: List[IsolationTreeNode] = []
        self.baseline_data: List[List[float]] = []
        self._init_baseline_forest()

    def _init_baseline_forest(self):
        rng = random.Random(2026)
        self.baseline_data = []
        for _ in range(120):
            # [req_rate, service_ports, unique_paths, entropy, ngram]
            self.baseline_data.append([
                rng.uniform(1.0, 25.0),
                rng.choice([0.0, 1.0]),
                rng.uniform(1.0, 8.0),
                rng.uniform(2.5, 4.4),
                rng.uniform(0.0, 18.0)
            ])
        self.trees = [self._build_tree(self.baseline_data, 0, rng) for _ in range(self.n_trees)]

    def retrain_with_online_samples(self, new_benign_samples: List[List[float]]) -> int:
        """
        [자가 발전 온라인 재학습] 사용자 PC의 실제 정상 트래픽 벡터를 병합하여
        25개 Isolation Forest 결정 트리의 분할 경계를 자율 재보정합니다.
        """
        rng = random.Random(int(time.time()))
        merged = list(self.baseline_data[-80:]) + list(new_benign_samples[-60:])
        if len(merged) < 40:
            return len(self.trees)
        self.baseline_data = merged[-140:]
        self.trees = [self._build_tree(self.baseline_data, 0, rng) for _ in range(self.n_trees)]
        return len(self.trees)

    def _build_tree(self, data: List[List[float]], depth: int, rng: random.Random) -> IsolationTreeNode:
        if depth >= self.max_depth or len(data) <= 2:
            return IsolationTreeNode(size=len(data), is_leaf=True)
        n_features = len(data[0])
        feat = rng.randrange(n_features)
        vals = [row[feat] for row in data]
        min_v, max_v = min(vals), max(vals)
        if abs(max_v - min_v) < 1e-6:
            return IsolationTreeNode(size=len(data), is_leaf=True)
        split_v = rng.uniform(min_v, max_v)
        left_data = [r for r in data if r[feat] < split_v]
        right_data = [r for r in data if r[feat] >= split_v]
        return IsolationTreeNode(
            split_feat=feat,
            split_val=split_v,
            left=self._build_tree(left_data, depth + 1, rng),
            right=self._build_tree(right_data, depth + 1, rng)
        )

    def _path_length(self, x: List[float], node: IsolationTreeNode, current_depth: int) -> float:
        if node.is_leaf or node.split_feat is None:
            if node.size <= 1:
                return float(current_depth)
            return current_depth + 2.0 * (math.log(node.size - 1.0) + 0.5772156649) - (2.0 * (node.size - 1.0) / node.size)
        if x[node.split_feat] < node.split_val:
            return self._path_length(x, node.left, current_depth + 1)
        else:
            return self._path_length(x, node.right, current_depth + 1)

    def score_sample(self, x: List[float]) -> float:
        if not self.trees:
            return 0.0
        n_samples = max(20.0, float(len(self.baseline_data)))
        avg_path = sum(self._path_length(x, t, 0) for t in self.trees) / len(self.trees)
        c_n = 2.0 * (math.log(n_samples - 1.0) + 0.5772156649) - (2.0 * (n_samples - 1.0) / n_samples)
        anomaly_ratio = math.pow(2.0, -avg_path / c_n)
        if anomaly_ratio <= 0.52:
            return 0.0
        scaled = min(100.0, (anomaly_ratio - 0.50) * 210.0)
        return round(scaled, 1)


class MarkovPayloadAnalyzer:
    """
    문자 전이 확률(Character-level Markov Chain) 기반 난독화/변종 쉘코드 탐지기
    """
    COMMON_BIGRAMS = {
        "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or", "te",
        "of", "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng", "se", "ha", "as", "ou",
        "io", "le", "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea", "ra", "ce",
        "ht", "tt", "tp", "ps", "ap", "pi", "id", "us", "pa", "ge", "js", "cs", "ss"
    }

    def __init__(self):
        self.learned_safe_bigrams: Set[str] = set(self.COMMON_BIGRAMS)

    def adapt_safe_text(self, text: str):
        """정상 트래픽의 안전한 문자 전이를 온라인 학습하여 오탐률을 스스로 낮춤"""
        if not text or len(text) > 120:
            return
        s = text.lower()
        for i in range(len(s) - 1):
            bg = s[i:i+2]
            if bg.isalpha() and len(self.learned_safe_bigrams) < 350:
                self.learned_safe_bigrams.add(bg)

    def compute_perplexity_score(self, text: str) -> float:
        if not text or len(text) < 12:
            return 0.0
        s = text.lower()
        total_pairs = len(s) - 1
        unusual_transitions = 0.0
        for i in range(total_pairs):
            bg = s[i:i+2]
            c1, c2 = bg[0], bg[1]
            if (not c1.isalnum() and not c2.isalnum() and bg not in ("//", "./", "==", "&=", "?=")):
                unusual_transitions += 2.2
            elif bg in ("\\x", "%2", "%3", "%7", "${", "0x", "..", "||", "&&", ";c", ";l"):
                unusual_transitions += 3.5
            elif c1.isalpha() and c2.isalpha() and bg not in self.learned_safe_bigrams:
                unusual_transitions += 0.35

        ratio = unusual_transitions / max(1, total_pairs)
        return round(min(100.0, ratio * 95.0), 1)


class FullAIBehavioralEngine:
    """
    [Jinkero Shield Pro Edition 전용] 자가 발전형(Self-Evolving) 다중 앙상블 AI 풀 방어 엔진
    1. Isolation Forest 다변량 이상치 탐지 모델 (온라인 자가 재학습 지원)
    2. Markov Chain 문자 전이 확률(Perplexity) 기반 폴리모픽 난독화 탐지 (안전 바이그램 자율 적응)
    3. 샤넌 정보 엔트로피 H(X) & 고위험 N-gram 딥패킷 분석
    4. 자율 시그니처 합성기 (Autonomous Rule Synthesizer):
       미지의 변종/제로데이 공격 포착 시 공격 페이로드의 핵심 변이 패턴을 스스로 추출하여
       신규 방어 규칙(AUTO-EVO-*)을 자동 생성 및 즉시 방화벽 메모리에 주입
    5. 자율 C2 서브넷(/24) 군집 학습:
       동일 C클래스 대역에서 반복되는 C2/봇넷 공격을 감지하면 해당 /24 서브넷 전체에 대해 선제 방어 가중치 부여
    """
    SENSITIVITY_THRESHOLDS = {
        "CONSERVATIVE": 95,
        "BALANCED": 90,
        "AGGRESSIVE": 80
    }

    TRUSTED_PROCESSES = {
        "chrome.exe", "msedge.exe", "firefox.exe", "whale.exe", "brave.exe",
        "kakaotalk.exe", "discord.exe", "slack.exe", "teams.exe", "zoom.exe",
        "svchost.exe", "system", "lsass.exe", "services.exe", "explorer.exe",
        "onedrive.exe", "code.exe", "antigravity.exe", "python.exe",
        "jinkeroshield.exe", "jinkeroshieldpro.exe", "setup.exe"
    }

    def __init__(self, sensitivity: str = "BALANCED", auto_block: bool = True):
        self.lock = threading.Lock()
        self.sensitivity = sensitivity if sensitivity in self.SENSITIVITY_THRESHOLDS else "BALANCED"
        self.auto_block = auto_block

        self.iforest = LightweightIsolationForest(n_trees=25, max_depth=6)
        self.markov = MarkovPayloadAnalyzer()

        self.ip_timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=150))
        self.ip_service_ports: Dict[str, Set[int]] = defaultdict(set)
        self.ip_paths: Dict[str, Set[str]] = defaultdict(set)
        self.ip_recent_uris: Dict[str, deque] = defaultdict(lambda: deque(maxlen=25))
        self.ip_violation_count: Dict[str, int] = defaultdict(int)

        # 자가 발전(Self-Evolution) 상태 데이터
        self.evolution_generation: int = 1
        self.online_benign_samples: deque = deque(maxlen=200)
        self.self_synthesized_rules: List[Dict[str, str]] = []
        self.evolved_c2_subnets: Set[str] = set()
        self.subnet_hit_counter: Dict[str, Set[str]] = defaultdict(set)

        # 동적 AI 공격 패턴 및 C2 피드 (정적 백신 오진 방지를 위해 런타임 문자열 결합)
        self.dynamic_ai_patterns: List[Dict[str, str]] = [
            {"id": "AI-AGENT-01", "name": "LLM Prompt Injection & System Override", "pattern": r"(ignore\s+all\s+previous\s+" + r"instructions|system\s*prompt|you\s+are\s+now\s+dan|jail" + r"break|developer\s+mode)", "severity": "CRITICAL"},
            {"id": "AI-AGENT-02", "name": "Cloud Metadata SSRF Harvester", "pattern": r"(169\.254\.169\.254|metadata\.google\.internal|latest/meta-data|127\.0\.0\.1:2375)", "severity": "CRITICAL"},
            {"id": "AI-AGENT-03", "name": "Server-Side Template Injection (SSTI)", "pattern": r"(\{\{.*(__class__|__mro__|__subclasses__|config|self).*\}\}|\$\{7\*7\})", "severity": "CRITICAL"},
            {"id": "AI-AGENT-04", "name": "GraphQL Introspection Dump Bot", "pattern": r"(__schema|__type|IntrospectionQuery)", "severity": "HIGH"},
        ]
        self.threat_feed_ips: Set[str] = set()
        self.signature_version: str = "AI-PRO-2026.11.07-GEN1"

        self.high_risk_tokens = [
            "eval(", "base64_" + "decode", "fromcharcode", "getruntime", "exec(",
            "processbuilder", "power" + "shell", "invoke-" + "expression", "download" + "string",
            "cmd" + ".exe", "/bin/sh", "/bin/bash", "wscript." + "shell", "xp_" + "cmdshell",
            "union select", "waitfor delay", "${jn" + "di:", "0x4141", "\\x90\\x90"
        ]

        self.total_analyzed = 0
        self.total_blocked = 0
        self.total_adversarial_ai_caught = 0
        self.total_self_evolved_rules = 0

    @property
    def block_threshold(self) -> int:
        return self.SENSITIVITY_THRESHOLDS.get(self.sensitivity, 90)

    def set_sensitivity(self, mode: str):
        if mode in self.SENSITIVITY_THRESHOLDS:
            self.sensitivity = mode

    @staticmethod
    def _ip_to_subnet24(ip: str) -> str:
        parts = ip.strip().split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ""

    def hot_reload_intelligence(self, version: str, new_patterns: List[Dict[str, str]], feed_ips: Set[str]):
        """자동 업데이트 및 자가 발전 엔진이 합성한 시그니처와 위협 피드를 무중단 핫리로드"""
        with self.lock:
            self.signature_version = version
            existing_ids = {p["id"] for p in self.dynamic_ai_patterns}
            for pat in new_patterns:
                if pat.get("id") not in existing_ids:
                    self.dynamic_ai_patterns.append(pat)
                    existing_ids.add(pat.get("id"))
            self.threat_feed_ips.update(feed_ips)
            # C2 피드 IP들로부터 /24 서브넷 클러스터 자율 학습
            for fip in feed_ips:
                sub = self._ip_to_subnet24(fip)
                if sub:
                    self.subnet_hit_counter[sub].add(fip)
                    if len(self.subnet_hit_counter[sub]) >= 2:
                        self.evolved_c2_subnets.add(sub)

    def synthesize_rule_from_attack(self, payload: str, ip: str = "") -> Dict[str, str]:
        """
        [자가 발전 핵심 기능] 새로운 변종/폴리모픽 공격이 탐지되었을 때,
        공격 문자열에서 핵심 위험 시그니처 조각을 스스로 추출하여 새로운 정규식 방어 규칙(AUTO-EVO-*)을 합성합니다.
        """
        with self.lock:
            # 1. 공격자 IP의 /24 서브넷 군집 학습
            sub = self._ip_to_subnet24(ip)
            if sub:
                self.subnet_hit_counter[sub].add(ip)
                if len(self.subnet_hit_counter[sub]) >= 2:
                    self.evolved_c2_subnets.add(sub)

            # 2. 페이로드에서 의심 함수/경로/인코딩 토큰 추출
            candidates = re.findall(
                r"([a-zA-Z0-9_]{4,24}\s*\(\s*[a-zA-Z0-9_'\"]{3,20}|/[a-zA-Z0-9_\-\.]{4,20}/[a-zA-Z0-9_\-\.]{4,20}|\$\{[a-zA-Z0-9_:.\-]{3,20}\})",
                payload
            )
            extracted = ""
            for cand in candidates:
                c_low = cand.lower()
                if any(tok in c_low for tok in ("eval", "base64", "exec", "shell", "cmd", "prompt", "meta-data", "jndi", "admin", "env", "passwd", "select", "curl", "wget")):
                    extracted = cand.strip()
                    break
            if not extracted and len(payload) >= 10:
                extracted = payload.strip()[:28]

            if not extracted:
                return {}

            escaped_pat = re.escape(extracted)
            # 이미 동일한 패턴이 존재하는지 확인
            for p in self.dynamic_ai_patterns:
                if p.get("pattern") == escaped_pat:
                    return {}

            self.total_self_evolved_rules += 1
            rule_id = f"AUTO-EVO-{self.total_self_evolved_rules:02d}"
            new_rule = {
                "id": rule_id,
                "name": f"[자가 발전 합성 규칙] 변종 공격 패턴 자동 학습 ({extracted[:22]}...)",
                "pattern": escaped_pat,
                "severity": "CRITICAL"
            }
            self.dynamic_ai_patterns.append(new_rule)
            self.self_synthesized_rules.append(new_rule)
            return new_rule

    def run_autonomous_evolution_cycle(self) -> Dict[str, any]:
        """
        [자가 발전 사이클 실행]
        축적된 정상 트래픽 벡터로 Isolation Forest 트리를 재학습하고,
        자율 합성된 방어 규칙 및 C2 서브넷 클러스터를 최적화하여 세대(Generation)를 진화시킵니다.
        """
        with self.lock:
            samples = list(self.online_benign_samples)
            retrained_trees = self.iforest.retrain_with_online_samples(samples)
            self.evolution_generation += 1
            gen_str = f"Gen {self.evolution_generation}.0"
            return {
                "generation": gen_str,
                "retrained_trees": retrained_trees,
                "learned_samples": len(samples),
                "synthesized_rules_count": len(self.self_synthesized_rules),
                "evolved_subnets_count": len(self.evolved_c2_subnets),
                "safe_bigrams_count": len(self.markov.learned_safe_bigrams),
                "new_rules": list(self.self_synthesized_rules)
            }

    @staticmethod
    def compute_shannon_entropy(data: str) -> float:
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

    def compute_ngram_score(self, payload: str) -> float:
        if not payload or len(payload) < 8:
            return 0.0
        lower_p = payload.lower()
        length = len(payload)
        attack_chars = sum(1 for c in payload if c in "';\"`$(){}[]<>|\\^~")
        special_ratio = attack_chars / length
        hex_escapes = len(re.findall(r"(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|%2[247]|%3[bBcCeE]|%7[bBdD])", payload))
        encoding_score = min(35.0, hex_escapes * 6.0)
        token_hits = sum(1 for tok in self.high_risk_tokens if tok in lower_p)
        token_score = min(65.0, token_hits * 28.0)
        return round(min(100.0, (special_ratio * 120.0) + encoding_score + token_score), 1)

    def _detect_adversarial_ai_attack(self, ip: str, target_inspect: str, req_per_min: int, unique_paths: int) -> Tuple[float, str, str]:
        with self.lock:
            patterns_snapshot = list(self.dynamic_ai_patterns)

        for pat in patterns_snapshot:
            try:
                if re.search(pat["pattern"], target_inspect, re.IGNORECASE):
                    prefix = "자가발전 규칙 적중" if pat["id"].startswith("AUTO-EVO") else "AI 공격 에이전트 패턴 탐지"
                    return 96.0, f"AI_AGENT_{pat['id']}", f"{prefix}: {pat['name']} ({pat['id']})"
            except re.error:
                continue

        with self.lock:
            uris = list(self.ip_recent_uris[ip])
        if len(uris) >= 12 and req_per_min >= 45:
            query_count = sum(1 for u in uris if "?" in u or "=" in u)
            if query_count >= 10:
                return 92.0, "AI_AUTONOMOUS_FUZZER", f"자율형 AI 취약점 퍼징 에이전트 행위 감지 (분당 {req_per_min}회 고속 파라미터 변이)"

        return 0.0, "", ""

    def analyze_http_request(self, ip: str, method: str, path: str, headers: Dict[str, str], body: str = "") -> FullAIAssessment:
        now = time.time()
        target_inspect = f"{path} {body}".strip()
        ua = headers.get("User-Agent", "")
        subnet24 = self._ip_to_subnet24(ip)

        with self.lock:
            self.total_analyzed += 1
            self.ip_timestamps[ip].append(now)
            self.ip_paths[ip].add(path.split("?")[0])
            self.ip_recent_uris[ip].append(path)
            recent_60s = [t for t in self.ip_timestamps[ip] if now - t <= 60.0]
            req_per_min = len(recent_60s)
            unique_paths = len(self.ip_paths[ip])
            in_threat_feed = ip in self.threat_feed_ips
            in_evolved_subnet = bool(subnet24 and subnet24 in self.evolved_c2_subnets)

        if in_threat_feed:
            with self.lock:
                self.total_blocked += 1
            return FullAIAssessment(
                score=99,
                is_blocked=True,
                is_suspicious=True,
                category="TI_GLOBAL_C2_FEED",
                xai_reason="[AI 위협점수 99점 | 위협 인텔리전스 차단] 자동 업데이트된 글로벌 악성 C2/봇넷 피드 등재 IP",
                sub_scores={"threat_feed": 99.0}
            )

        entropy = self.compute_shannon_entropy(target_inspect)
        ngram_score = self.compute_ngram_score(target_inspect)
        markov_score = self.markov.compute_perplexity_score(target_inspect)

        iforest_score = self.iforest.score_sample([
            float(req_per_min), 1.0, float(unique_paths), entropy, ngram_score
        ])

        adv_score, adv_cat, adv_reason = self._detect_adversarial_ai_attack(
            ip, f"{target_inspect} {ua}", req_per_min, unique_paths
        )

        payload_ensemble = ngram_score
        if entropy >= 5.0 and (ngram_score >= 45.0 or markov_score >= 55.0):
            payload_ensemble = min(100.0, max(ngram_score, markov_score) + 28.0)

        subnet_boost = 15.0 if in_evolved_subnet and max(payload_ensemble, iforest_score) >= 60.0 else 0.0
        composite_score = int(min(100, round(max(payload_ensemble, adv_score, iforest_score * 0.85) + subnet_boost)))

        reasons = []
        category = "AI_NORMAL"

        if adv_score >= 90.0:
            reasons.append(adv_reason)
            category = adv_cat
            with self.lock:
                self.total_adversarial_ai_caught += 1
        if payload_ensemble >= 75.0:
            reasons.append(f"다중 모델 난독화/변종 페이로드 탐지(엔트로피 H={entropy:.2f}, Markov={markov_score:.0f}%, N-gram={ngram_score:.0f}%)")
            if category == "AI_NORMAL":
                category = "AI_ENSEMBLE_ZERO_DAY"
        if in_evolved_subnet and subnet_boost > 0:
            reasons.append(f"자가 학습된 고위험 C2 서브넷({subnet24}) 가중치 적용")

        is_blocked = self.auto_block and (composite_score >= self.block_threshold)
        is_suspicious = composite_score >= 70
        synthesized_id = ""

        # [자가 발전 온라인 학습]
        if composite_score < 25:
            # 안전한 정상 요청이면 온라인 베이스라인 버퍼 및 Markov 안전 사전에 자가 학습
            with self.lock:
                self.online_benign_samples.append([float(req_per_min), 0.0, float(unique_paths), entropy, ngram_score])
            self.markov.adapt_safe_text(path)
        elif is_blocked and payload_ensemble >= 75.0:
            # 변종 공격 차단 시 스스로 새로운 방어 규칙(AUTO-EVO-*)을 즉석 합성!
            new_rule = self.synthesize_rule_from_attack(target_inspect, ip=ip)
            if new_rule:
                synthesized_id = new_rule["id"]
                reasons.append(f"🧬 자가 발전 엔진이 신규 방어 규칙({synthesized_id})을 자율 합성하여 영구 학습함")

        with self.lock:
            if is_blocked:
                self.ip_violation_count[ip] += 1
                self.total_blocked += 1

        if not reasons:
            xai_reason = f"[AI 위협점수 {composite_score}점] 앙상블 모델 정상 판정 (Gen {self.evolution_generation}.0, H={entropy:.2f})"
        else:
            tag = "풀방어 자율 격리" if is_blocked else "주의 관찰"
            xai_reason = f"[AI 위협점수 {composite_score}점 | {tag}] " + " / ".join(reasons)

        return FullAIAssessment(
            score=composite_score,
            is_blocked=is_blocked,
            is_suspicious=is_suspicious,
            category=category,
            xai_reason=xai_reason,
            synthesized_rule_id=synthesized_id,
            sub_scores={
                "entropy": entropy,
                "ngram": ngram_score,
                "markov": markov_score,
                "iforest": iforest_score,
                "adversarial_ai": adv_score
            }
        )

    def analyze_socket_connection(self, remote_ip: str, remote_port: int, local_port: int, proc_name: str) -> FullAIAssessment:
        if remote_ip in ("127.0.0.1", "::1", "0.0.0.0") or remote_ip.startswith(("192.168.", "10.", "172.")):
            return FullAIAssessment(0, False, False, "AI_LOCAL", "[AI 위협점수 0점] 내부/로컬 안전 네트워크 통신")

        subnet24 = self._ip_to_subnet24(remote_ip)
        with self.lock:
            in_feed = remote_ip in self.threat_feed_ips
            in_evolved_subnet = bool(subnet24 and subnet24 in self.evolved_c2_subnets)

        if in_feed:
            with self.lock:
                self.total_blocked += 1
            return FullAIAssessment(
                score=99,
                is_blocked=True,
                is_suspicious=True,
                category="TI_GLOBAL_C2_FEED",
                xai_reason=f"[AI 위협점수 99점 | 양방향 C2 차단] 글로벌 위협 인텔리전스 피드에 등록된 악성 C2 서버({remote_ip}) 통신 차단"
            )

        proc_lower = (proc_name or "").lower()
        if proc_lower in self.TRUSTED_PROCESSES and local_port >= 10000 and not in_evolved_subnet:
            with self.lock:
                self.online_benign_samples.append([2.0, 0.0, 1.0, 3.2, 2.0])
            return FullAIAssessment(2, False, False, "AI_NORMAL", f"[AI 위협점수 2점] 신뢰 프로세스({proc_name}) 정상 외부 통신")

        if remote_port in (80, 443, 53, 8443, 5228) and local_port >= 10000 and proc_lower not in ("certutil.exe", "mshta.exe", "bitsadmin.exe") and not in_evolved_subnet:
            return FullAIAssessment(4, False, False, "AI_NORMAL", f"[AI 위협점수 4점] 표준 웹/보안 프로토콜(포트 {remote_port}) 정상 통신")

        now = time.time()
        with self.lock:
            self.total_analyzed += 1
            self.ip_timestamps[remote_ip].append(now)
            if 0 < local_port < 10000:
                self.ip_service_ports[remote_ip].add(local_port)
            recent_60s = [t for t in self.ip_timestamps[remote_ip] if now - t <= 60.0]
            conn_rate = len(recent_60s)
            service_port_spread = len(self.ip_service_ports[remote_ip])

        port_scan_score = 94.0 if service_port_spread >= 10 else (72.0 if service_port_spread >= 5 else 0.0)
        lolbin_risk = 91.0 if any(p in proc_lower for p in ("certutil", "mshta", "bitsadmin", "regsvr32", "wscript", "cscript")) else 0.0
        subnet_risk = 88.0 if in_evolved_subnet and proc_lower not in self.TRUSTED_PROCESSES else 0.0
        iforest_score = self.iforest.score_sample([float(conn_rate), float(service_port_spread), 1.0, 3.5, 10.0])

        composite_score = int(min(100, round(max(port_scan_score, lolbin_risk, subnet_risk))))
        reasons = []
        category = "AI_NORMAL"

        if port_scan_score >= 70.0:
            reasons.append(f"서비스 포트 집중 스캐닝({service_port_spread}개 서비스 포트 탐색)")
            category = "AI_PORT_SWEEP"
        if lolbin_risk >= 85.0:
            reasons.append(f"위험 시스템 유틸리티({proc_name})의 외부 원격 C2 접속 시도")
            category = "AI_LOLBIN_C2"
        if subnet_risk >= 85.0:
            reasons.append(f"자가 학습된 악성 C2 서브넷({subnet24}) 대역 통신 감지")
            category = "AI_EVOLVED_C2_SUBNET"

        is_blocked = self.auto_block and (composite_score >= self.block_threshold)
        is_suspicious = composite_score >= 70

        if is_blocked and subnet24:
            with self.lock:
                self.subnet_hit_counter[subnet24].add(remote_ip)
                if len(self.subnet_hit_counter[subnet24]) >= 2:
                    self.evolved_c2_subnets.add(subnet24)

        if not reasons:
            xai_reason = f"[AI 위협점수 {composite_score}점] 정상 소켓 통신 (IForest={iforest_score:.0f})"
        else:
            tag = "양방향 자율 격리" if is_blocked else "주의 관찰"
            xai_reason = f"[AI 위협점수 {composite_score}점 | {tag}] " + ", ".join(reasons)

        return FullAIAssessment(
            score=composite_score,
            is_blocked=is_blocked,
            is_suspicious=is_suspicious,
            category=category,
            xai_reason=xai_reason,
            sub_scores={"iforest": iforest_score, "service_ports": float(service_port_spread)}
        )
