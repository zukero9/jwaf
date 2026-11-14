import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional, Tuple

@dataclass
class ThreatAssessment:
    is_blocked: bool
    threat_level: str  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    rule_name: str
    details: str

class ThreatDetectionEngine:
    """
    웹/네트워크 공격 및 최근 금융권 타깃 지능형 공격 패턴을 탐지/차단하는 룰 엔진
    - 중국발 금융권 공격 패턴: 웹셸 업로드, 원격 코드 실행(RCE), 역직렬화 취약점, Spring4Shell/Log4j, 
      SQL 인젝션, 경로 조작(Path Traversal), Fastjson RCE, 파밍/피싱 리디렉션
    """
    def __init__(self):
        # 1. SQL Injection 패턴
        self.sqli_patterns = [
            r"union\s+select", r"select\s+.*\s+from", r"insert\s+into",
            r"drop\s+table", r"exec(\s+|\+)+(s|x)p\w+", r"waitfor\s+delay",
            r"benchmark\s*\(\d+", r"sleep\s*\(\s*\d+\s*\)", r"--", r"'\s*or\s*'1'='1"
        ]
        
        # 2. XSS & 프론트엔드 피싱/세션 탈취 패턴
        self.xss_patterns = [
            r"<script.*?>", r"javascript:", r"onload\s*=", r"onerror\s*=",
            r"document\.cookie", r"window\.location"
        ]

        # 3. Directory Traversal & 파일 조작/변조 시도
        self.traversal_patterns = [
            r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e/", r"\.\.%2f",
            r"/etc/passwd", r"boot\.ini", r"win\.ini", r"web\.config"
        ]

        # 4. 중국발 금융/엔터프라이즈 타깃 특화 공격 (Fastjson, Log4j, Spring, WebShell, Deserialization)
        self.apt_patterns = [
            (r"\$\{jndi:(ldap|rmi|dns)", "Log4j Remote Code Execution (CVE-2021-44228)"),
            (r"@type[\"']?\s*:\s*[\"']?[^\"]*(com\.sun\.rowset|org\.apache\.tomcat)", "Fastjson Deserialization RCE"),
            (r"class\.module\.classLoader", "Spring4Shell (CVE-2022-22965)"),
            (r"(cmd\.exe|powershell\.exe|/bin/sh|/bin/bash)\s*(/c|-c)?", "Command Injection via Shell"),
            (r"(certutil|bitsadmin|vssadmin|whoami|nltest|net1?\.exe)\s+", "Suspicious Financial Recon / Living Off The Land"),
            (r"\.(jspx?|php|asp[x]?|ashx|war)(\?|$)", "Malicious WebShell Upload/Execution Attempt"),
            (r"(eval|assert|passthru|shell_exec|system)\s*\(", "Remote Code Execution Primitive"),
            (r"actuator/gateway/routes", "Spring Cloud Gateway RCE Pattern")
        ]

    def inspect_request(self, method: str, path: str, headers: dict, body: str = "") -> ThreatAssessment:
        decoded_path = urllib.parse.unquote(urllib.parse.unquote(path))
        full_text = f"{method} {decoded_path}\n"
        for k, v in headers.items():
            full_text += f"{k}: {v}\n"
        full_text += body

        lower_text = full_text.lower()

        # 1. 특화 APT / 금융 공격 패턴 검사
        for pattern, desc in self.apt_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                return ThreatAssessment(
                    is_blocked=True,
                    threat_level="CRITICAL",
                    rule_name="FINANCIAL_APT_DEFENSE",
                    details=f"금융권 표적 공격 패턴 차단: {desc}"
                )

        # 2. 파일 경로 조작 / 디렉터리 탐색 차단
        for pattern in self.traversal_patterns:
            if re.search(pattern, lower_text):
                return ThreatAssessment(
                    is_blocked=True,
                    threat_level="HIGH",
                    rule_name="PATH_TRAVERSAL_PREVENTION",
                    details=f"외부 침입 파일 탐색 및 시스템 조작 시도 감지: {pattern}"
                )

        # 3. SQL 인젝션 차단
        for pattern in self.sqli_patterns:
            if re.search(pattern, lower_text):
                return ThreatAssessment(
                    is_blocked=True,
                    threat_level="HIGH",
                    rule_name="SQL_INJECTION_DEFENSE",
                    details=f"DB 침해 및 데이터 탈취 시도 탐지: {pattern}"
                )

        # 4. XSS / 악성 스크립트 차단
        for pattern in self.xss_patterns:
            if re.search(pattern, lower_text):
                return ThreatAssessment(
                    is_blocked=True,
                    threat_level="MEDIUM",
                    rule_name="XSS_SCRIPT_BLOCK",
                    details=f"악성 피싱/인젝션 스크립트 탐지: {pattern}"
                )

        return ThreatAssessment(
            is_blocked=False,
            threat_level="SAFE",
            rule_name="NONE",
            details="정상적인 트래픽 통과"
        )

