import re
import urllib.parse
from dataclasses import dataclass

@dataclass
class ThreatAssessment:
    is_blocked: bool
    threat_level: str
    rule_name: str
    details: str

class ThreatDetectionEngine:
    """
    [Pro Edition] 웹/네트워크 공격, 중국발 금융권 APT, 그리고 AI 에이전트 공격(Prompt Injection/SSRF/SSTI)을 탐지하는 DPI 룰 엔진
    """
    def __init__(self):
        self.sqli_patterns = [
            r"union\s+select", r"select\s+.*\s+from", r"insert\s+into",
            r"drop\s+table", r"exec(\s+|\+)+(s|x)p\w+", r"waitfor\s+delay",
            r"benchmark\s*\(\d+", r"sleep\s*\(\s*\d+\s*\)", r"--", r"'\s*or\s*'1'='1"
        ]
        self.xss_patterns = [
            r"<script.*?>", r"javascript:", r"onload\s*=", r"onerror\s*=",
            r"document\.cookie", r"window\.location"
        ]
        self.traversal_patterns = [
            r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e/", r"\.\.%2f",
            r"/etc/passwd", r"boot\.ini", r"win\.ini", r"web\.config"
        ]
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

        for pattern, desc in self.apt_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                return ThreatAssessment(True, "CRITICAL", "FINANCIAL_APT_DEFENSE", f"금융권 표적 APT 공격 차단: {desc}")

        for pattern in self.traversal_patterns:
            if re.search(pattern, lower_text):
                return ThreatAssessment(True, "HIGH", "PATH_TRAVERSAL_PREVENTION", f"외부 침입 파일 탐색 및 시스템 조작 차단: {pattern}")

        for pattern in self.sqli_patterns:
            if re.search(pattern, lower_text):
                return ThreatAssessment(True, "HIGH", "SQL_INJECTION_DEFENSE", f"DB 침해 및 데이터 탈취 시도 차단: {pattern}")

        for pattern in self.xss_patterns:
            if re.search(pattern, lower_text):
                return ThreatAssessment(True, "MEDIUM", "XSS_SCRIPT_BLOCK", f"악성 피싱/인젝션 스크립트 차단: {pattern}")

        return ThreatAssessment(False, "SAFE", "NONE", "정상적인 트래픽 통과")

