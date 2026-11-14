import os
import sys
import ssl
import time
import datetime
import threading
from typing import Tuple, Dict

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

CERT_DIR = os.path.join(os.path.dirname(__file__), "certs")
CA_KEY_FILE = os.path.join(CERT_DIR, "jwaf_root_ca.key")
CA_CERT_FILE = os.path.join(CERT_DIR, "jwaf_root_ca.crt")


class TlsInspectionEngine:
    """
    [JWAF Pro Edition] TLS/SSL 심층 복호화 검사 (Deep Packet SSL Inspection) 엔진
    - 동적 로컬 루트 CA 발급 및 실시간 호스트별 가상 인증서 On-the-Fly 생성
    - HTTPS 암호화 세션(TLS 1.2 / TLS 1.3)을 복호화하여 패킷 내부의 악성코드,
      웹셸, AI 프롬프트 인젝션 및 난독화 페이로드를 인라인으로 검사
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.ca_key = None
        self.ca_cert = None
        self.cert_cache: Dict[str, Tuple[str, str]] = {}
        self.total_decrypted_sessions = 0
        self.total_tls_threats_blocked = 0
        self._ensure_root_ca()

    def _ensure_root_ca(self):
        """로컬 루트 CA 개인키 및 인증서 자동 생성 및 로드"""
        os.makedirs(CERT_DIR, exist_ok=True)
        if os.path.exists(CA_KEY_FILE) and os.path.exists(CA_CERT_FILE):
            try:
                with open(CA_KEY_FILE, "rb") as f:
                    self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
                with open(CA_CERT_FILE, "rb") as f:
                    self.ca_cert = x509.load_pem_x509_certificate(f.read())
                return
            except Exception:
                pass

        # 신규 2048-bit RSA 루트 CA 생성
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Seoul"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "JWAF Jinkero Security Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, "JWAF Pro SSL Deep Inspection CA"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.ca_key, hashes.SHA256())
        )

        with open(CA_KEY_FILE, "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(CA_CERT_FILE, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def get_or_create_host_cert(self, hostname: str) -> Tuple[str, str]:
        """지정된 도메인/IP에 대한 가상 SSL 인증서를 루트 CA로 즉석 서명하여 반환"""
        clean_host = hostname.split(":")[0].strip().lower()
        if not clean_host:
            clean_host = "localhost"

        with self.lock:
            if clean_host in self.cert_cache:
                cert_file, key_file = self.cert_cache[clean_host]
                if os.path.exists(cert_file) and os.path.exists(key_file):
                    return cert_file, key_file

            host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "JWAF Dynamic Proxy"),
                x509.NameAttribute(NameOID.COMMON_NAME, clean_host),
            ])
            now = datetime.datetime.now(datetime.timezone.utc)
            alt_names = [x509.DNSName(clean_host)]
            if clean_host not in ("localhost", "127.0.0.1"):
                alt_names.append(x509.DNSName("localhost"))

            host_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(self.ca_cert.subject)
                .public_key(host_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
                .sign(self.ca_key, hashes.SHA256())
            )

            cert_path = os.path.join(CERT_DIR, f"host_{clean_host}.crt")
            key_path = os.path.join(CERT_DIR, f"host_{clean_host}.key")

            with open(cert_path, "wb") as f:
                f.write(host_cert.public_bytes(serialization.Encoding.PEM))
            with open(key_path, "wb") as f:
                f.write(host_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            self.cert_cache[clean_host] = (cert_path, key_path)
            return cert_path, key_path

    def create_server_ssl_context(self, hostname: str = "localhost") -> ssl.SSLContext:
        """복호화 인라인 검사를 위한 TLS Server SSLContext 생성"""
        cert_path, key_path = self.get_or_create_host_cert(hostname)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        return ctx

    def inspect_decrypted_payload(self, client_ip: str, url: str, headers: dict, body: str, ai_engine) -> dict:
        """
        [복호화 딥패킷 AI 검사]
        HTTPS 통신 복호화 후 내부 평문 바디 및 헤더를 AI 다중 앙상블 엔진으로 정밀 검사
        """
        with self.lock:
            self.total_decrypted_sessions += 1

        assessment = ai_engine.analyze_http_request(
            ip=client_ip,
            method=headers.get("Method", "POST"),
            path=url,
            headers=headers,
            body=body
        )

        if assessment.is_blocked:
            with self.lock:
                self.total_tls_threats_blocked += 1

        return {
            "is_blocked": assessment.is_blocked,
            "threat_score": assessment.score,
            "category": assessment.category,
            "xai_reason": assessment.xai_reason,
            "synthesized_rule_id": assessment.synthesized_rule_id
        }

# 전역 TLS 심층 복호화 엔진 인스턴스
TLS_INSPECTOR = TlsInspectionEngine()
