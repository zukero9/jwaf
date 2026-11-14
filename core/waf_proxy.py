import threading
import time
import html as html_lib
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from core.rules import ThreatDetectionEngine

MAX_WAF_BODY_BYTES = 1024 * 1024  # 1 MB 최대 페이로드 제한 (메모리 고갈 DoS 공격 방어)


class LocalWAFProxy:
    """
    [JWAF Pro Edition - 시큐어 코딩 적용] 풀스펙 앙상블 AI + 딥패킷 인라인 WAF 프록시
    - Reflected XSS 방지(html.escape), 대용량 Body DoS 차단(1MB 제한), Open Proxy/SSRF 경로 검증 적용
    """
    def __init__(self, listen_port: int, target_port: int, config, geoip, ai_engine, log_callback):
        self.listen_port = listen_port
        self.target_port = target_port
        self.config = config
        self.geoip = geoip
        self.ai_engine = ai_engine
        self.log_callback = log_callback
        self.threat_engine = ThreatDetectionEngine()
        self.httpd = None
        self.server_thread = None
        self.is_running = False

    def start(self):
        if self.is_running:
            return
        waf_instance = self

        class WAFHandler(BaseHTTPRequestHandler):
            timeout = 5.0  # Slowloris 연결 지연 DoS 방어

            def log_message(self, format, *args):
                pass

            def do_GET(self):
                self._handle_request("GET")

            def do_POST(self):
                self._handle_request("POST")

            def do_PUT(self):
                self._handle_request("PUT")

            def do_DELETE(self):
                self._handle_request("DELETE")

            def _handle_request(self, method):
                client_ip = self.client_address[0]
                country = waf_instance.geoip.get_country(client_ip)

                if not waf_instance.config.is_active:
                    self._forward(method)
                    return

                if client_ip in waf_instance.config.white_ips:
                    waf_instance._log_event(client_ip, country, method, self.path, "ALLOWED", "WHITE_LIST", "화이트리스트 통과", "SAFE", 0)
                    self._forward(method)
                    return

                if client_ip in waf_instance.config.black_ips:
                    waf_instance._log_event(client_ip, country, method, self.path, "BLOCKED", "BLACK_LIST", "차단된 블랙리스트 IP 접근", "CRITICAL", 100)
                    self._block_response("Blocked by JWAF Jinkero Shield Pro: Blacklisted IP")
                    return

                # [글로벌 실시간 집단지성(Swarm Intelligence) C2 IP 차단 연동]
                from core.swarm_threat_intel import SWARM_INTEL
                if SWARM_INTEL.is_swarm_c2_threat(client_ip):
                    waf_instance._log_event(client_ip, country, method, self.path, "BLOCKED", "SWARM_C2_FEED", "글로벌 집단지성 클라우드 C2 위협 IP 차단", "CRITICAL", 99)
                    self._block_response("Blocked by JWAF Global Swarm Intelligence: Malicious C2 Node")
                    return

                if country in waf_instance.config.blocked_countries:
                    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
                    waf_instance._log_event(client_ip, country, method, self.path, "BLOCKED", "GEO_BLOCK", f"국가 차단 정책 적용: {country}", "HIGH", 95)
                    if client_ip not in ("127.0.0.1", "::1"):
                        waf_instance.config.record_geo_block(client_ip, country, now_str, f"WAF 국가({country}) 차단")
                        from core.firewall_manager import sync_inbound_block_rule
                        sync_inbound_block_rule(waf_instance.config.black_ips, waf_instance.config.outbound_c2_block_enabled)
                    self._block_response(f"Access Denied: Country [{country}] is blocked by JWAF Policy.")
                    return

                try:
                    content_length = int(self.headers.get('Content-Length', 0))
                except ValueError:
                    content_length = 0

                if content_length > MAX_WAF_BODY_BYTES:
                    waf_instance._log_event(
                        client_ip, country, method, self.path, "BLOCKED", "WAF_PAYLOAD_OVERFLOW_DOS",
                        f"비정상 대용량 페이로드 DoS 차단 ({content_length} bytes)", "CRITICAL", 98
                    )
                    self._block_response("Payload Too Large: Blocked by JWAF DoS Protection")
                    return

                body = ""
                if content_length > 0:
                    try:
                        body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
                    except Exception:
                        pass

                headers_dict = {k: v for k, v in self.headers.items()}
                assessment = waf_instance.threat_engine.inspect_request(method, self.path, headers_dict, body)

                if assessment.is_blocked:
                    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
                    waf_instance._log_event(
                        client_ip, country, method, self.path, "BLOCKED", assessment.rule_name,
                        f"[시그니처 차단] {assessment.details}", assessment.threat_level, 98
                    )
                    if client_ip not in ("127.0.0.1", "::1"):
                        waf_instance.config.record_threat_block(client_ip, country, now_str, assessment.rule_name, assessment.details)
                        from core.firewall_manager import sync_inbound_block_rule
                        sync_inbound_block_rule(waf_instance.config.black_ips, waf_instance.config.outbound_c2_block_enabled)
                    self._block_response(f"Security Alert: Request Terminated by JWAF Pro [{assessment.rule_name}]\n{assessment.details}")
                    return

                ai_score = 0
                if waf_instance.config.ai_enabled and waf_instance.ai_engine:
                    ai_eval = waf_instance.ai_engine.analyze_http_request(client_ip, method, self.path, headers_dict, body)
                    ai_score = ai_eval.score
                    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

                    if ai_eval.is_blocked:
                        waf_instance.config.record_ai_anomaly(
                            client_ip, country, now_str, ai_eval.score, ai_eval.category, ai_eval.xai_reason, True
                        )
                        waf_instance.config.record_threat_block(
                            client_ip, country, now_str, ai_eval.category, ai_eval.xai_reason
                        )
                        if client_ip not in ("127.0.0.1", "::1"):
                            from core.firewall_manager import sync_inbound_block_rule
                            sync_inbound_block_rule(waf_instance.config.black_ips, waf_instance.config.outbound_c2_block_enabled)

                        waf_instance._log_event(
                            client_ip, country, method, self.path, "BLOCKED_AI", ai_eval.category,
                            ai_eval.xai_reason, "CRITICAL", ai_eval.score
                        )
                        # 글로벌 집단지성 허브에 로컬 차단 이벤트 브로드캐스트
                        SWARM_INTEL.broadcast_local_threat(client_ip, ai_eval.synthesized_rule_id or ai_eval.category, ai_eval.xai_reason)
                        self._block_response(f"Full AI Defense Triggered [{ai_eval.category}]\n{ai_eval.xai_reason}")
                        return
                    elif ai_eval.is_suspicious:
                        waf_instance.config.record_ai_anomaly(
                            client_ip, country, now_str, ai_eval.score, ai_eval.category, ai_eval.xai_reason, False
                        )
                        waf_instance._log_event(
                            client_ip, country, method, self.path, "ALERT_AI", ai_eval.category,
                            ai_eval.xai_reason, "MEDIUM", ai_eval.score
                        )
                        self._forward(method, body)
                        return

                waf_instance._log_event(client_ip, country, method, self.path, "ALLOWED", "INSPECT_PASSED", f"정상 요청 승인 (AI 위협점수: {ai_score}점)", "SAFE", ai_score)
                self._forward(method, body)

            def _block_response(self, reason: str):
                safe_reason = html_lib.escape(str(reason))
                self.send_response(403)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('X-Frame-Options', 'DENY')
                self.send_header('X-Protected-By', 'JWAF-Jinkero-Shield-Pro-AI')
                self.end_headers()
                html_doc = f"""<!DOCTYPE html>
<html>
<head><title>403 Access Denied - JWAF Jinkero Shield Pro AI</title></head>
<body style="font-family:'Segoe UI',sans-serif;background:#0F172A;color:#F8FAFC;text-align:center;padding:50px;">
    <div style="max-width:620px;margin:0 auto;background:#1E293B;border:1px solid #EF4444;border-radius:14px;padding:30px;">
        <h2 style="color:#EF4444;">⚠️ 침해 공격 시도 차단됨 (JWAF Jinkero Shield Pro AI)</h2>
        <pre style="background:#0F172A;padding:15px;border-radius:8px;text-align:left;color:#FCA5A5;overflow-x:auto;">{safe_reason}</pre>
    </div>
</body>
</html>"""
                self.wfile.write(html_doc.encode('utf-8'))

            def _forward(self, method, body=""):
                # Open Proxy / SSRF 방지를 위해 경로 정규화 검증
                raw_path = str(self.path or "/")
                if not raw_path.startswith("/") or raw_path.startswith("//") or "://" in raw_path.split("?")[0]:
                    self._block_response("Invalid URI Path: Blocked by JWAF SSRF/Open-Proxy Guard")
                    return

                target_url = f"http://127.0.0.1:{waf_instance.target_port}{raw_path}"
                try:
                    req = urllib.request.Request(target_url, data=body.encode('utf-8') if body else None, method=method)
                    for k, v in self.headers.items():
                        if k.lower() not in ('host', 'content-length', 'connection', 'transfer-encoding'):
                            req.add_header(k, v)
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        self.send_response(resp.status)
                        for k, v in resp.getheaders():
                            self.send_header(k, v)
                        self.end_headers()
                        self.wfile.write(resp.read(MAX_WAF_BODY_BYTES * 4))
                except Exception as e:
                    self.send_response(502)
                    self.send_header('Content-Type', 'text/plain; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(f"JWAF Gateway Error (Target Port {waf_instance.target_port} unreachable): {e}".encode('utf-8'))

        try:
            self.httpd = HTTPServer(('0.0.0.0', self.listen_port), WAFHandler)
            self.is_running = True
            self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self.server_thread.start()
        except Exception:
            self.is_running = False

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.is_running = False

    def _log_event(self, ip, country, method, path, action, rule, details, threat_level="SAFE", ai_score=0):
        if self.log_callback:
            self.log_callback({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "country": country,
                "method": method,
                "path": path,
                "action": action,
                "rule": rule,
                "threat_level": threat_level,
                "ai_score": ai_score,
                "details": details
            })
