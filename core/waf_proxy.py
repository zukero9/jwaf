import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.request
from core.rules import ThreatDetectionEngine

class LocalWAFProxy:
    """
    로컬 PC의 웹서버 또는 외부 인입 요청을 가로채서
    SQLi, XSS, Path Traversal, 중국발 금융권 RCE 및 AI 변종 공격 페이로드를 실시간 차단하는 인라인 WAF
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
            def log_message(self, format, *args):
                pass  # 콘솔 기본 로그 억제

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

                # 1. 쉴드 마스터 스위치 체크
                if not waf_instance.config.is_active:
                    self._forward(method)
                    return

                # 2. 화이트리스트 IP 검사 (우선 통과)
                if client_ip in waf_instance.config.white_ips:
                    waf_instance._log_event(client_ip, country, method, self.path, "ALLOWED", "WHITE_LIST", "화이트리스트 통과", "SAFE", 0)
                    self._forward(method)
                    return

                # 3. 블랙리스트 IP 검사
                if client_ip in waf_instance.config.black_ips:
                    waf_instance._log_event(client_ip, country, method, self.path, "BLOCKED", "BLACK_LIST", "차단된 블랙리스트 IP 접근", "CRITICAL", 100)
                    self._block_response("Blocked by Jinkero Shield: Blacklisted IP")
                    return

                # 4. 국가별 차단 검사 (GeoIP)
                if country in waf_instance.config.blocked_countries:
                    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
                    waf_instance._log_event(client_ip, country, method, self.path, "BLOCKED", "GEO_BLOCK", f"국가 차단 정책 적용: {country}", "HIGH", 95)
                    # 자동으로 방화벽 동기화 및 기록
                    if client_ip not in ("127.0.0.1", "::1"):
                        waf_instance.config.record_geo_block(client_ip, country, now_str, f"WAF 국가({country}) 차단")
                        from core.firewall_manager import sync_inbound_block_rule
                        sync_inbound_block_rule(waf_instance.config.black_ips)

                    self._block_response(f"Access Denied: Country [{country}] is blocked by Jinkero Shield Policy.")
                    return

                # 5. 본문 및 헤더 읽기
                content_length = int(self.headers.get('Content-Length', 0))
                body = ""
                if content_length > 0:
                    try:
                        body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
                    except Exception:
                        pass

                # 6. 인라인 WAF 딥 패킷 인스펙션 (금융 공격, 웹셸, RCE 정적 시그니처 검사)
                headers_dict = {k: v for k, v in self.headers.items()}
                assessment = waf_instance.threat_engine.inspect_request(method, self.path, headers_dict, body)

                if assessment.is_blocked:
                    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
                    waf_instance._log_event(
                        client_ip, country, method, self.path, "BLOCKED", assessment.rule_name,
                        f"[시그니처 차단] {assessment.details}", assessment.threat_level, 98
                    )
                    # 지능형 침해 시도 탐지 시 설정 파일에 영구 기록 및 Windows 방화벽 단일 규칙(Jinkero_Block_Ips)에 즉시 누적 동기화
                    if client_ip not in ("127.0.0.1", "::1"):
                        waf_instance.config.record_threat_block(
                            client_ip, country, now_str, assessment.rule_name, assessment.details
                        )
                        from core.firewall_manager import sync_inbound_block_rule
                        sync_inbound_block_rule(waf_instance.config.black_ips)

                    self._block_response(f"Security Alert: Request Terminated by Jinkero WAF [{assessment.rule_name}]\n{assessment.details}")
                    return

                # 7. AI 자율 방어 엔진 분석 (샤넌 엔트로피 + N-gram 난독화 + 슬라이딩 윈도우 스캐닝 탐지)
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
                            sync_inbound_block_rule(waf_instance.config.black_ips)

                        waf_instance._log_event(
                            client_ip, country, method, self.path, "BLOCKED_AI", ai_eval.category,
                            ai_eval.xai_reason, "CRITICAL", ai_eval.score
                        )
                        self._block_response(f"AI Autonomous Defense Triggered [{ai_eval.category}]\n{ai_eval.xai_reason}")
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

                # 정상 요청 통과
                waf_instance._log_event(client_ip, country, method, self.path, "ALLOWED", "INSPECT_PASSED", f"정상 요청 승인 (AI 위협점수: {ai_score}점)", "SAFE", ai_score)
                self._forward(method, body)

            def _block_response(self, reason):
                self.send_response(403)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('X-Protected-By', 'Jinkero-Shield-AI-WAF')
                self.end_headers()
                html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>403 Access Denied - Jinkero Shield</title>
                    <style>
                        body {{ font-family: 'Segoe UI', Roboto, sans-serif; background-color: #121212; color: #E0E0E0; text-align: center; padding: 50px; }}
                        .box {{ max-width: 600px; margin: 0 auto; background: #1E1E1E; border: 1px solid #CF6679; border-radius: 16px; padding: 30px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }}
                        h2 {{ color: #CF6679; margin-top: 0; }}
                        pre {{ background: #2D2D2D; padding: 15px; border-radius: 8px; text-align: left; color: #FFB4AB; font-size: 13px; overflow-x: auto; }}
                        .footer {{ margin-top: 20px; font-size: 12px; color: #888; }}
                    </style>
                </head>
                <body>
                    <div class="box">
                        <h2>⚠️ 침해 공격 시도 차단됨 (Access Denied)</h2>
                        <p>로컬 PC 보안 쉴드(Jinkero Shield AI WAF)에 의해 위협 트래픽이 실시간 격리되었습니다.</p>
                        <pre>{reason}</pre>
                        <div class="footer">Protected by Jinkero Shield Next-Gen AI Firewall</div>
                    </div>
                </body>
                </html>
                """
                self.wfile.write(html.encode('utf-8'))

            def _forward(self, method, body=""):
                target_url = f"http://127.0.0.1:{waf_instance.target_port}{self.path}"
                try:
                    req = urllib.request.Request(target_url, data=body.encode('utf-8') if body else None, method=method)
                    for k, v in self.headers.items():
                        if k.lower() not in ('host', 'content-length'):
                            req.add_header(k, v)
                    
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        self.send_response(resp.status)
                        for k, v in resp.getheaders():
                            self.send_header(k, v)
                        self.end_headers()
                        self.wfile.write(resp.read())
                except Exception as e:
                    self.send_response(502)
                    self.send_header('Content-Type', 'text/plain; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(f"WAF Gateway Error (Target Port {waf_instance.target_port} unreachable): {e}".encode('utf-8'))

        try:
            self.httpd = HTTPServer(('0.0.0.0', self.listen_port), WAFHandler)
            self.is_running = True
            self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self.server_thread.start()
        except Exception as e:
            self.is_running = False
            print(f"[WAF Warning] Port {self.listen_port} bind failed ({e}). WAF will run in network packet inspection mode.")

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
