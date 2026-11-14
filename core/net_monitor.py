import psutil
import threading
import time
from typing import Callable, Dict, Set
from collections import defaultdict

class NetworkConnectionMonitor:
    """
    내 컴퓨터의 전체 네트워크 연결 및 프로세스별 트래픽 순위,
    실시간 RX/TX 전송량 및 AI 기반 확실한 이상 징후를 추적하는 모니터
    """
    def __init__(self, config, geoip, ai_engine, log_callback: Callable, traffic_callback: Callable = None):
        self.config = config
        self.geoip = geoip
        self.ai_engine = ai_engine
        self.log_callback = log_callback
        self.traffic_callback = traffic_callback
        self.is_running = False
        self.thread = None
        self.seen_connections: Set[str] = set()

        # 프로세스별 패킷/연결 누적 집계 (트래픽 순위용)
        self.process_connection_counts = defaultdict(int)
        self.last_net_io = None
        self.last_time = time.time()

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self.last_net_io = psutil.net_io_counters()
        self.last_time = time.time()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.is_running = False

    def get_top_processes(self, limit=10):
        """연결 활성도가 가장 높은 상위 프로세스 순위 반환"""
        sorted_procs = sorted(self.process_connection_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_procs[:limit]

    def _monitor_loop(self):
        while self.is_running:
            try:
                # 1. 실시간 시스템 전체 RX / TX 속도 계산
                now = time.time()
                dt = now - self.last_time
                if dt >= 0.8:
                    cur_net_io = psutil.net_io_counters()
                    if self.last_net_io:
                        bytes_recv = cur_net_io.bytes_recv - self.last_net_io.bytes_recv
                        bytes_sent = cur_net_io.bytes_sent - self.last_net_io.bytes_sent
                        rx_kbs = max(0.0, (bytes_recv / 1024.0) / dt)
                        tx_kbs = max(0.0, (bytes_sent / 1024.0) / dt)
                        
                        if self.traffic_callback:
                            self.traffic_callback(rx_kbs, tx_kbs)

                    self.last_net_io = cur_net_io
                    self.last_time = now

                # 2. 소켓 연결 및 프로세스 감시
                connections = psutil.net_connections(kind='inet')
                current_keys = set()

                for conn in connections:
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        local_port = conn.laddr.port if conn.laddr else 0
                        status = conn.status

                        conn_id = f"{remote_ip}:{remote_port}->{local_port}:{conn.status}"
                        current_keys.add(conn_id)

                        if conn_id not in self.seen_connections:
                            self.seen_connections.add(conn_id)
                            self._analyze_connection(remote_ip, remote_port, local_port, conn.pid, status)

                if len(self.seen_connections) > 2000:
                    self.seen_connections = current_keys

            except Exception:
                pass
            time.sleep(1.0)

    def _analyze_connection(self, remote_ip: str, remote_port: int, local_port: int, pid: int, status: str):
        if not self.config.is_active:
            return

        country = self.geoip.get_country(remote_ip)
        
        proc_name = "Unknown"
        proc_exe = ""
        if pid:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                try:
                    proc_exe = proc.exe()
                except Exception:
                    proc_exe = proc_name
                self.process_connection_counts[proc_name] += 1
            except Exception:
                pass

        action = "CONNECTED"
        threat_level = "LOW"
        details = f"프로세스: {proc_name} (PID: {pid}) | 로컬포트: {local_port} ↔ 원격: {remote_ip}:{remote_port} ({status})"
        rule_name = "NET_MONITOR"
        ai_score = 0

        # 0. 화이트리스트 IP는 항상 안전 통과
        if remote_ip in self.config.white_ips:
            if self.log_callback:
                self.log_callback({
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": remote_ip,
                    "country": country,
                    "method": f"PORT:{local_port}",
                    "path": f"{proc_name} [{status}]",
                    "action": "ALLOWED",
                    "rule": "WHITE_LIST",
                    "threat_level": "SAFE",
                    "ai_score": 0,
                    "details": f"[신뢰 IP 허용] {details}",
                    "proc_exe": proc_exe,
                    "remote_port": remote_port,
                    "local_port": local_port,
                    "pid": pid
                })
            return

        # 1. AI 자율 방어 행위 분석 (확실한 고위험 위협 90점 이상만 차단)
        if self.config.ai_enabled and self.ai_engine:
            ai_eval = self.ai_engine.analyze_socket_connection(remote_ip, remote_port, local_port, proc_name)
            ai_score = ai_eval.score
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")

            if ai_eval.is_blocked:
                action = "BLOCKED_AI"
                threat_level = "CRITICAL"
                rule_name = ai_eval.category
                details = f"{ai_eval.xai_reason} | 프로세스: {proc_name} (PID: {pid}, 포트: {local_port}↔{remote_port})"
                if remote_ip not in ("127.0.0.1", "::1"):
                    self.config.record_ai_anomaly(remote_ip, country, now_str, ai_eval.score, ai_eval.category, ai_eval.xai_reason, True)
                    self.config.record_threat_block(remote_ip, country, now_str, ai_eval.category, ai_eval.xai_reason)
                    from core.firewall_manager import sync_inbound_block_rule
                    sync_inbound_block_rule(self.config.black_ips)
            elif ai_eval.is_suspicious:
                action = "ALERT_AI"
                threat_level = "MEDIUM"
                rule_name = ai_eval.category
                details = f"{ai_eval.xai_reason} | 프로세스: {proc_name} (PID: {pid}, 포트: {local_port}↔{remote_port})"
                if remote_ip not in ("127.0.0.1", "::1"):
                    self.config.record_ai_anomaly(remote_ip, country, now_str, ai_eval.score, ai_eval.category, ai_eval.xai_reason, False)

        # 2. BlackIP 체크
        if remote_ip in self.config.black_ips and action != "BLOCKED_AI":
            action = "BLOCKED_IP"
            threat_level = "HIGH"
            rule_name = "BLACK_IP_DETECTED"
            ai_score = max(ai_score, 95)
            details = f"[확실한 위협 차단] 등록된 블랙리스트 IP 통신 차단! | 프로세스: {proc_name} (PID: {pid}, 포트: {local_port}↔{remote_port})"

        # 3. 국가별 차단 체크 (GeoIP - 명시적으로 차단 설정된 국가만 차단)
        elif country in self.config.blocked_countries and action != "BLOCKED_AI":
            action = "BLOCKED_GEO"
            threat_level = "HIGH"
            rule_name = "GEO_COUNTRY_BLOCK"
            ai_score = max(ai_score, 90)
            details = f"[국가별 격리 정책] 차단 대상 국가({country}) 통신 격리! | 프로세스: {proc_name} (PID: {pid}, 원격포트: {remote_port})"
            if remote_ip not in ("127.0.0.1", "::1"):
                now_str = time.strftime("%Y-%m-%d %H:%M:%S")
                self.config.record_geo_block(remote_ip, country, now_str, f"차단 국가({country}) 통신 감지 ({proc_name})")
                from core.firewall_manager import sync_inbound_block_rule
                sync_inbound_block_rule(self.config.black_ips)

        # 4. 위험 포트 인입 체크 (외부에서 내 로컬 위험 포트로 접속한 경우)
        if local_port in self.config.blocked_ports and status in ("ESTABLISHED", "SYN_RECV", "CLOSE_WAIT"):
            threat_level = "CRITICAL"
            action = "BLOCKED_PORT"
            rule_name = f"PORT_{local_port}_GUARD"
            ai_score = max(ai_score, 92)
            details = f"[위험 포트 방어] 차단된 로컬 포트({local_port})로의 외부 접근 감지! | 프로세스: {proc_name} (원격: {remote_ip}:{remote_port})"

        if self.log_callback:
            self.log_callback({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ip": remote_ip,
                "country": country,
                "method": f"PORT:{local_port}",
                "path": f"{proc_name} [{status}]",
                "action": action,
                "rule": rule_name,
                "threat_level": threat_level,
                "ai_score": ai_score,
                "details": details,
                "proc_exe": proc_exe,
                "remote_port": remote_port,
                "local_port": local_port,
                "pid": pid
            })
