from PyQt6.QtWidgets import QWidget
from PyQt6.QtCore import Qt, pyqtProperty, QPropertyAnimation, QEasingCurve, QPointF, QTimer, QRectF
from PyQt6.QtGui import QPainter, QColor, QPen, QBrush, QPainterPath, QFont, QLinearGradient
from collections import deque

class MaterialSwitch(QWidget):
    """
    모던 미니멀 스타일의 정교한 슬라이딩 토글 스위치
    """
    def __init__(self, parent=None, checked=True):
        super().__init__(parent)
        self.setFixedSize(48, 24)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._checked = checked
        self._thumb_position = 36.0 if checked else 12.0

        self._anim = QPropertyAnimation(self, b"thumb_position", self)
        self._anim.setDuration(140)
        self._anim.setEasingCurve(QEasingCurve.Type.OutQuad)

    @pyqtProperty(float)
    def thumb_position(self):
        return self._thumb_position

    @thumb_position.setter
    def thumb_position(self, pos):
        self._thumb_position = pos
        self.update()

    def isChecked(self):
        return self._checked

    def setChecked(self, checked):
        if self._checked != checked:
            self._checked = checked
            start = self._thumb_position
            end = 36.0 if checked else 12.0
            self._anim.stop()
            self._anim.setStartValue(start)
            self._anim.setEndValue(end)
            self._anim.start()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.setChecked(not self._checked)
            self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        if self._checked:
            track_color = QColor("#2563EB")
            border_color = QColor("#3B82F6")
            thumb_color = QColor("#FFFFFF")
        else:
            track_color = QColor("#1E293B")
            border_color = QColor("#334155")
            thumb_color = QColor("#94A3B8")

        p.setBrush(track_color)
        p.setPen(border_color)
        p.drawRoundedRect(1, 1, 46, 22, 11, 11)

        p.setBrush(thumb_color)
        p.setPen(Qt.PenStyle.NoPen)
        thumb_radius = 7.0 if self._checked else 6.0
        p.drawEllipse(int(self._thumb_position - thumb_radius), int(12 - thumb_radius), int(thumb_radius * 2), int(thumb_radius * 2))
        p.end()


class MetricKpiCard(QWidget):
    """
    과도한 그라디언트를 배제한 세련되고 깔끔한 Windows 11 Fluent Dark 미니멀 모던 카드
    """
    def __init__(self, title: str, value: str, subtext: str, theme: str = "blue", parent=None):
        super().__init__(parent)
        self.title_text = title
        self.value_text = value
        self.subtext = subtext
        self.theme = theme
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(92)
        self._is_hovered = False

        self.themes = {
            "blue": {
                "accent": QColor("#38BDF8"),
                "badge_bg": QColor(56, 189, 248, 20),
                "hover_border": QColor("#0284C7")
            },
            "red": {
                "accent": QColor("#F87171"),
                "badge_bg": QColor(248, 113, 113, 20),
                "hover_border": QColor("#DC2626")
            },
            "amber": {
                "accent": QColor("#FBBF24"),
                "badge_bg": QColor(251, 191, 36, 20),
                "hover_border": QColor("#D97706")
            },
            "green": {
                "accent": QColor("#34D399"),
                "badge_bg": QColor(52, 211, 153, 20),
                "hover_border": QColor("#059669")
            }
        }

    def set_value(self, val: str):
        self.value_text = val
        self.update()

    def enterEvent(self, event):
        self._is_hovered = True
        self.update()

    def leaveEvent(self, event):
        self._is_hovered = False
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w = self.width()
        h = self.height()

        th = self.themes.get(self.theme, self.themes["blue"])

        bg_color = QColor("#161E2E") if not self._is_hovered else QColor("#1B2538")
        border_color = th["hover_border"] if self._is_hovered else QColor("#283347")

        p.setBrush(bg_color)
        p.setPen(QPen(border_color, 1.2))
        p.drawRoundedRect(1, 1, w - 2, h - 2, 10, 10)

        p.setBrush(th["accent"])
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(5, 12, 3, h - 24, 1.5, 1.5)

        val_font_size = 17 if len(self.value_text) >= 10 else (19 if len(self.value_text) >= 6 else 22)
        p.setFont(QFont("Segoe UI Variable Display", val_font_size, QFont.Weight.Bold))
        p.setPen(th["accent"])
        p.drawText(20, 40, self.value_text)

        p.setFont(QFont("Malgun Gothic", 10, QFont.Weight.Bold))
        p.setPen(QColor("#F1F5F9"))
        p.drawText(20, 65, self.title_text)

        p.setFont(QFont("Segoe UI", 9))
        p.setPen(QColor("#94A3B8"))
        p.drawText(20, 82, self.subtext + "  →")
        p.end()


class LiveTrafficChart(QWidget):
    """
    고시인성(High-Visibility) 네트워크 RX(수신)/TX(송신) 실시간 모니터링 차트
    - 상단 대형 디지털 HUD 배지로 현재 RX/TX 속도 및 최대(Peak) 속도를 선명하게 표시
    - 그래프 우측 끝에 실시간 수치 콜아웃 태그 및 발광 포인트 렌더링
    - 과부하(>= 12MB/s) 발생 시 긴급 적색/황색 점멸 경고
    """
    def __init__(self, parent=None, max_points=60):
        super().__init__(parent)
        self.max_points = max_points
        self.rx_history = deque([0.0] * max_points, maxlen=max_points)
        self.tx_history = deque([0.0] * max_points, maxlen=max_points)
        self.cur_rx_kb = 0.0
        self.cur_tx_kb = 0.0
        self.peak_rx_kb = 0.0
        self.peak_tx_kb = 0.0
        self.setMinimumHeight(185)

        self.overload_threshold_kb = 12288.0  # 12 MB/s
        self.is_overloaded = False
        self.flash_state = False

        self.flash_timer = QTimer(self)
        self.flash_timer.timeout.connect(self._toggle_flash)
        self.flash_timer.start(350)

    def _toggle_flash(self):
        if self.is_overloaded:
            self.flash_state = not self.flash_state
            self.update()
        else:
            if self.flash_state:
                self.flash_state = False
                self.update()

    def update_data(self, rx_kbs: float, tx_kbs: float):
        self.cur_rx_kb = rx_kbs
        self.cur_tx_kb = tx_kbs
        if rx_kbs > self.peak_rx_kb:
            self.peak_rx_kb = rx_kbs
        if tx_kbs > self.peak_tx_kb:
            self.peak_tx_kb = tx_kbs
        self.rx_history.append(rx_kbs)
        self.tx_history.append(tx_kbs)
        self.is_overloaded = (rx_kbs >= self.overload_threshold_kb or tx_kbs >= self.overload_threshold_kb)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        padding_left = 86
        padding_bottom = 22
        padding_top = 52
        padding_right = 95

        chart_w = max(100, w - padding_left - padding_right)
        chart_h = max(60, h - padding_top - padding_bottom)

        # 1. 고대비 딥 다크 배경 패널
        if self.is_overloaded and self.flash_state:
            p.setBrush(QColor("#281016"))
            p.setPen(QPen(QColor("#EF4444"), 2.2))
        else:
            p.setBrush(QColor("#0B111E"))
            p.setPen(QPen(QColor("#2A3950"), 1.2))

        p.drawRoundedRect(1, 1, w - 2, h - 2, 10, 10)

        # 2. 상단 디지털 HUD 수치 배지 (화면 너비 변화에 맞춰 유동적으로 배치)
        # 박스 너비는 가로폭에 따라 자연스럽게 늘어나며, 공간이 좁아져도 겹치지 않도록 설계
        rx_w = min(295.0, max(180.0, (w - 280.0) / 2.0))
        tx_w = rx_w
        hud_box_w = min(280.0, max(180.0, rx_w))

        # (A) 수신 RX HUD 박스
        rx_box = QRectF(14, 8, hud_box_w, 34)
        p.setBrush(QColor(14, 165, 233, 28))
        p.setPen(QPen(QColor("#00E5FF"), 1.3))
        p.drawRoundedRect(rx_box, 8, 8)

        p.setFont(QFont("Malgun Gothic", 9, QFont.Weight.Bold))
        p.setPen(QColor("#BAE6FD"))
        p.drawText(22, 29, "⬇ RX:")

        p.setFont(QFont("Segoe UI", 13, QFont.Weight.Black))
        p.setPen(QColor("#00F0FF"))
        p.drawText(68, 30, self._format_speed(self.cur_rx_kb))

        p.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        p.setPen(QColor("#7DD3FC"))
        p.drawText(int(rx_box.right() - 55), 29, f"P:{self._format_speed_short(self.peak_rx_kb)}")

        # (B) 송신 TX HUD 박스
        tx_box = QRectF(rx_box.right() + 10, 8, hud_box_w, 34)
        p.setBrush(QColor(16, 185, 129, 28))
        p.setPen(QPen(QColor("#00FF9D"), 1.3))
        p.drawRoundedRect(tx_box, 8, 8)

        p.setFont(QFont("Malgun Gothic", 9, QFont.Weight.Bold))
        p.setPen(QColor("#A7F3D0"))
        p.drawText(int(tx_box.left() + 8), 29, "⬆ TX:")

        p.setFont(QFont("Segoe UI", 13, QFont.Weight.Black))
        p.setPen(QColor("#00FF9D"))
        p.drawText(int(tx_box.left() + 54), 30, self._format_speed(self.cur_tx_kb))

        p.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        p.setPen(QColor("#6EE7B7"))
        p.drawText(int(tx_box.right() - 55), 29, f"P:{self._format_speed_short(self.peak_tx_kb)}")

        # (C) 합산 실시간 대역폭 표시 또는 과부하 경고 배지
        total_kb = self.cur_rx_kb + self.cur_tx_kb
        if self.is_overloaded:
            warn_w = min(300.0, max(200.0, w - tx_box.right() - 20))
            warn_box = QRectF(w - warn_w - 14, 8, warn_w, 34)
            p.setBrush(QColor("#991B1B" if self.flash_state else "#78350F"))
            p.setPen(QPen(QColor("#FCA5A5"), 1.5))
            p.drawRoundedRect(warn_box, 8, 8)
            p.setFont(QFont("Malgun Gothic", 9, QFont.Weight.Bold))
            p.setPen(QColor("#FFFFFF"))
            p.drawText(int(warn_box.left() + 10), 29, "🚨 [과부하 경고] 트래픽 급증!")
        else:
            tot_w = min(220.0, max(160.0, w - tx_box.right() - 20))
            tot_box = QRectF(w - tot_w - 14, 8, tot_w, 34)
            p.setBrush(QColor("#162032"))
            p.setPen(QPen(QColor("#334155"), 1.0))
            p.drawRoundedRect(tot_box, 8, 8)
            p.setFont(QFont("Malgun Gothic", 9, QFont.Weight.Bold))
            p.setPen(QColor("#94A3B8"))
            p.drawText(int(tot_box.left() + 10), 29, "⚡ 총 대역폭:")
            p.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
            p.setPen(QColor("#FBBF24"))
            p.drawText(int(tot_box.left() + 85), 30, self._format_speed(total_kb))

        # 3. Y축 눈금선 및 고대비 눈금 수치
        max_val = max(max(self.rx_history), max(self.tx_history), 60.0)
        scale_max = max_val * 1.22

        p.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
        for i in range(4):
            y = padding_top + (chart_h / 3.0) * i
            p.setPen(QPen(QColor("#1E2D44"), 1, Qt.PenStyle.DashLine))
            p.drawLine(int(padding_left), int(y), int(w - padding_right), int(y))
            
            label_val = scale_max * (1.0 - i / 3.0)
            lbl_str = f"{label_val/1024.0:.1f} MB/s" if label_val >= 1024 else f"{label_val:.0f} KB/s"
            p.setPen(QColor("#CBD5E1"))
            p.drawText(12, int(y + 4), lbl_str)

        step_x = chart_w / (self.max_points - 1)

        # 4. RX 곡선 및 그라디언트 영역 (선명한 네온 시안)
        rx_last_pt = self._draw_series(
            p, self.rx_history, scale_max, padding_left, padding_top, chart_h, step_x,
            line_color=QColor("#00F0FF"), top_alpha_color=QColor(0, 240, 255, 105), bottom_alpha_color=QColor(0, 240, 255, 6)
        )

        # 5. TX 곡선 및 그라디언트 영역 (선명한 네온 에메랄드)
        tx_last_pt = self._draw_series(
            p, self.tx_history, scale_max, padding_left, padding_top, chart_h, step_x,
            line_color=QColor("#00FF9D"), top_alpha_color=QColor(0, 255, 157, 100), bottom_alpha_color=QColor(0, 255, 157, 6)
        )

        # 6. 우측 끝 실시간 포인트 발광 마커 & 수치 콜아웃 태그
        if rx_last_pt and tx_last_pt:
            rx_y = rx_last_pt.y()
            tx_y = tx_last_pt.y()
            # 두 태그가 겹치지 않도록 최소 간격 보정
            if abs(rx_y - tx_y) < 18:
                if rx_y <= tx_y:
                    rx_y -= 9
                    tx_y += 9
                else:
                    tx_y -= 9
                    rx_y += 9

            self._draw_live_callout(p, rx_last_pt.x(), rx_y, f"RX {self._format_speed_short(self.cur_rx_kb)}", QColor("#00F0FF"), QColor("#082F49"))
            self._draw_live_callout(p, tx_last_pt.x(), tx_y, f"TX {self._format_speed_short(self.cur_tx_kb)}", QColor("#00FF9D"), QColor("#064E3B"))

        p.end()

    def _draw_series(self, p, data_deque, scale_max, pad_left, pad_top, chart_h, step_x, line_color, top_alpha_color, bottom_alpha_color):
        path = QPainterPath()
        fill_path = QPainterPath()

        points = []
        for i, val in enumerate(data_deque):
            x = pad_left + i * step_x
            normalized = min(val / scale_max, 1.0)
            y = pad_top + chart_h - (normalized * chart_h)
            points.append(QPointF(x, y))

        if not points:
            return None

        path.moveTo(points[0])
        fill_path.moveTo(points[0].x(), pad_top + chart_h)
        fill_path.lineTo(points[0])

        for pt in points[1:]:
            path.lineTo(pt)
            fill_path.lineTo(pt)

        fill_path.lineTo(points[-1].x(), pad_top + chart_h)
        fill_path.closeSubpath()

        grad = QLinearGradient(0, pad_top, 0, pad_top + chart_h)
        grad.setColorAt(0.0, top_alpha_color)
        grad.setColorAt(1.0, bottom_alpha_color)

        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(grad))
        p.drawPath(fill_path)

        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(line_color, 2.6))
        p.drawPath(path)

        # 끝점 발광 원
        last_pt = points[-1]
        p.setBrush(line_color)
        p.setPen(QPen(QColor("#FFFFFF"), 1.5))
        p.drawEllipse(last_pt, 4.5, 4.5)
        return last_pt

    def _draw_live_callout(self, p, x, y, text, border_color, bg_color):
        tag_rect = QRectF(x + 8, max(48.0, min(self.height() - 22.0, y - 10)), 80, 20)
        p.setBrush(bg_color)
        p.setPen(QPen(border_color, 1.2))
        p.drawRoundedRect(tag_rect, 5, 5)
        p.setFont(QFont("Consolas", 8, QFont.Weight.Bold))
        p.setPen(border_color)
        p.drawText(int(tag_rect.x() + 5), int(tag_rect.y() + 14), text)

    def _format_speed(self, kb_s: float) -> str:
        if kb_s >= 1024.0:
            return f"{kb_s / 1024.0:.2f} MB/s"
        return f"{kb_s:.1f} KB/s"

    def _format_speed_short(self, kb_s: float) -> str:
        if kb_s >= 1024.0:
            return f"{kb_s / 1024.0:.1f}M"
        return f"{kb_s:.0f}K"
