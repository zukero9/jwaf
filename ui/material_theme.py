# Modern Cyber Security & Windows 11 Fluent Dark Integrated Theme
# 사이버보안 전문 대시보드 룩앤필 (다크 미카, 엠버/골드 시그니처, 정교한 테두리)

NORTON_WIN11_STYLE = """
/* 전역 위젯 및 Segoe UI Variable / 맑은 고딕 타이포그래피 */
QWidget {
    font-family: 'Segoe UI Variable Display', 'Segoe UI', 'Malgun Gothic', '맑은 고딕', sans-serif;
    font-size: 13px;
    color: #E2E8F0;
    background-color: transparent;
}

QMainWindow {
    /* Windows 11 Dark Mica & Norton Dark Slate */
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #12161F, stop:0.5 #0F131A, stop:1 #0A0D12);
}

/* Windows 11 Dark Card Surface */
QFrame#Card {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1A202C, stop:1 #141A24);
    border-radius: 12px;
    border: 1px solid #2D3748;
}

QFrame#HeaderCard {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1A202C, stop:0.7 #171E29, stop:1 #121720);
    border-radius: 12px;
    border: 1px solid #2D3748;
}

/* 타이틀 및 헤더 */
QLabel#HeaderTitle {
    font-size: 22px;
    font-weight: 800;
    color: #F8FAFC;
    letter-spacing: -0.3px;
}

QLabel#CardTitle {
    font-size: 14px;
    font-weight: 700;
    color: #E2E8F0;
}

/* Norton Signature 황금빛 엠버 & 사이버 블루 버튼 */
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #F59E0B, stop:1 #D97706);
    color: #0F172A;
    border-radius: 7px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 700;
    border: 1px solid #FBBF24;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FBBF24, stop:1 #F59E0B);
    border: 1px solid #FDE68A;
}

QPushButton:pressed {
    background: #B45309;
}

QPushButton#DangerButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #EF4444, stop:1 #DC2626);
    color: #FFFFFF;
    border: 1px solid #F87171;
}

QPushButton#DangerButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #F87171, stop:1 #EF4444);
}

QPushButton#SuccessButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #10B981, stop:1 #059669);
    color: #FFFFFF;
    border: 1px solid #34D399;
}

QPushButton#SuccessButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #34D399, stop:1 #10B981);
}

QPushButton#SecondaryButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2D3748, stop:1 #1F2937);
    color: #E2E8F0;
    border: 1px solid #4A5568;
}

QPushButton#SecondaryButton:hover {
    background: #4A5568;
    color: #FFFFFF;
    border: 1px solid #718096;
}

/* Windows 11 일체형 상단 탭 디자인 */
QTabWidget::pane {
    border: 1px solid #2D3748;
    border-radius: 10px;
    background: #141A24;
}

QTabBar::tab {
    background: #1A202C;
    color: #94A3B8;
    padding: 10px 20px;
    margin-right: 4px;
    font-size: 13px;
    font-weight: 600;
    border-top-left-radius: 7px;
    border-top-right-radius: 7px;
    border: 1px solid #2D3748;
    border-bottom: none;
}

QTabBar::tab:selected {
    color: #FBBF24; /* Norton Signature Gold */
    background: #141A24;
    border: 1px solid #F59E0B;
    border-bottom: 2px solid #141A24;
    font-weight: 700;
}

QTabBar::tab:hover:!selected {
    color: #F8FAFC;
    background: #242D3D;
}

/* 표 (TableWidget) - 노턴 스타일 선명한 그리드 */
QTableWidget {
    background-color: #0F131A;
    border: none;
    gridline-color: #1F2633;
    color: #E2E8F0;
    font-size: 13px;
    selection-background-color: #1E293B;
    selection-color: #FBBF24;
}

QHeaderView::section {
    background-color: #1A202C;
    color: #94A3B8;
    padding: 9px 8px;
    border: none;
    border-bottom: 1px solid #2D3748;
    font-size: 12px;
    font-weight: 700;
}

/* 텍스트 입력 필드 */
QLineEdit {
    background-color: #0F131A;
    border: 1px solid #2D3748;
    border-radius: 7px;
    padding: 8px 12px;
    font-size: 13px;
    color: #F8FAFC;
}

QLineEdit:focus {
    border: 1px solid #F59E0B;
    background-color: #141A24;
}

/* 리스트 위젯 */
QListWidget {
    background-color: #0F131A;
    border: 1px solid #2D3748;
    border-radius: 9px;
    padding: 6px;
    color: #E2E8F0;
}

QListWidget::item {
    padding: 7px 10px;
    border-radius: 6px;
    margin-bottom: 2px;
}

QListWidget::item:selected {
    background: #2D3748;
    color: #FBBF24;
    font-weight: 600;
}

/* 체크박스 */
QCheckBox {
    spacing: 9px;
    font-size: 13px;
    color: #E2E8F0;
}

QCheckBox::indicator {
    width: 19px;
    height: 19px;
    border-radius: 5px;
    border: 1px solid #4A5568;
    background-color: #0F131A;
}

QCheckBox::indicator:hover {
    border-color: #F59E0B;
}

QCheckBox::indicator:checked {
    background-color: #F59E0B;
    border-color: #FBBF24;
}

/* 스크롤바 */
QScrollBar:vertical {
    border: none;
    background: #0F131A;
    width: 8px;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background: #2D3748;
    border-radius: 4px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background: #4A5568;
}
"""
