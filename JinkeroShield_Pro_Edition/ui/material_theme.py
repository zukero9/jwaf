NORTON_WIN11_STYLE = """
QWidget {
    font-family: 'Segoe UI Variable Display', 'Segoe UI', 'Malgun Gothic', '맑은 고딕', sans-serif;
    font-size: 13px;
    color: #E2E8F0;
    background-color: transparent;
}
QMainWindow {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #101520, stop:0.5 #0B0F17, stop:1 #070A10);
}
QFrame#Card {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #182030, stop:1 #121824);
    border-radius: 12px;
    border: 1px solid #2A364B;
}
QFrame#HeaderCard {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #182234, stop:0.7 #141C2B, stop:1 #101622);
    border-radius: 12px;
    border: 1px solid #334155;
}
QLabel#HeaderTitle {
    font-size: 21px;
    font-weight: 800;
    color: #F8FAFC;
    letter-spacing: -0.3px;
}
QLabel#CardTitle {
    font-size: 14px;
    font-weight: 700;
    color: #E2E8F0;
}
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #F59E0B, stop:1 #D97706);
    color: #0F172A;
    border-radius: 7px;
    padding: 7px 15px;
    font-size: 12px;
    font-weight: 700;
    border: 1px solid #FBBF24;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FBBF24, stop:1 #F59E0B);
    border: 1px solid #FDE68A;
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
}
QTabWidget::pane {
    border: 1px solid #2D3748;
    border-radius: 10px;
    background: #121824;
}
QTabBar::tab {
    background: #1A2232;
    color: #94A3B8;
    padding: 9px 15px;
    margin-right: 4px;
    font-size: 12px;
    font-weight: 600;
    border-top-left-radius: 7px;
    border-top-right-radius: 7px;
    border: 1px solid #2D3748;
    border-bottom: none;
}
QTabBar::tab:selected {
    color: #38BDF8;
    background: #121824;
    border: 1px solid #0284C7;
    border-bottom: 2px solid #121824;
    font-weight: 700;
}
QTabBar::tab:hover:!selected {
    color: #F8FAFC;
    background: #242D3D;
}
QTableWidget {
    background-color: #0C1018;
    border: none;
    gridline-color: #1E2736;
    color: #E2E8F0;
    font-size: 12px;
    selection-background-color: #1E293B;
    selection-color: #38BDF8;
}
QHeaderView::section {
    background-color: #161E2C;
    color: #94A3B8;
    padding: 8px 8px;
    border: none;
    border-bottom: 1px solid #2D3748;
    font-size: 12px;
    font-weight: 700;
}
QLineEdit {
    background-color: #0C1018;
    border: 1px solid #2D3748;
    border-radius: 7px;
    padding: 7px 11px;
    font-size: 12px;
    color: #F8FAFC;
}
QLineEdit:focus {
    border: 1px solid #38BDF8;
}
QListWidget {
    background-color: #0C1018;
    border: 1px solid #2D3748;
    border-radius: 8px;
    padding: 5px;
    color: #E2E8F0;
}
QListWidget::item {
    padding: 6px 9px;
    border-radius: 5px;
}
QListWidget::item:selected {
    background: #1E293B;
    color: #38BDF8;
    font-weight: 600;
}
QCheckBox {
    spacing: 8px;
    font-size: 12px;
    color: #E2E8F0;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 5px;
    border: 1px solid #4A5568;
    background-color: #0C1018;
}
QCheckBox::indicator:checked {
    background-color: #0284C7;
    border-color: #38BDF8;
}
"""

