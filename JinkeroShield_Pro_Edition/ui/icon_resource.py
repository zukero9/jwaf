import os
import sys
import base64
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtCore import Qt

JWAF_ICON_B64 = (
    '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'
    'kiQ4awRiAAAAAElFTkSuQmCC'
)


def get_jwaf_qpixmap(size: int = 40) -> QPixmap:
    """AI가 생성한 JWAF 전용 사이버 쉴드 아이콘을 QPixmap으로 반환"""
    pm = QPixmap()
    base_dir = (
        os.path.dirname(os.path.abspath(sys.executable))
        if getattr(sys, "frozen", False)
        else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    for fname in ("jwaf_icon.png", "jwaf_icon.ico"):
        fpath = os.path.join(base_dir, fname)
        if os.path.exists(fpath):
            pm = QPixmap(fpath)
            if not pm.isNull():
                break
    if pm.isNull():
        try:
            raw = base64.b64decode(JWAF_ICON_B64.encode("ascii"))
            pm.loadFromData(raw, "PNG")
        except Exception:
            pass
    if size > 0 and not pm.isNull():
        return pm.scaled(
            size,
            size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
    return pm


def get_jwaf_qicon() -> QIcon:
    """AI가 생성한 JWAF 전용 사이버 쉴드 아이콘을 QIcon으로 반환"""
    base_dir = (
        os.path.dirname(os.path.abspath(sys.executable))
        if getattr(sys, "frozen", False)
        else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    ico_file = os.path.join(base_dir, "jwaf_icon.ico")
    if os.path.exists(ico_file):
        return QIcon(ico_file)
    return QIcon(get_jwaf_qpixmap(96))
