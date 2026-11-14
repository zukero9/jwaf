import sys
import ctypes
import os
import traceback
from PyQt6.QtWidgets import QApplication, QMessageBox
from ui.main_window import MainWindow

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def excepthook(exc_type, exc_value, exc_tb):
    err_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    print(err_msg)
    try:
        with open("crash_log.txt", "a", encoding="utf-8") as f:
            f.write(err_msg + "\n" + "="*50 + "\n")
        QMessageBox.critical(None, "실행 오류 (Jinkero Shield)", f"프로그램 시작 중 오류가 발생했습니다:\n\n{exc_value}\n\n자세한 내역은 crash_log.txt에 기록되었습니다.")
    except Exception:
        pass

def main():
    sys.excepthook = excepthook
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    
    app = QApplication(sys.argv)
    app.setApplicationName("Jinkero Shield 개인용 방화벽 & 로컬 WAF")
    app.setQuitOnLastWindowClosed(False)

    # 관리자 권한 확인
    if not is_admin():
        print("[Notice] Running with standard user rights. Elevated admin rights recommended for Windows Firewall manipulation.")

    try:
        window = MainWindow()
        if "--minimized" in sys.argv:
            window.hide()
            window.tray_icon.showMessage(
                "Jinkero Shield 자동 시작됨",
                "윈도우 시작과 함께 백그라운드 트레이 모드로 실시간 방화벽 보호가 활성화되었습니다.",
                window.tray_icon.MessageIcon.Information,
                2500
            )
        else:
            window.show()
        sys.exit(app.exec())
    except Exception as e:
        excepthook(type(e), e, e.__traceback__)

if __name__ == "__main__":
    main()

