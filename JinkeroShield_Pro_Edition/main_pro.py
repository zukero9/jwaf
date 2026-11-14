import sys
import ctypes
import os
import traceback
from PyQt6.QtWidgets import QApplication, QMessageBox
from ui.main_window import MainWindow
from setup_wizard import ProSetupWizard, run_uninstall_procedure


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def excepthook(exc_type, exc_value, exc_tb):
    err_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    print(err_msg)
    try:
        log_path = os.path.join(os.environ.get("TEMP", "."), "crash_log_pro.txt")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(err_msg + "\n" + "=" * 50 + "\n")
        QMessageBox.critical(
            None,
            "실행 오류 (Jinkero Shield Pro AI)",
            f"프로그램 실행 중 오류가 발생했습니다:\n\n{exc_value}\n\n자세한 내역은 {log_path}에 기록되었습니다."
        )
    except Exception:
        pass


def main():
    sys.excepthook = excepthook
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"

    # 1. 언인스톨 모드 (--uninstall): 제어판에서 제거 시 폴더 잠금이 발생하지 않도록 즉시 TEMP로 작업 디렉터리 이동
    if "--uninstall" in sys.argv:
        try:
            os.chdir(os.environ.get("TEMP", r"C:\Windows\Temp"))
        except Exception:
            pass
        app = QApplication(sys.argv)
        reply = QMessageBox.question(
            None,
            "Jinkero Shield Pro AI 완전 제거",
            "Jinkero Shield Pro AI (V2.0)와 모든 구성 파일, 바탕화면/시작메뉴 바로가기, 방화벽 규칙 및 레지스트리를 시스템에서 완전히 삭제하시겠습니까?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            removed_dir = run_uninstall_procedure()
            QMessageBox.information(
                None,
                "Jinkero Shield Pro 완전 제거 완료",
                f"Jinkero Shield Pro AI가 시스템에서 완벽하게 제거되었습니다.\n\n"
                f"• 제거된 설치 폴더: {removed_dir}\n"
                f"• 바탕화면 및 시작 메뉴 바로가기 삭제 완료\n"
                f"• Windows 방화벽 규칙 및 시작 프로그램 등록 해제 완료"
            )
        os._exit(0)

    app = QApplication(sys.argv)
    app.setApplicationName("Jinkero Shield Pro AI - Full Defense Firewall & EDR")

    exe_basename = os.path.basename(sys.executable if getattr(sys, "frozen", False) else sys.argv[0]).lower()

    # 2. 정식 설치 마법사 모드 (setup.exe 실행 시 또는 --setup 인자 전달 시)
    if exe_basename == "setup.exe" or "--setup" in sys.argv:
        bundle_dir = (
            os.path.dirname(os.path.abspath(sys.executable))
            if getattr(sys, "frozen", False)
            else os.path.dirname(os.path.abspath(__file__))
        )
        wiz = ProSetupWizard(bundle_dir)
        wiz.exec()
        sys.exit(0)

    # 3. 일반 대시보드 / 트레이 백그라운드 실행 모드 (JinkeroShieldPro.exe)
    app.setQuitOnLastWindowClosed(False)

    if not is_admin():
        print("[Notice] Running with standard user rights. Elevated admin rights recommended for Windows Firewall & EDR.")

    try:
        window = MainWindow()
        if "--minimized" in sys.argv:
            window.hide()
            window.tray_icon.showMessage(
                "Jinkero Shield Pro AI 자동 시작됨",
                "Windows 부팅과 함께 자가 발전 앙상블 AI 방화벽 및 EDR 보호가 트레이 모드로 활성화되었습니다.",
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
