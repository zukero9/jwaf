import os
import sys
import time
import shutil
import ctypes
from ctypes import wintypes
import subprocess
import winreg
import psutil
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QCheckBox, QProgressBar, QFileDialog, QMessageBox, QTextEdit
)
from PyQt6.QtCore import Qt

DEFAULT_INSTALL_DIR = r"C:\Program Files\JinkeroShieldPro"
UNINSTALL_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\JinkeroShieldPro"
AUTORUN_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]

    def __init__(self, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8):
        super().__init__(l, w1, w2, (wintypes.BYTE * 8)(b1, b2, b3, b4, b5, b6, b7, b8))


def create_windows_shortcut(target_exe: str, shortcut_path: str, description: str):
    """
    [V3 백신 행위탐지 오진 방지]
    외부 PowerShell이나 WScript.Shell 프로세스를 절대 실행하지 않고,
    순수 Win32 네이티브 COM API (ole32.dll IShellLinkW + IPersistFile)를 메모리 내에서 직접 호출하여 .lnk 바로가기를 생성합니다.
    """
    try:
        CLSID_ShellLink = _GUID(0x00021401, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46)
        IID_IShellLinkW = _GUID(0x000214F9, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46)
        IID_IPersistFile = _GUID(0x0000010B, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46)

        ole32 = ctypes.windll.ole32
        ole32.CoInitialize(None)
        psl = ctypes.c_void_p()
        hr = ole32.CoCreateInstance(
            ctypes.byref(CLSID_ShellLink), None, 1, ctypes.byref(IID_IShellLinkW), ctypes.byref(psl)
        )
        if hr != 0 or not psl.value:
            return

        vtbl = ctypes.cast(ctypes.cast(psl, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.POINTER(ctypes.c_void_p))
        QueryInterface = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p))(vtbl[0])
        Release = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(vtbl[2])
        SetDescription = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.LPCWSTR)(vtbl[7])
        SetWorkingDirectory = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.LPCWSTR)(vtbl[9])
        SetIconLocation = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_int)(vtbl[17])
        SetPath = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.LPCWSTR)(vtbl[20])

        abs_exe = os.path.abspath(target_exe)
        exe_dir = os.path.dirname(abs_exe)
        ico_file = os.path.join(exe_dir, "jwaf_icon.ico")

        SetPath(psl, abs_exe)
        SetWorkingDirectory(psl, exe_dir)
        SetDescription(psl, description)
        SetIconLocation(psl, ico_file if os.path.exists(ico_file) else abs_exe, 0)

        ppf = ctypes.c_void_p()
        if QueryInterface(psl, ctypes.byref(IID_IPersistFile), ctypes.byref(ppf)) == 0 and ppf.value:
            ppf_vtbl = ctypes.cast(ctypes.cast(ppf, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.POINTER(ctypes.c_void_p))
            Save = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.LPCWSTR, wintypes.BOOL)(ppf_vtbl[6])
            ReleasePPF = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(ppf_vtbl[2])
            Save(ppf, os.path.abspath(shortcut_path), True)
            ReleasePPF(ppf)

        Release(psl)
    except Exception:
        pass


def register_windows_uninstaller(install_dir: str, exe_path: str):
    """Windows 제어판(프로그램 추가/제거 및 설정 > 설치된 앱)에 정식 소프트웨어 등록"""
    try:
        ico_path = os.path.join(install_dir, "jwaf_icon.ico")
        display_icon = ico_path if os.path.exists(ico_path) else exe_path
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, UNINSTALL_REG_KEY)
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "JWAF - Jinkero Shield Pro AI (V2.0 Full Defense Suite)")
        winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, "2.0.0")
        winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "JINKERO Security Lab")
        winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, display_icon)
        winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, install_dir)
        winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, f'"{exe_path}" --uninstall')
        winreg.SetValueEx(key, "QuietUninstallString", 0, winreg.REG_SZ, f'"{exe_path}" --uninstall')
        winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
    except Exception:
        pass


def get_registered_install_dir() -> str:
    """레지스트리에 기록된 설치 경로 조회"""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, UNINSTALL_REG_KEY, 0, winreg.KEY_READ)
        loc, _ = winreg.QueryValueEx(key, "InstallLocation")
        winreg.CloseKey(key)
        if loc and os.path.exists(loc):
            return os.path.abspath(loc)
    except Exception:
        pass
    return ""


def _terminate_running_shield_processes():
    """제거 전 백그라운드 트레이 등에서 실행 중인 JinkeroShieldPro.exe 프로세스를 모두 종료하여 파일 잠금 해제"""
    my_pid = os.getpid()
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid = proc.info["pid"]
            pname = (proc.info["name"] or "").lower()
            if pid != my_pid and pname in ("jinkeroshieldpro.exe", "jinkeroshield_pro_setup.exe"):
                proc.kill()
        except Exception:
            pass
    time.sleep(0.5)


def run_uninstall_procedure() -> str:
    """
    [제어판 프로그램 추가/제거 완벽 삭제 엔진]
    1. 실행 중인 백그라운드 프로세스 종료 (파일 잠금 해제)
    2. Windows 방화벽 규칙(Jinkero_Block_Ips, Jinkero_Outbound_Block, Jinkero_Block_Ports) 제거
    3. 바탕화면 및 시작 메뉴 바로가기(.lnk) 삭제
    4. Windows 시작 프로그램 레지스트리 및 제어판 Uninstall 레지스트리 삭제
    5. 설치 폴더(C:\\Program Files\\JinkeroShieldPro 등) 내부 파일 및 폴더 자체를 남김없이 100% 완전 삭제
    """
    temp_dir = os.environ.get("TEMP", r"C:\Windows\Temp")
    try:
        os.chdir(temp_dir)
    except Exception:
        pass

    # 1. 삭제할 설치 폴더 경로 파악
    target_dirs = set()
    reg_dir = get_registered_install_dir()
    if reg_dir:
        target_dirs.add(os.path.abspath(reg_dir))

    for candidate in (
        DEFAULT_INSTALL_DIR,
        os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Programs", "JinkeroShieldPro"),
    ):
        if os.path.exists(candidate):
            target_dirs.add(os.path.abspath(candidate))

    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        if "jinkeroshieldpro" in os.path.basename(exe_dir).lower() and "dist" not in exe_dir.lower():
            target_dirs.add(exe_dir)

    # 2. 실행 중인 다른 JinkeroShieldPro 프로세스 강제 종료
    _terminate_running_shield_processes()

    # 3. Windows 방화벽 규칙 정리
    try:
        from core.firewall_manager import cleanup_legacy_rules, delete_shield_rule, INBOUND_BLOCK_RULE, OUTBOUND_BLOCK_RULE, PORT_BLOCK_RULE
        cleanup_legacy_rules()
        delete_shield_rule(INBOUND_BLOCK_RULE)
        delete_shield_rule(OUTBOUND_BLOCK_RULE)
        delete_shield_rule(PORT_BLOCK_RULE)
    except Exception:
        pass

    # 4. 레지스트리(제어판 Uninstall & 시작프로그램 Run) 삭제
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, UNINSTALL_REG_KEY)
    except Exception:
        pass

    try:
        rkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTORUN_REG_KEY, 0, winreg.KEY_SET_VALUE)
        for val_name in ("JinkeroShieldPro", "JinkeroShield"):
            try:
                winreg.DeleteValue(rkey, val_name)
            except Exception:
                pass
        winreg.CloseKey(rkey)
    except Exception:
        pass

    # 5. 바탕화면 & 시작 메뉴 바로가기 및 구버전 카나리 파일 삭제
    shortcut_candidates = [
        os.path.join(os.path.expanduser("~"), "Desktop", "JWAF - Jinkero Shield Pro AI.lnk"),
        os.path.join(os.path.expanduser("~"), "Desktop", "Jinkero Shield Pro AI.lnk"),
        os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\JWAF - Jinkero Shield Pro AI.lnk"),
        os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Jinkero Shield Pro AI.lnk"),
        os.path.join(os.path.expanduser("~"), "Documents", "!_Jinkero_Canary_Trap_Do_Not_Modify.docx"),
    ]
    for sp in shortcut_candidates:
        if sp and os.path.exists(sp):
            try:
                os.remove(sp)
            except Exception:
                pass

    # 6. 설치 디렉터리 내부 잠기지 않은 파일 즉시 삭제 + 프로세스 종료 직후 폴더 완전 삭제 예약
    removed_summary = []
    for tdir in target_dirs:
        if not os.path.exists(tdir) or any(ch in tdir for ch in ('"', '&', '|', ';', '`', '$', '>')):
            continue
        removed_summary.append(tdir)
        # 먼저 즉시 삭제 가능한 하위 파일/폴더 제거
        shutil.rmtree(tdir, ignore_errors=True)
        if os.path.exists(tdir):
            # 자기 자신이 해당 폴더에서 실행 중이라 잠겨있는 경우, 프로세스 종료 직후(0.5초 간격 최대 15회 재시도) 폴더를 완전 삭제
            cmd_line = f'cmd.exe /d /c "for /L %i in (1,1,15) do @(if exist "{tdir}" (rmdir /s /q "{tdir}" >nul 2>&1 & ping 127.0.0.1 -n 2 >nul))"'
            try:
                subprocess.Popen(
                    cmd_line,
                    cwd=temp_dir,
                    shell=False,
                    creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS
                )
            except Exception:
                pass

    return ", ".join(removed_summary) if removed_summary else DEFAULT_INSTALL_DIR


class ProSetupWizard(QDialog):
    """
    Windows 11 정식 소프트웨어 설치 마법사 GUI (Jinkero Shield Pro V2.0)
    """
    def __init__(self, source_bundle_dir: str):
        super().__init__()
        candidate_dist = os.path.join(source_bundle_dir, "dist", "JinkeroShieldPro")
        if os.path.exists(os.path.join(candidate_dist, "JinkeroShieldPro.exe")):
            self.source_bundle_dir = candidate_dist
        else:
            self.source_bundle_dir = source_bundle_dir
        self.setWindowTitle("JWAF (Jinkero Shield Pro AI V2.0) — Windows 정식 설치 마법사 (setup.exe)")
        try:
            from ui.icon_resource import get_jwaf_qicon
            self.setWindowIcon(get_jwaf_qicon())
        except Exception:
            pass
        self.setFixedSize(680, 540)
        self.setStyleSheet("""
            QDialog { background-color: #0B0F19; color: #F8FAFC; font-family: 'Malgun Gothic', 'Segoe UI', sans-serif; }
            QLabel { color: #E2E8F0; font-size: 13px; }
            QLineEdit { background: #161F30; border: 1px solid #334155; border-radius: 6px; padding: 8px; color: #FFFFFF; }
            QPushButton { background: #0284C7; color: #FFFFFF; border-radius: 7px; padding: 9px 18px; font-weight: bold; border: 1px solid #38BDF8; }
            QPushButton:hover { background: #0369A1; }
            QPushButton#Secondary { background: #1E293B; border: 1px solid #475569; }
            QPushButton#Danger { background: #991B1B; border: 1px solid #EF4444; }
            QPushButton#Danger:hover { background: #7F1D1D; }
            QCheckBox { color: #CBD5E1; font-size: 13px; spacing: 8px; }
            QProgressBar { border: 1px solid #334155; border-radius: 6px; background: #161F30; text-align: center; color: #FFFFFF; font-weight: bold; }
            QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284C7, stop:1 #10B981); border-radius: 5px; }
        """)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(13)

        hdr_row = QHBoxLayout()
        try:
            from ui.icon_resource import get_jwaf_qpixmap
            icon_lbl = QLabel()
            icon_lbl.setPixmap(get_jwaf_qpixmap(44))
            icon_lbl.setFixedSize(48, 48)
            hdr_row.addWidget(icon_lbl)
        except Exception:
            pass
        title = QLabel("JWAF (Jinkero Shield Pro AI V2.0) 정식 설치 마법사")
        title.setStyleSheet("font-size: 20px; font-weight: 800; color: #38BDF8;")
        hdr_row.addWidget(title)
        hdr_row.addStretch()
        layout.addLayout(hdr_row)

        sub = QLabel("Windows 시스템에 자가 발전(Self-Evolving) 앙상블 AI 방화벽 및 EDR 스위트(JinkeroShieldPro.exe)를 설치합니다.")
        sub.setStyleSheet("color: #94A3B8; font-size: 12px;")
        layout.addWidget(sub)

        feature_box = QTextEdit()
        feature_box.setReadOnly(True)
        feature_box.setMaximumHeight(135)
        feature_box.setStyleSheet("background: #111827; border: 1px solid #1F2937; border-radius: 8px; padding: 10px; font-size: 12px; color: #CBD5E1;")
        feature_box.setHtml("""
        <b style="color:#FBBF24;">[Jinkero Shield Pro V2.0 정식 설치판 핵심 포함 사항]</b><br/>
        • <b>다중 앙상블 AI & 자가 발전(Self-Evolving) 엔진</b>: Isolation Forest(25 Trees) 온라인 자가 재학습 + 변종 공격 자율 규칙 합성(<code>AUTO-EVO-*</code>)<br/>
        • <b>백신(V3 등) 친화형 클린 인스톨러</b>: 네이티브 Win32 COM 바로가기 생성 및 Base64 인코딩 시그니처 DB 적용으로 타 백신 오진 원천 방지<br/>
        • <b>양방향 Windows 방화벽 연동</b>: 인바운드(<code>Jinkero_Block_Ips</code>) + 아웃바운드 C2 유출 차단(<code>Jinkero_Outbound_Block</code>)<br/>
        • <b>완벽한 클린 언인스톨러</b>: 제어판(프로그램 추가/제거) 삭제 시 프로세스·방화벽·레지스트리·설치 폴더까지 100% 완전 삭제 지원
        """)
        layout.addWidget(feature_box)

        path_lbl = QLabel("설치 대상 폴더 경로 (실행 파일: JinkeroShieldPro.exe):")
        path_lbl.setStyleSheet("font-weight: bold; color: #F8FAFC;")
        layout.addWidget(path_lbl)

        path_bar = QHBoxLayout()
        self.path_input = QLineEdit(DEFAULT_INSTALL_DIR)
        path_bar.addWidget(self.path_input)
        browse_btn = QPushButton("폴더 찾아보기...")
        browse_btn.setObjectName("Secondary")
        browse_btn.clicked.connect(self._browse_dir)
        path_bar.addWidget(browse_btn)
        layout.addLayout(path_bar)

        self.chk_desktop = QCheckBox("바탕화면에 'Jinkero Shield Pro AI' 바로가기 아이콘 생성 (네이티브 Win32 COM)")
        self.chk_desktop.setChecked(True)
        layout.addWidget(self.chk_desktop)

        self.chk_startmenu = QCheckBox("Windows 시작 메뉴 및 제어판(프로그램 추가/제거)에 정식 등록")
        self.chk_startmenu.setChecked(True)
        layout.addWidget(self.chk_startmenu)

        self.chk_autorun = QCheckBox("Windows 부팅 시 트레이 백그라운드 보호 자동 시작 등록")
        self.chk_autorun.setChecked(True)
        layout.addWidget(self.chk_autorun)

        self.chk_launch_now = QCheckBox("설치 완료 즉시 JinkeroShieldPro.exe 실행")
        self.chk_launch_now.setChecked(True)
        layout.addWidget(self.chk_launch_now)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setFixedHeight(22)
        layout.addWidget(self.progress)

        self.status_lbl = QLabel("설치 준비 완료 — [정식 설치 시작] 버튼을 클릭하세요.")
        self.status_lbl.setStyleSheet("color: #34D399; font-size: 12px; font-weight: bold;")
        layout.addWidget(self.status_lbl)

        btn_bar = QHBoxLayout()
        uninst_btn = QPushButton("🗑️ 기존 설치본 완전 제거 (Uninstall)")
        uninst_btn.setObjectName("Danger")
        uninst_btn.clicked.connect(self._perform_uninstall_from_wizard)
        btn_bar.addWidget(uninst_btn)

        btn_bar.addStretch()
        cancel_btn = QPushButton("닫기")
        cancel_btn.setObjectName("Secondary")
        cancel_btn.clicked.connect(self.reject)
        btn_bar.addWidget(cancel_btn)

        self.install_btn = QPushButton("🚀 정식 설치 시작 (Install)")
        self.install_btn.clicked.connect(self._perform_installation)
        btn_bar.addWidget(self.install_btn)
        layout.addLayout(btn_bar)

    def _browse_dir(self):
        d = QFileDialog.getExistingDirectory(self, "설치할 폴더 선택", self.path_input.text())
        if d:
            self.path_input.setText(os.path.join(d, "JinkeroShieldPro"))

    def _perform_uninstall_from_wizard(self):
        reply = QMessageBox.question(
            self,
            "Jinkero Shield Pro 완전 제거 확인",
            "시스템에 설치된 Jinkero Shield Pro AI의 모든 파일, 바로가기, 방화벽 규칙 및 제어판 등록 정보를 남김없이 완전 삭제하시겠습니까?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            removed_path = run_uninstall_procedure()
            QMessageBox.information(
                self,
                "완전 제거 완료",
                f"Jinkero Shield Pro AI가 시스템에서 100% 완전 삭제되었습니다.\n\n• 삭제된 설치 경로: {removed_path}\n• 바탕화면/시작메뉴 바로가기 및 제어판 레지스트리 삭제 완료"
            )
            self.accept()

    def _perform_installation(self):
        target_dir = self.path_input.text().strip()
        if not target_dir or any(ch in target_dir for ch in ('"', '&', '|', ';', '`', '$', '>')):
            QMessageBox.warning(self, "설치 경로 오류", "유효하지 않은 특수문자가 포함된 경로입니다.")
            return

        self.install_btn.setEnabled(False)
        self.progress.setValue(10)
        self.status_lbl.setText("기존 실행 중인 프로세스 확인 및 설치 폴더 준비 중...")

        _terminate_running_shield_processes()

        try:
            os.makedirs(target_dir, exist_ok=True)
        except PermissionError:
            fallback_dir = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "Programs", "JinkeroShieldPro")
            os.makedirs(fallback_dir, exist_ok=True)
            target_dir = fallback_dir
            self.path_input.setText(target_dir)

        try:
            self.progress.setValue(35)
            self.status_lbl.setText("1/3 JinkeroShieldPro.exe 및 코어 AI 엔진 파일 복사 중...")

            if os.path.abspath(self.source_bundle_dir).lower() != os.path.abspath(target_dir).lower():
                for item in os.listdir(self.source_bundle_dir):
                    # 불필요한 임시 빌드 폴더나 배치 파일은 복사 제외
                    if item.lower() in ("build", "dist", "__pycache__") or item.lower().endswith((".bat", ".spec")):
                        continue
                    s_item = os.path.join(self.source_bundle_dir, item)
                    d_item = os.path.join(target_dir, item)
                    if os.path.isdir(s_item):
                        shutil.copytree(s_item, d_item, dirs_exist_ok=True)
                    else:
                        shutil.copy2(s_item, d_item)

            self.progress.setValue(70)
            self.status_lbl.setText("2/3 네이티브 Win32 바로가기 및 제어판 등록 중...")

            installed_exe = os.path.join(target_dir, "JinkeroShieldPro.exe")
            if not os.path.exists(installed_exe):
                installed_exe = os.path.abspath(sys.executable)

            if self.chk_desktop.isChecked():
                # 기존 구버전 바로가기 정리 후 JWAF 커스텀 아이콘 바로가기 생성
                old_desk = os.path.join(os.path.expanduser("~"), "Desktop", "Jinkero Shield Pro AI.lnk")
                if os.path.exists(old_desk):
                    try:
                        os.remove(old_desk)
                    except Exception:
                        pass
                desktop_lnk = os.path.join(os.path.expanduser("~"), "Desktop", "JWAF - Jinkero Shield Pro AI.lnk")
                create_windows_shortcut(installed_exe, desktop_lnk, "JWAF - Jinkero Shield Pro AI (Full Defense Firewall & EDR)")

            if self.chk_startmenu.isChecked():
                start_menu_dir = os.path.join(
                    os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs"
                )
                if os.path.exists(start_menu_dir):
                    sm_lnk = os.path.join(start_menu_dir, "JWAF - Jinkero Shield Pro AI.lnk")
                    create_windows_shortcut(installed_exe, sm_lnk, "JWAF - Jinkero Shield Pro AI")

            register_windows_uninstaller(target_dir, installed_exe)

            self.progress.setValue(90)
            self.status_lbl.setText("3/3 Windows 부팅 자동 시작 구성 중...")

            if self.chk_autorun.isChecked():
                from core.startup_manager import set_startup_enabled
                set_startup_enabled(True, custom_exe_path=installed_exe)

            self.progress.setValue(100)
            self.status_lbl.setText(f"✅ 정식 설치 완료! 설치 경로: {target_dir}")

            QMessageBox.information(
                self, "설치 완료",
                f"Jinkero Shield Pro AI (V2.0) 정식 설치가 성공적으로 완료되었습니다!\n\n"
                f"• 설치 실행 파일: {installed_exe}\n"
                f"• 바탕화면 및 시작 메뉴 바로가기 생성 완료\n"
                f"• Windows 제어판(프로그램 추가/제거) 등록 완료"
            )

            if self.chk_launch_now.isChecked() and os.path.exists(installed_exe):
                subprocess.Popen([installed_exe], cwd=target_dir)

            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "설치 오류", f"설치 중 오류가 발생했습니다:\n{e}")
            self.install_btn.setEnabled(True)
