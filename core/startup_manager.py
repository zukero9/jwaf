import sys
import os
import winreg

from typing import Optional

STARTUP_KEY_NAME = "JinkeroShield"

def get_exe_path() -> str:
    """현재 실행 중인 실행 파일의 절대 경로 반환"""
    if getattr(sys, 'frozen', False):
        return os.path.abspath(sys.executable)
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "main.py"))

def is_startup_enabled() -> bool:
    """윈도우 시작 프로그램 등록 여부 확인"""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_READ
        )
        val, _ = winreg.QueryValueEx(key, STARTUP_KEY_NAME)
        winreg.CloseKey(key)
        return bool(val)
    except Exception:
        return False

def set_startup_enabled(enabled: bool, custom_exe_path: Optional[str] = None) -> bool:
    """윈도우 시작 프로그램 등록 또는 제거"""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        if enabled:
            target = custom_exe_path if custom_exe_path else get_exe_path()
            exe_path = f'"{target}" --minimized'
            winreg.SetValueEx(key, STARTUP_KEY_NAME, 0, winreg.REG_SZ, exe_path)
        else:
            try:
                winreg.DeleteValue(key, STARTUP_KEY_NAME)
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"[Startup Reg Error] {e}")
        return False

