import sys
import os
import winreg

from typing import Optional

STARTUP_KEY_NAME = "JinkeroShieldPro"

def get_exe_path() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.abspath(sys.executable)
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "main_pro.py"))

def is_startup_enabled() -> bool:
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
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        if enabled:
            target = custom_exe_path if custom_exe_path else get_exe_path()
            exe_cmd = f'"{target}" --minimized'
            winreg.SetValueEx(key, STARTUP_KEY_NAME, 0, winreg.REG_SZ, exe_cmd)
        else:
            try:
                winreg.DeleteValue(key, STARTUP_KEY_NAME)
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
        return True
    except Exception:
        return False

