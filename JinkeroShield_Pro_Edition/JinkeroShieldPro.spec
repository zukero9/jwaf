# -*- mode: python ; coding: utf-8 -*-
import sys
if r'E:\soamai\localwaf' in sys.path:
    sys.path.remove(r'E:\soamai\localwaf')
sys.path.insert(0, r'E:\soamai\localwaf\JinkeroShield_Pro_Edition')

a = Analysis(
    ['main_pro.py'],
    pathex=['E:\\soamai\\localwaf\\JinkeroShield_Pro_Edition'],
    binaries=[],
    datas=[('jwaf_icon.ico', '.'), ('jwaf_icon.png', '.')],
    hiddenimports=['core.ai_full_engine', 'core.auto_updater', 'core.edr_process_guard', 'core.self_protection', 'ui.icon_resource', 'setup_wizard'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe_main = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='JinkeroShieldPro',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    manifest='admin_manifest.xml',
    version='version_info.txt',
    icon='jwaf_icon.ico',
)

exe_setup = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='setup',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    manifest='admin_manifest.xml',
    version='version_info.txt',
    icon='jwaf_icon.ico',
)

coll = COLLECT(
    exe_main,
    exe_setup,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='JinkeroShieldPro',
)
