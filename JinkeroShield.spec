# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('core', 'core'), ('ui', 'ui'), ('jwaf_icon.ico', '.')],
    hiddenimports=[
        'PyQt6.QtCore', 'PyQt6.QtGui', 'PyQt6.QtWidgets',
        'core.ai_full_engine', 'core.auto_updater', 'core.edr_process_guard',
        'core.self_protection', 'core.tls_inspector', 'core.wfp_kernel_guard',
        'core.swarm_threat_intel', 'cryptography', 'cryptography.x509'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='JinkeroShield',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['jwaf_icon.ico'],
    manifest='admin_manifest.xml',
)
