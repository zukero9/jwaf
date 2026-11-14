import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class SecurityFileHandler(FileSystemEventHandler):
    def __init__(self, alert_callback):
        super().__init__()
        self.alert_callback = alert_callback

    def on_modified(self, event):
        if not event.is_directory:
            filename = os.path.basename(event.src_path).lower()
            if filename == "hosts":
                self.alert_callback({
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "HOSTS_TAMPERING",
                    "severity": "CRITICAL",
                    "path": event.src_path,
                    "description": "[긴급 경고] Windows hosts 파일 무단 변조 감지! (금융 파밍/DNS 하이재킹 시도 의심)"
                })
            elif filename.endswith((".locked", ".encrypted", ".crypt", ".ryuk", ".lockbit")):
                self.alert_callback({
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "RANSOMWARE_EXTENSION_ALERT",
                    "severity": "CRITICAL",
                    "path": event.src_path,
                    "description": f"[랜섬웨어 긴급 경보] 의심스러운 랜섬웨어 암호화 확장자 변조 감지: {os.path.basename(event.src_path)}"
                })


class FileIntegrityGuard:
    """
    1. Windows hosts 파일(C:\\Windows\\System32\\drivers\\etc\\hosts) 파밍 감시
    2. 백신(V3 등)의 문서 폴더 보호와 충돌하지 않도록 비침투형(Read-Only Passive) 방식으로만 감시 수행
    """
    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.observer = None
        self.hosts_dir = r"C:\Windows\System32\drivers\etc"
        self._cleanup_legacy_canary()

    def _cleanup_legacy_canary(self):
        """이전 버전에서 생성되었을 수 있는 내 문서 테스트 파일 자동 정리"""
        try:
            old_canary = os.path.join(os.path.expanduser("~"), "Documents", "!_Jinkero_Canary_Trap_Do_Not_Modify.docx")
            if os.path.exists(old_canary):
                os.remove(old_canary)
        except Exception:
            pass

    def start(self):
        try:
            self.observer = Observer()
            handler = SecurityFileHandler(self.alert_callback)
            if os.path.exists(self.hosts_dir):
                self.observer.schedule(handler, self.hosts_dir, recursive=False)
            self.observer.start()
        except Exception:
            pass

    def stop(self):
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=1)
            except Exception:
                pass
