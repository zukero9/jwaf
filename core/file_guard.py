import os
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileIntegrityHandler(FileSystemEventHandler):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def on_modified(self, event):
        if not event.is_directory:
            self.callback("MODIFIED", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.callback("CREATED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.callback("DELETED", event.src_path)

class FileIntegrityGuard:
    """
    중요 시스템 파일(예: hosts 파일, 시작프로그램, 지정 중요 폴더)에 대한
    외부 프로세스/악성코드의 무단 변조, 조작, 랜섬웨어 감염 시도를 실시간 감시합니다.
    """
    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.observer = None
        self.is_running = False
        self.watched_paths = []
        
        # 기본 감시 대상 (윈도우 hosts 파일 위치 및 사용자 중요 경로)
        windir = os.environ.get("WINDIR", "C:\\Windows")
        hosts_dir = os.path.join(windir, "System32", "drivers", "etc")
        if os.path.exists(hosts_dir):
            self.watched_paths.append(hosts_dir)

    def add_watch_path(self, path: str):
        if os.path.exists(path) and path not in self.watched_paths:
            self.watched_paths.append(path)

    def start(self):
        if self.is_running:
            return
        self.observer = Observer()
        event_handler = FileIntegrityHandler(self._handle_event)
        for p in self.watched_paths:
            try:
                self.observer.schedule(event_handler, p, recursive=False)
            except Exception as e:
                pass
        self.observer.start()
        self.is_running = True

    def stop(self):
        if self.observer and self.is_running:
            self.observer.stop()
            self.observer.join()
            self.is_running = False

    def _handle_event(self, action: str, file_path: str):
        filename = os.path.basename(file_path).lower()
        threat_level = "HIGH"
        if "hosts" in filename:
            threat_level = "CRITICAL"
            desc = f"[경고] 윈도우 금융 파밍 방어: Hosts 파일 무단 변조 탐지! ({action}: {file_path})"
        else:
            desc = f"보호 폴더 내 파일 변경 감지 ({action}: {file_path})"
        
        if self.alert_callback:
            self.alert_callback({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": "FILE_TAMPERING",
                "action": action,
                "path": file_path,
                "threat_level": threat_level,
                "description": desc
            })

