import os
import hashlib
import psutil
from typing import Dict, List, Tuple

class EDRProcessGuard:
    """
    [Pro Edition 전용] EDR(Endpoint Detection & Response) 프로세스 네트워크 감사 및 킬스위치
    - 네트워크 통신 중인 모든 프로세스의 PID, 실행 경로, 명령줄(Command Line), SHA-256 해시 추출
    - 악성 의심 프로세스 즉시 강제 종료(Kill Process) 및 연결된 원격 C2 IP 동시 격리 지원
    """
    SYSTEM_PROTECTED_PROCS = {
        "system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe", "dwm.exe",
        "explorer.exe", "jinkeroshield.exe", "jinkeroshieldpro.exe"
    }

    def __init__(self):
        self.hash_cache: Dict[str, str] = {}

    def get_file_sha256(self, exe_path: str) -> str:
        if not exe_path or not os.path.exists(exe_path):
            return "N/A (System/Protected)"
        if exe_path in self.hash_cache:
            return self.hash_cache[exe_path]
        try:
            h = hashlib.sha256()
            with open(exe_path, "rb") as f:
                # 앞부분 2MB 샘플 해싱으로 UI 속도 및 무결성 식별 동시 확보
                chunk = f.read(2 * 1024 * 1024)
                h.update(chunk)
            digest = h.hexdigest()[:24] + "..."
            self.hash_cache[exe_path] = digest
            return digest
        except Exception:
            return "Access Denied (Kernel)"

    def get_active_network_processes(self) -> List[Dict[str, str]]:
        """현재 네트워크 소켓을 열고 있는 활성 프로세스 목록과 SHA-256 해시, 원격지 정보 반환"""
        proc_map: Dict[int, Dict] = {}
        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                if not c.pid or c.pid <= 4:
                    continue
                pid = c.pid
                r_str = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "LISTEN"
                l_port = c.laddr.port if c.laddr else 0

                if pid not in proc_map:
                    try:
                        p = psutil.Process(pid)
                        pname = p.name()
                        try:
                            pexe = p.exe()
                        except Exception:
                            pexe = ""
                        try:
                            pcmd = " ".join(p.cmdline())[:120]
                        except Exception:
                            pcmd = pname
                        sha = self.get_file_sha256(pexe)
                        proc_map[pid] = {
                            "pid": str(pid),
                            "name": pname,
                            "exe": pexe or pname,
                            "cmdline": pcmd,
                            "sha256": sha,
                            "remotes": set(),
                            "local_ports": set(),
                            "conn_count": 0
                        }
                    except Exception:
                        continue

                if pid in proc_map:
                    proc_map[pid]["conn_count"] += 1
                    if c.raddr:
                        proc_map[pid]["remotes"].add(r_str)
                    if l_port:
                        proc_map[pid]["local_ports"].add(str(l_port))
        except Exception:
            pass

        results = []
        for pid, info in sorted(proc_map.items(), key=lambda x: x[1]["conn_count"], reverse=True):
            remotes_list = sorted(list(info["remotes"]))[:4]
            results.append({
                "pid": info["pid"],
                "name": info["name"],
                "exe": info["exe"],
                "cmdline": info["cmdline"],
                "sha256": info["sha256"],
                "conn_count": str(info["conn_count"]),
                "remote_summary": ", ".join(remotes_list) if remotes_list else "LOCAL LISTEN",
                "raw_ips": [r.split(":")[0] for r in info["remotes"] if ":" in r]
            })
        return results[:50]

    def kill_process_by_pid(self, pid: int) -> Tuple[bool, str]:
        """지정한 PID 프로세스를 즉시 강제 종료 (시스템 필수 프로세스는 보호)"""
        try:
            p = psutil.Process(pid)
            pname = p.name()
            if pname.lower() in self.SYSTEM_PROTECTED_PROCS:
                return False, f"시스템 핵심 프로세스({pname})는 OS 안정성을 위해 강제 종료할 수 없습니다."
            p.terminate()
            try:
                p.wait(timeout=1.5)
            except psutil.TimeoutExpired:
                p.kill()
            return True, f"프로세스 [{pname} (PID: {pid})]를 성공적으로 강제 종료(Kill)하여 네트워크 연결을 차단했습니다."
        except Exception as e:
            return False, f"프로세스 종료 실패 (관리자 권한 필요 또는 이미 종료됨): {e}"

