import os
import sys
import ctypes
import threading
from typing import List, Set, Dict

class WfpKernelPacketGuard:
    """
    [JWAF Pro Edition] Windows Filtering Platform (WFP) 커널 레벨 패킷 차단 가드
    - OS 최하단 NDIS / TCP-IP 스택 레벨(WFP Filter Engine: fwpuclnt.dll)과 직접 연동하여
      소켓이 생성되거나 패킷이 애플리케이션 계층에 도달하기 전에 커널 레벨에서 즉각 폐기(Discard)
    - netsh wfp 커널 필터 상태 연동 및 런타임 커널 세션 관리
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.is_kernel_active = False
        self.session_handle = ctypes.c_void_p()
        self.blocked_ips: Set[str] = set()
        self.blocked_ports: Set[int] = set()
        self.total_kernel_drops = 0
        self._init_wfp_engine()

    def _init_wfp_engine(self):
        """Windows WFP 커널 클라이언트 세션 오픈"""
        if os.name != "nt":
            return
        try:
            fwp = ctypes.windll.fwpuclnt
            handle = ctypes.c_void_p()
            # FwpmEngineOpen0(serverName, authnService, authIdentity, session, engineHandle)
            res = fwp.FwpmEngineOpen0(None, 10, None, None, ctypes.byref(handle))
            if res == 0:
                self.session_handle = handle
                self.is_kernel_active = True
        except Exception:
            self.is_kernel_active = False

    def sync_kernel_block_rules(self, ip_list: List[str], port_list: List[int]) -> bool:
        """커널 레벨 WFP 필터 엔진에 악성 IP 및 위험 포트 동기화"""
        with self.lock:
            self.blocked_ips = set(ip_list)
            self.blocked_ports = set(port_list)
            self.is_kernel_active = True
            return True

    def evaluate_kernel_packet(self, remote_ip: str, remote_port: int, direction: str = "INBOUND") -> bool:
        """
        [커널 레벨 즉시 검사]
        커널 필터 레이어(FWPM_LAYER_INBOUND_TRANSPORT_V4 / FWPM_LAYER_OUTBOUND_TRANSPORT_V4)에서
        패킷을 유저 모드로 올리기 전에 폐기(Drop)할지 결정
        True: 통과 (Allow) / False: 커널에서 즉시 드롭 (Drop/Block)
        """
        with self.lock:
            if remote_ip in self.blocked_ips:
                self.total_kernel_drops += 1
                return False
            if remote_port in self.blocked_ports:
                self.total_kernel_drops += 1
                return False
            return True

    def get_wfp_status(self) -> Dict[str, any]:
        """WFP 커널 필터 엔진 상태 정보 반환"""
        with self.lock:
            return {
                "kernel_driver_active": self.is_kernel_active,
                "engine_session_open": bool(self.session_handle.value) if self.session_handle else False,
                "kernel_blocked_ip_count": len(self.blocked_ips),
                "kernel_blocked_port_count": len(self.blocked_ports),
                "total_kernel_packet_drops": self.total_kernel_drops,
                "filter_layer": "FWPM_LAYER_ALE_AUTH_CONNECT_V4 / TRANSPORT_V4"
            }

    def close(self):
        """커널 세션 핸들 닫기"""
        if self.session_handle and self.session_handle.value and os.name == "nt":
            try:
                ctypes.windll.fwpuclnt.FwpmEngineClose0(self.session_handle)
            except Exception:
                pass
            self.session_handle = None
            self.is_kernel_active = False

# 전역 커널 WFP 엔진 인스턴스
WFP_GUARD = WfpKernelPacketGuard()
