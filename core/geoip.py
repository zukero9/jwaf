import ipaddress
import urllib.request
import json
import os
import threading

GEO_CACHE_FILE = os.path.join(os.path.dirname(__file__), "geoip_cache.json")

# 한국 주요 ISP 공인 대역 (오탐 방지용 최우선 신뢰 매핑)
# KT, SK브로드밴드, LG U+, 카카오/드림라인/CJ 등
KNOWN_KR_RANGES = [
    "121.53.0.0/16",   # 카카오/드림라인 (이미지 오류 대역)
    "121.128.0.0/11",  # KT
    "175.112.0.0/12",  # KT
    "175.192.0.0/11",  # KT
    "112.160.0.0/11",  # SKB
    "211.234.0.0/16",  # 카카오/다음
    "211.246.0.0/16",  # 카카오
    "27.113.0.0/16",   # 카카오
    "203.133.160.0/19" # 카카오
]

class GeoIPLookup:
    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()
        self._load_cache()

    def _load_cache(self):
        if os.path.exists(GEO_CACHE_FILE):
            try:
                with open(GEO_CACHE_FILE, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
            except Exception:
                self.cache = {}

    def _save_cache(self):
        try:
            with open(GEO_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False)
        except Exception:
            pass

    def get_country(self, ip_str: str) -> str:
        """
        IP의 국가 코드를 반환합니다.
        광범위한 하드코딩 서브넷에 의한 오탐을 없애고,
        실시간 온라인 GeoIP 정밀 조회 및 로컬 캐시를 최우선 적용합니다.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                return "LOCAL"
        except Exception:
            return "UNKNOWN"

        # 1. 로컬 캐시 확인
        with self.lock:
            if ip_str in self.cache:
                return self.cache[ip_str]

        # 2. 한국 주요 대역 오탐 방지 체크
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for kr_cidr in KNOWN_KR_RANGES:
                if ip_obj in ipaddress.ip_network(kr_cidr):
                    with self.lock:
                        self.cache[ip_str] = "KR"
                        self._save_cache()
                    return "KR"
        except Exception:
            pass

        # 3. 실시간 공인 GeoIP API 정밀 조회 (ip-api.com)
        try:
            url = f"http://ip-api.com/json/{ip_str}?fields=status,countryCode"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                if data.get("status") == "success":
                    country = data.get("countryCode", "UNKNOWN")
                    with self.lock:
                        self.cache[ip_str] = country
                        self._save_cache()
                    return country
        except Exception:
            pass

        return "UNKNOWN"
