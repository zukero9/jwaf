import ipaddress
import urllib.request
import json
import os
import threading

GEO_CACHE_FILE = os.path.join(os.path.dirname(__file__), "geoip_cache.json")

KNOWN_KR_RANGES = [
    "121.53.0.0/16",
    "121.128.0.0/11",
    "175.112.0.0/12",
    "175.192.0.0/11",
    "112.160.0.0/11",
    "211.234.0.0/16",
    "211.246.0.0/16",
    "27.113.0.0/16",
    "203.133.160.0/19"
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
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                return "LOCAL"
        except Exception:
            return "UNKNOWN"

        with self.lock:
            if ip_str in self.cache:
                return self.cache[ip_str]

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

