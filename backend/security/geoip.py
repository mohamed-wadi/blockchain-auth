"""
Géolocalisation des IPs pour la carte d'attaques
CHOC JURY: carte mondiale en temps réel
"""
import requests
import time

_cache = {}

def get_ip_location(ip):
    """Retourne lat/lon/pays d'une IP via api gratuite"""
    if ip in _cache:
        cached = _cache[ip]
        if time.time() - cached["ts"] < 3600:
            return cached["data"]

    if ip in ["127.0.0.1", "::1", "localhost"]:
        return {"lat": 33.5731, "lon": -7.5898, "country": "MA", "city": "Casablanca"}

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=lat,lon,country,countryCode,city",
            timeout=3
        )
        data = r.json()
        result = {
            "lat": data.get("lat", 0),
            "lon": data.get("lon", 0),
            "country": data.get("countryCode", "??"),
            "city": data.get("city", "Unknown")
        }
        _cache[ip] = {"data": result, "ts": time.time()}
        return result
    except Exception:
        return {"lat": 0, "lon": 0, "country": "??", "city": "Unknown"}