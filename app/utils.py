import hashlib, math, datetime, uuid

def sha1_fingerprint(*parts: str) -> str:
    h = hashlib.sha1()
    for p in parts:
        h.update((p or '').encode('utf-8'))
    return h.hexdigest()

def haversine_m(lat1, lon1, lat2, lon2):
    R = 6371000.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def uuid_str():
    return str(uuid.uuid4())
