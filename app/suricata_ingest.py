import os, json, time, datetime

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
EVE_PATH = os.path.join(DATA_DIR, "suricata", "eve.json")
HOST_EVENTS_PATH = os.path.join(DATA_DIR, "host_isolation_events.json")

def load_json(path, default):
    try:
        if not os.path.exists(path): return default
        with open(path, "r", encoding="utf-8") as f: return json.load(f)
    except Exception:
        return default

def save_json_atomic(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def parse_alert(line):
    try:
        obj = json.loads(line)
    except Exception:
        return None
    if obj.get("event_type") != "alert":
        return None
    al = obj.get("alert", {})
    prio = al.get("priority") or al.get("severity") or 2
    sev = {1:"HIGH",2:"MEDIUM",3:"LOW"}.get(int(prio), "MEDIUM")
    src = obj.get("src_ip"); dst = obj.get("dest_ip")
    reason = f'{al.get("signature")} (SID {al.get("signature_id")})'
    return {
        "timestamp": obj.get("timestamp") or datetime.datetime.utcnow().isoformat()+"Z",
        "host": src, "src": src, "dst": dst,
        "severity": sev, "priority": int(prio),
        "reason": reason
    }

def tail_eve():
    print("[IDS] Suricata ingest running, monitoring eve.json:", EVE_PATH, flush=True)
    events = load_json(HOST_EVENTS_PATH, [])
    last_size = 0
    while True:
        try:
            if os.path.exists(EVE_PATH):
                sz = os.path.getsize(EVE_PATH)
                if sz != last_size:
                    last_size = sz
                    with open(EVE_PATH, "r", encoding="utf-8") as f:
                        for line in f:
                            ev = parse_alert(line.strip())
                            if ev: events.append(ev)
                    save_json_atomic(HOST_EVENTS_PATH, events[-500:])
            time.sleep(2)
        except Exception as e:
            print("[IDS] error:", e, flush=True)
            time.sleep(2)

if __name__ == "__main__":
    tail_eve()
