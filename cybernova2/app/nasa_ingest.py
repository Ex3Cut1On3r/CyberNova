import os, json, time, datetime, requests, yaml
from typing import List, Dict
from .utils import sha1_fingerprint, now_iso, uuid_str
from .alert_schema import Alert

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(BASE_DIR, "data")
CONFIG_PATH = os.path.join(BASE_DIR, "config.yaml")

with open(CONFIG_PATH, 'r') as f:
    CFG = yaml.safe_load(f)

LIVE_FEED_PATH = os.path.join(DATA_DIR, "nasa_live_feed_data.json")
ALERTS_PATH = os.path.join(DATA_DIR, "nasa_live_alerts.json")

DONKI_BASE = "https://api.nasa.gov/DONKI"
NASA_API_KEY = os.getenv("NASA_API_KEY")

def load_json(path, default):
    try:
        if not os.path.exists(path):
            return default
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def build_alert(typ, desc, labels=None):
    ts = now_iso()
    fp = sha1_fingerprint("DONKI", typ, desc, ts[:16])
    return Alert(
        id=uuid_str(), source="DONKI", type=typ, severity=severity_from_type(typ),
        timestamp=ts, labels=labels or {}, description=desc, fingerprint=fp
    ).model_dump()

def severity_from_type(t: str) -> str:
    # Basic mapping; refine as needed
    m = {
        "Solar Flare": "MEDIUM",
        "CME": "HIGH",
        "Geomagnetic Storm": "HIGH",
        "Radiation Storm": "HIGH",
        "Rate Anomaly": "LOW",
    }
    return m.get(t, "LOW")

def fetch_or_fallback(endpoint: str, params: Dict):
    if NASA_API_KEY:
        try:
            params = dict(params); params["api_key"] = NASA_API_KEY
            r = requests.get(f"{DONKI_BASE}/{endpoint}", params=params, timeout=10)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            print("[DONKI] API error, using fallback:", e)
    # fallback to local
    data = load_json(LIVE_FEED_PATH, [])
    # filter by 'event_type'
    return [d for d in data if d.get("event_type")==endpoint]

def run():
    feed = load_json(LIVE_FEED_PATH, [])
    alerts = load_json(ALERTS_PATH, [])

    print("[DONKI] NASA ingest starting. API key set?" , bool(NASA_API_KEY))
    while True:
        now = datetime.datetime.utcnow()
        start_date = (now - datetime.timedelta(days=3)).strftime("%Y-%m-%d")
        params = {"startDate": start_date}

        # fetch various
        flr = fetch_or_fallback("FLR", params)
        cme = fetch_or_fallback("CME", params)
        gst = fetch_or_fallback("GST", params)
        sep = fetch_or_fallback("SEP", params)
        rbe = fetch_or_fallback("RBE", params)

        new_items = []
        def add_items(label, items):
            for it in items:
                it2 = {"event_type": label, "timestamp": now_iso(), "raw": it}
                new_items.append(it2)

        add_items("FLR", flr); add_items("CME", cme); add_items("GST", gst); add_items("SEP", sep); add_items("RBE", rbe)

        # append limited
        feed.extend(new_items); feed = feed[-CFG['retention']['max_feed_items']:]

        # simple rate anomaly alert
        rate = len(new_items)
        if rate >= CFG['nasa']['events_per_hour_threshold']:
            alerts.append(build_alert("Rate Anomaly", f"{rate} space-weather events in the last pull", {"rate": str(rate)}))
            alerts = alerts[-CFG['retention']['max_alerts']:]
        save_json(LIVE_FEED_PATH, feed); save_json(ALERTS_PATH, alerts)
        time.sleep(60)

if __name__ == "__main__":
    run()
