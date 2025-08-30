import os, json, time, requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(BASE_DIR, "data")

LIVE_AVIATION_PATH = os.path.join(DATA_DIR, "opensky_live.json")
FALLBACK = os.path.join(DATA_DIR, "opensky_sample.json")

HEADERS = {"User-Agent": "CyberNOVA-SpaceShield/1.0 (+demo)"}
# Lebanon-ish bounding box (tightens payload, improves success for anonymous)
BBOX = {"lamin": 33.0, "lomin": 35.0, "lamax": 34.7, "lomax": 36.7}

def load_json(path, default):
    try:
        if not os.path.exists(path): return default
        with open(path, 'r') as f: return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def fetch_opensky():
    url = "https://opensky-network.org/api/states/all"
    try:
        r = requests.get(url, params=BBOX, headers=HEADERS, timeout=12)
        r.raise_for_status()
        j = r.json()
        # Ensure structure has 'states' and it's a list; else treat as fail
        if not isinstance(j, dict) or not isinstance(j.get("states"), list):
            return None
        return j
    except Exception as e:
        print("[OpenSky] fetch error:", e)
        return None

def run():
    print("[OpenSky] Aviation ingest starting.")
    while True:
        data = fetch_opensky()
        if not data:
            print("[OpenSky] Using fallback sample.")
            data = load_json(FALLBACK, {})
        save_json(LIVE_AVIATION_PATH, data)
        time.sleep(60)

if __name__ == "__main__":
    run()
