import os, json, time, datetime, requests
from dotenv import load_dotenv

load_dotenv()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(BASE_DIR, "data")

LIVE_SWPC_PATH = os.path.join(DATA_DIR, "noaa_swpc.json")
FALLBACK = os.path.join(DATA_DIR, "noaa_swpc_sample.json")

def load_json(path, default):
    try:
        if not os.path.exists(path): return default
        with open(path, 'r') as f: return json.load(f)
    except Exception: return default

def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def fetch_swpc():
    try:
        r = requests.get("https://services.swpc.noaa.gov/products/summary.json", timeout=10)
        r.raise_for_status()
        return {
            "ts": datetime.datetime.utcnow().isoformat()+"Z",
            "summary": r.json()
        }
    except Exception as e:
        print("[SWPC] fetch error:", e)
        return None

def run():
    print("[SWPC] NOAA ingest starting.")
    while True:
        data = fetch_swpc()
        if not data:
            print("[SWPC] Using local fallback sample.")
            data = load_json(FALLBACK, {})
        save_json(LIVE_SWPC_PATH, data)
        time.sleep(300)  # every 5 minutes

if __name__ == "__main__":
    run()
