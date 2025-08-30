# app/app.py — CyberNOVA: SpaceShield (PyDeck + Inject + Demo Login)

import os, json, datetime, pandas as pd, yaml, streamlit as st
import requests, pydeck as pdk
from streamlit_autorefresh import st_autorefresh

# Optional helpers (safe to miss)
try:
    from .auth import find_user, verify_password  # not used in demo login
except Exception:
    pass
try:
    from .impact import impact_from_alert
    from .anomaly_ml import MLAnomalyDetector
except Exception:
    impact_from_alert = lambda a: {}
    class MLAnomalyDetector: pass

# ---------------- PATHS ----------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR   = os.path.dirname(SCRIPT_DIR)
DATA_DIR   = os.path.join(BASE_DIR, "data")
CONFIG_PATH= os.path.join(BASE_DIR, "config.yaml")

LIVE_FEED_FILE    = os.path.join(DATA_DIR, "live_feed_data.json")
LIVE_ALERTS_FILE  = os.path.join(DATA_DIR, "live_alerts.json")
NASA_FEED_FILE    = os.path.join(DATA_DIR, "nasa_live_feed_data.json")
NASA_ALERTS_FILE  = os.path.join(DATA_DIR, "nasa_live_alerts.json")
AV_FILE           = os.path.join(DATA_DIR, "opensky_live.json")
MAR_FILE          = os.path.join(DATA_DIR, "maritime_sample.json")
TRAILS_FILE       = os.path.join(DATA_DIR, "aviation_trails.json")

BASE_LAT, BASE_LON = 33.8953, 35.4744

# ---------------- PAGE CONFIG ----------------
st.set_page_config(layout="wide", page_title="CyberNOVA: SpaceShield — Mission Control")

# ---------------- THEME CSS (optional file) ----------------
css_path = os.path.join(SCRIPT_DIR, "theme.css")
if os.path.exists(css_path):
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ---------------- MAP BASE ----------------
MAPBOX_TOKEN = os.getenv("MAPBOX_TOKEN", "")
if MAPBOX_TOKEN:
    pdk.settings.mapbox_api_key = MAPBOX_TOKEN
    MAP_STYLE = "mapbox://styles/mapbox/dark-v11"
else:
    MAP_STYLE = "https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json"

# ---------------- UTILS ----------------
def load_json(path, default):
    try:
        if not os.path.exists(path): return default
        with open(path, 'r', encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json_atomic(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def inject_alert(source, severity, type_, description):
    alerts = load_json(LIVE_ALERTS_FILE, [])
    new_alert = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "source": source,
        "severity": severity,
        "type": type_,
        "description": description
    }
    alerts.append(new_alert)
    save_json_atomic(LIVE_ALERTS_FILE, alerts)
    st.success(f"Injected: {type_} ({severity})")

# --------- OpenSky fetch + trails for Deck.gl ----------
def fetch_opensky_over_lebanon(timeout=6):
    """Return list of dicts with lon, lat, callsign from OpenSky within Lebanon bbox."""
    url = "https://opensky-network.org/api/states/all"
    params = {"lamin": 33.0, "lomin": 35.0, "lamax": 34.8, "lomax": 36.7}
    try:
        r = requests.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        states = data.get("states", []) or []
        rows = []
        for sv in states:
            if isinstance(sv, list) and len(sv) >= 7:
                lon, lat = sv[5], sv[6]
                if isinstance(lon, (int,float)) and isinstance(lat, (int,float)):
                    callsign = (sv[1] or "N/A").strip() if isinstance(sv[1], str) else "N/A"
                    rows.append({"lon": float(lon), "lat": float(lat), "callsign": callsign})
        return rows
    except Exception:
        # Fallback to cached file if available
        av = load_json(AV_FILE, {"states": []})
        rows = []
        for sv in av.get("states", []):
            if isinstance(sv, list) and len(sv) >= 7 and isinstance(sv[5], (int,float)) and isinstance(sv[6], (int,float)):
                callsign = (sv[1] or "N/A").strip() if isinstance(sv[1], str) else "N/A"
                rows.append({"lon": float(sv[5]), "lat": float(sv[6]), "callsign": callsign})
        return rows

def update_aviation_trails(states_like):
    """Update short trails from a minimal states list => saves to TRAILS_FILE as [lat,lon,ts]."""
    trails = load_json(TRAILS_FILE, {})
    now = datetime.datetime.utcnow().isoformat() + "Z"
    def add_point(key, lat, lon):
        if key not in trails: trails[key] = []
        trails[key].append([lat, lon, now])
        trails[key] = trails[key][-20:]
    for sv in states_like[:200]:
        try:
            lat, lon = sv[6], sv[5]  # positions as crafted below
            callsign = (sv[1] or "N/A").strip() if isinstance(sv[1], str) else "N/A"
            if lat is None or lon is None: continue
            if not (33.0 <= lat <= 34.8 and 35.0 <= lon <= 36.7): continue
            add_point(callsign, float(lat), float(lon))
        except Exception:
            continue
    save_json_atomic(TRAILS_FILE, trails)
    return trails

def trails_for_deck():
    trails = load_json(TRAILS_FILE, {})
    paths = []
    for key, pts in trails.items():
        path = []
        for p in pts:
            try:
                lat, lon = float(p[0]), float(p[1])
                if 33.0 <= lat <= 34.8 and 35.0 <= lon <= 36.7:
                    path.append([lon, lat])  # deck.gl needs [lon,lat]
            except Exception:
                pass
        if len(path) >= 2:
            paths.append({"callsign": key, "path": path})
    return paths

def lebanon_risk_polygon(sev_key):
    if sev_key not in ("med","high","crit"): return []
    import math
    center = (BASE_LAT, BASE_LON); R_km = 8
    coords = []
    for deg in range(0, 360, 8):
        rad = math.radians(deg)
        dlat = (R_km / 110.574) * math.sin(rad)
        dlon = (R_km / (111.320 * math.cos(math.radians(center[0])))) * math.cos(rad)
        coords.append([center[1] + dlon, center[0] + dlat])
    return [{"polygon": coords, "name": "Beirut Risk Glow"}]

def gps_spoof_markers_from_alerts(alerts):
    out = []
    for a in alerts[-30:]:
        if str(a.get("type","")).lower().startswith("gps"):
            out.append({"lon": BASE_LON, "lat": BASE_LAT, "label": "GPS Spoof"})
    return out

# ---------------- LOGIN / WELCOME (Demo mode) ----------------
def login_page():
    st.markdown("<h2>🔐 CyberNOVA: SpaceShield — Login</h2>", unsafe_allow_html=True)
    with st.form("login_form", clear_on_submit=False):
        u = st.text_input("Username", placeholder="demo_user")
        p = st.text_input("Password", type="password", placeholder="••••••••")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        username = (u.strip() or "demo")
        st.session_state["auth"] = {"username": username, "name": username.capitalize(), "role": "analyst"}
        st.session_state["entered"] = False
        st.experimental_rerun()

def welcome_page():
    user = st.session_state.get("auth", {})
    st.markdown(f"<h2>Welcome, {user.get('name','Operator')}</h2>", unsafe_allow_html=True)
    st.markdown("This is your converged space–cyber mission control.")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("🚀 Launch Mission Control", use_container_width=True):
            st.session_state["entered"] = True
            st.experimental_rerun()
    with c2:
        if st.button("🔓 Sign out", use_container_width=True):
            st.session_state.clear()
            st.experimental_rerun()

# ---------------- ENTRY FLOW ----------------
if "auth" not in st.session_state:
    login_page(); st.stop()
if not st.session_state.get("entered"):
    welcome_page(); st.stop()

# ---------------- HEADER ----------------
st.markdown("<h1>🛰️ CyberNOVA: SpaceShield — Mission Control</h1>", unsafe_allow_html=True)
st.caption("See the Storm • Stop the Threat")

# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.markdown("## ⚙️ Controls")
    refresh_ms = st.slider("Auto-refresh (ms)", 5000, 30000, 12000, step=1000)
    st.markdown("---")
    if st.button("🔓 Sign out", use_container_width=True):
        st.session_state.clear(); st.experimental_rerun()

# ---------------- LOAD DATA ----------------
sim_feed    = load_json(LIVE_FEED_FILE, [])
sim_alerts  = load_json(LIVE_ALERTS_FILE, [])
nasa_feed   = load_json(NASA_FEED_FILE, [])
nasa_alerts = load_json(NASA_ALERTS_FILE, [])
aviation    = load_json(AV_FILE, {"states":[]})
maritime    = load_json(MAR_FILE, {"ships":[]})
all_alerts  = (sim_alerts or []) + (nasa_alerts or [])

# ---------------- THREAT & TRIAGE ----------------
def triage_table(alerts):
    if not alerts: return st.info("No alerts now.")
    df = pd.DataFrame(alerts)
    cols = [c for c in ["timestamp","source","severity","type","description"] if c in df.columns]
    if not cols: cols = list(df.columns)
    df = df[cols].sort_values("timestamp", ascending=False)
    st.dataframe(df, width="stretch")

def threat_level(alerts):
    order={"INFO":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    if not alerts: return "ok","All Systems Normal"
    sev=max(alerts,key=lambda a:order.get(a.get("severity","LOW"),1)).get("severity","LOW")
    key={"CRITICAL":"crit","HIGH":"high","MEDIUM":"med","LOW":"low"}.get(sev,"ok")
    label={"CRITICAL":"Critical Threat","HIGH":"High Threat","MEDIUM":"Elevated","LOW":"Low","INFO":"Low"}.get(sev,"Low")
    return key,label

sev_key, sev_label = threat_level(all_alerts)
st.markdown(f"""
<div class="status-bar">
  <div class="badge {sev_key}">{sev_label}</div>
  <div style="color:#8aa4b0">GPS • Network • Commands • Space Weather • Aviation</div>
</div>
""", unsafe_allow_html=True)

# ---------------- TICKER + SPARKLINE ----------------
msgs=[f"[{a.get('timestamp','')}] {a.get('type','?')} — {a.get('severity','')}" for a in all_alerts[-6:][::-1]]
ticker_text="  •  ".join(msgs) if msgs else "All systems nominal • Listening across GPS • Network • Space Weather"
st.markdown(f"""
<div style='overflow:hidden;white-space:nowrap;background:rgba(0,0,0,.4);border:1px solid #00f5d466;border-radius:999px;padding:4px 12px;color:#b7fff2;'>
  <marquee scrollamount="5">{ticker_text}</marquee>
</div>
""", unsafe_allow_html=True)

pkt=[i.get("packet_count") for i in sim_feed if i.get("feed_type")=="NETWORK_TRAFFIC" and isinstance(i.get("packet_count"),(int,float))]
if len(pkt)>=5: st.line_chart(pkt[-60:], height=60, width=420)

# ---------------- FLOATING INJECT BUTTONS ----------------
st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
cA,cB,cC=st.columns(3)
with cA:
    if st.button("🚨 GPS Spoof", key="inj_gps"):
        inject_alert("Simulator","HIGH","GPS Spoofing","GPS coordinates near Beirut Airport manipulated.")
with cB:
    if st.button("☀️ Solar Flare", key="inj_solar"):
        inject_alert("NASA/NOAA","CRITICAL","Solar Flare","Solar flare detected — comms disruption possible.")
with cC:
    if st.button("🌐 DDoS", key="inj_ddos"):
        inject_alert("Network Monitor","MEDIUM","DDoS Anomaly","Unusual network spike detected.")
        feed = load_json(LIVE_FEED_FILE, [])
        feed.append({
            "timestamp": datetime.datetime.utcnow().isoformat()+"Z",
            "feed_type": "NETWORK_TRAFFIC",
            "packet_count": 50000, "data_volume_kb": 250000,
            "src": "192.168.1.100", "dst": "10.0.0.5"
        })
        save_json_atomic(LIVE_FEED_FILE, feed)

# ---------------- TABS ----------------
tabs = st.tabs(["Lebanon Mission Map","Space Weather","Live Feed"])

with tabs[0]:
    st.subheader("Lebanon Mission View")
    col1,col2 = st.columns([1.2,1])
    with col1:
        # Real flights
        flights = fetch_opensky_over_lebanon()
        synth_states=[]
        for f in flights:
            # minimal state row: [0]=None, [1]=callsign, [5]=lon, [6]=lat
            synth_states.append([None, f["callsign"], None, None, None, f["lon"], f["lat"]])
        update_aviation_trails(synth_states)
        paths = trails_for_deck()

        df_flights = pd.DataFrame(flights) if flights else pd.DataFrame(columns=["lon","lat","callsign"])
        ships=[]
        for s in maritime.get("ships", []):
            if isinstance(s.get("lat"),(int,float)) and isinstance(s.get("lon"),(int,float)):
                ships.append({"lon": float(s["lon"]), "lat": float(s["lat"]), "name": s.get("name","Vessel")})
        df_ships = pd.DataFrame(ships) if ships else pd.DataFrame(columns=["lon","lat","name"])
        df_spoof = pd.DataFrame(gps_spoof_markers_from_alerts(all_alerts))
        df_glow  = pd.DataFrame(lebanon_risk_polygon(sev_key))

        layers=[]
        if paths:
            layers.append(pdk.Layer("PathLayer", data=paths, get_path="path",
                                    get_color=[0,245,212,160], width_scale=1, width_min_pixels=2,
                                    rounded=True, opacity=0.7))
        if not df_flights.empty:
            layers.append(pdk.Layer("ScatterplotLayer", data=df_flights, get_position=["lon","lat"],
                                    get_radius=2000, pickable=True, opacity=0.9, stroked=False,
                                    filled=True, get_fill_color=[0,245,212,220]))
        if not df_ships.empty:
            layers.append(pdk.Layer("ScatterplotLayer", data=df_ships, get_position=["lon","lat"],
                                    get_radius=2200, pickable=True, opacity=0.9, stroked=False,
                                    filled=True, get_fill_color=[70,231,255,200]))
        if not df_spoof.empty:
            layers.append(pdk.Layer("ScatterplotLayer", data=df_spoof, get_position=["lon","lat"],
                                    get_radius=2600, pickable=False, opacity=0.85,
                                    filled=True, get_fill_color=[255,51,102,220]))
        if not df_glow.empty:
            layers.append(pdk.Layer("PolygonLayer", data=df_glow, get_polygon="polygon", stroked=False,
                                    get_fill_color=[255,51,102,45] if sev_key=="crit" else [255,209,102,35],
                                    opacity=0.5))

        view_state = pdk.ViewState(latitude=33.9, longitude=35.6, zoom=7.8, pitch=35, bearing=5)
        deck = pdk.Deck(map_style=MAP_STYLE, initial_view_state=view_state, layers=layers,
                        tooltip={"html":"<b>{callsign}</b>"} if not df_flights.empty else None)
        st.pydeck_chart(deck)

    with col2:
        st.subheader("Triage — Active Alerts")
        triage_table(all_alerts)

with tabs[1]:
    st.subheader("NASA Space Weather — Recent Events")
    if nasa_feed:
        df = pd.DataFrame(nasa_feed)
        show = [c for c in ["timestamp","event_type"] if c in df.columns]
        st.dataframe(df[show].sort_values("timestamp", ascending=False), width="stretch")
    else:
        st.info("No NASA events (check NASA_API_KEY).")
    st.subheader("NASA-derived Alerts")
    triage_table(nasa_alerts)

with tabs[2]:
    st.subheader("Live Data Feed — Simulator")
    if sim_feed:
        df = pd.DataFrame(sim_feed).sort_values("timestamp", ascending=False)
        st.dataframe(df, width="stretch")
    else:
        st.info("Waiting for simulator data...")

# ---------------- AUTO REFRESH ----------------
st_autorefresh(interval=refresh_ms, key="auto-refresh-ui")
