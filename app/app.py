# app/app.py — Mission Control (Lebanon view + Host Isolation panel)
import os, json, datetime, pandas as pd, yaml, streamlit as st
import folium
from streamlit_folium import st_folium
from streamlit_autorefresh import st_autorefresh

# --- paths ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR   = os.path.dirname(SCRIPT_DIR)
DATA_DIR   = os.path.join(BASE_DIR, "data")
CONFIG     = os.path.join(BASE_DIR, "config.yaml")

# --- data files ---
LIVE_FEED_FILE    = os.path.join(DATA_DIR, "live_feed_data.json")
LIVE_ALERTS_FILE  = os.path.join(DATA_DIR, "live_alerts.json")
NASA_FEED_FILE    = os.path.join(DATA_DIR, "nasa_live_feed_data.json")
NASA_ALERTS_FILE  = os.path.join(DATA_DIR, "nasa_live_alerts.json")
HOST_EVENTS_FILE  = os.path.join(DATA_DIR, "host_isolation_events.json")
ISOL_STATE_FILE   = os.path.join(DATA_DIR, "isolation_state.json")
ASSETS_FILE       = os.path.join(DATA_DIR, "assets.json")

# --- imports for isolation controller ---
try:
    from .isolation_controller import isolate_host, release_host, read_isolation_state
except Exception:
    # fallback if run as "streamlit run app/app.py"
    from isolation_controller import isolate_host, release_host, read_isolation_state

# --- helpers ---
def load_json(path, default):
    """Loads a JSON file, returning a default value on error or if the file doesn't exist."""
    try:
        if not os.path.exists(path): return default
        with open(path, "r", encoding="utf-8") as f: return json.load(f)
    except Exception as e:
        st.error(f"Error loading {path}: {e}")
        return default

def save_json_atomic(path, obj):
    """Saves a JSON object to a file atomically to prevent data corruption."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception as e:
        st.error(f"Error saving {path}: {e}")

# --- UI config ---
st.set_page_config(layout="wide", page_title="CyberNOVA: SpaceShield — Mission Control")
st.markdown("<h1>🛰️ CyberNOVA: SpaceShield — Mission Control</h1>", unsafe_allow_html=True)
st.caption("See the Storm • Stop the Threat")

# --- sidebar ---
with st.sidebar:
    st.markdown("## ⚙️ Controls")
    refresh_ms = st.slider("Auto-refresh (ms)", 5000, 30000, 12000, step=1000)
    st.write("Isolation mode:", os.environ.get("ISOLATION_MODE", "sim"))
    st.markdown("---")
    st.write("Use `docker compose up --build` for full stack.")
    st.markdown("---")
    st.write("Ports: UI 8501 • Events 8080")

# --- load data ---
sim_feed    = load_json(LIVE_FEED_FILE, [])
sim_alerts  = load_json(LIVE_ALERTS_FILE, [])
nasa_feed   = load_json(NASA_FEED_FILE, [])
nasa_alerts = load_json(NASA_ALERTS_FILE, [])
host_events = load_json(HOST_EVENTS_FILE, [])        # from Suricata ingest (normalized)
assets_doc  = load_json(ASSETS_FILE, {"assets": []})
assets      = assets_doc.get("assets", [])
isol_state  = read_isolation_state(ISOL_STATE_FILE)

# --- threat level / triage ---
def triage_table(alerts, title="Triage — Active Alerts"):
    """Displays a sortable table of alerts."""
    st.subheader(title)
    if not alerts:
        st.info("No alerts at the moment.")
        return
    df = pd.DataFrame(alerts)
    # try common columns first
    cols_order = [c for c in ["timestamp", "source", "severity", "type", "host", "reason", "description"] if c in df.columns]
    df = df[cols_order] if cols_order else df
    # sort by timestamp if available
    if "timestamp" in df.columns:
        df = df.sort_values("timestamp", ascending=False)
    st.dataframe(df, use_container_width=True)

def threat_level(all_alerts):
    """Calculates and returns the overall threat level based on the highest severity alert."""
    order = {"INFO":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    if not all_alerts: return "ok", "All Systems Normal"
    sev = max(all_alerts, key=lambda a: order.get(a.get("severity","LOW"),1)).get("severity","LOW")
    key = {"CRITICAL":"crit","HIGH":"high","MEDIUM":"med","LOW":"low"}.get(sev,"ok")
    label = {"CRITICAL":"Critical Threat","HIGH":"High Threat","MEDIUM":"Elevated","LOW":"Low","INFO":"Low"}.get(sev,"Low")
    return key, label

# merge alerts for quick overview
merged_alerts = []
if sim_alerts:   merged_alerts.extend(sim_alerts)
if nasa_alerts:  merged_alerts.extend(nasa_alerts)
if host_events:  merged_alerts.extend(host_events)

sev_key, sev_label = threat_level(merged_alerts)
st.markdown(f"""
<div style="
  display:flex;align-items:center;gap:12px;
  padding:10px 14px;border-radius:12px;
  background:linear-gradient(90deg, rgba(0,245,212,.08), rgba(0,0,0,.1));
  border:1px solid rgba(0,245,212,.25);
  ">
  <div style="font-weight:600;color:#00f5d4;">STATUS:</div>
  <div style="padding:4px 10px;border-radius:8px;background:#0a1214;color:#b7fff2;border:1px solid rgba(0,245,212,.2)">
    {sev_label}
  </div>
  <div style="color:#7dbdb4">GPS • Network • Space Weather • IDS</div>
</div>
""", unsafe_allow_html=True)

st.markdown("<br/>", unsafe_allow_html=True)

# --- Create tabs ---
tab_mission, tab_feeds, tab_alerts = st.tabs(["Mission Control", "Live Feeds", "Alerts & Triage"])

with tab_mission:
    # --- layout: Lebanon Map (left) + Host Isolation (right) ---
    c_map, c_hosts = st.columns([1.1, 1])

    with c_map:
        st.subheader("Lebanon Mission View")
        # Using a dark theme for the map to match the dashboard's aesthetic
        m = folium.Map(location=[33.9, 35.6], zoom_start=8, tiles="CartoDB dark_matter")
        st_folium(m, width=720, height=420)

    with c_hosts:
        st.subheader("Host Isolation — Control Panel")

        if not assets:
            st.info("No assets defined. Create data/assets.json to register hosts.")
        else:
            # Show assets with isolate/release buttons
            for asset in assets:
                name = asset.get("name","Asset")
                ips  = asset.get("ips", [])
                ip   = ips[0] if ips else None
                seg  = asset.get("segment","")
                typ  = asset.get("type","")
                if not ip:
                    continue

                status = isol_state.get(ip, {}).get("status", "released")
                ts     = isol_state.get(ip, {}).get("ts", "")
                reason = isol_state.get(ip, {}).get("reason", "")

                badge = "🟢 Released" if status != "isolated" else "🔴 Isolated"
                st.markdown(f"**{name}** — `{ip}`  ·  *{seg or 'segment'}* · *{typ or 'type'}* ·  {badge}")

                cc1, cc2, cc3 = st.columns([1,1,2])
                with cc1:
                    if st.button(f"Isolate {ip}", key=f"isolate_{ip}"):
                        try:
                            res = isolate_host(ip, reason="Operator action via UI", state_path=ISOL_STATE_FILE)
                            st.success(res)
                        except Exception as e:
                            st.error(f"Failed to isolate host: {e}")
                        st.rerun()
                with cc2:
                    if st.button(f"Release {ip}", key=f"release_{ip}"):
                        try:
                            res = release_host(ip, state_path=ISOL_STATE_FILE)
                            st.success(res)
                        except Exception as e:
                            st.error(f"Failed to release host: {e}")
                        st.rerun()
                with cc3:
                    if status == "isolated":
                        st.caption(f"Reason: {reason} • {ts}")

        st.markdown("---")
        # Show latest host IDS events (if any)
        if host_events:
            triage_table(host_events[-50:], title="Live IDS — Latest Host Events")
        else:
            st.info("No host IDS events yet. When Suricata writes eve.json → ingest will populate this.")

with tab_feeds:
    st.subheader("Live Feed Data")
    if sim_feed:
        st.info("Live data from the simulated GNSS system.")
        st.dataframe(pd.DataFrame(sim_feed), use_container_width=True)
    else:
        st.info("No simulated live feed data available.")

    st.markdown("---")

    st.subheader("NASA Live Feed Data")
    if nasa_feed:
        st.info("Real-time data from NASA.")
        st.dataframe(pd.DataFrame(nasa_feed), use_container_width=True)
    else:
        st.info("No NASA live feed data available.")

with tab_alerts:
    # --- global triage table (optional)
    triage_table(merged_alerts[-100:], title="Global Triage (Space + Sim + IDS)")
    st.info("This table combines all alerts from simulated, NASA, and host IDS feeds.")


# --- auto refresh only lightweight state (not the whole page loop-crazy)
st_autorefresh(interval=refresh_ms, key="auto-refresh-ui")
