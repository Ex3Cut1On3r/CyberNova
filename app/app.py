# app/app.py — Mission Control (Modern UI with Stunning Visual Design)
import os, json, datetime, pandas as pd, yaml, streamlit as st
import random

import folium
from streamlit_folium import st_folium
from streamlit_autorefresh import st_autorefresh
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta

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

# --- Threat simulation functions ---
def generate_threat_alert(threat_type, severity="HIGH", target_ip="192.168.56.101"):
    """Generate a simulated threat alert"""
    import random

    threat_templates = {
        "gps_spoofing": {
            "type": "GPS Spoofing",
            "description": "Malicious GPS signal injection detected - coordinates being manipulated",
            "source": "GNSS Monitor",
            "reason": "Suspicious coordinate deviation beyond threshold",
            "details": f"Fake GPS signals targeting receiver at {target_ip}"
        },
        "jamming": {
            "type": "Signal Jamming",
            "description": "Radio frequency jamming attack in progress",
            "source": "RF Analyzer",
            "reason": "Abnormal signal attenuation detected",
            "details": f"Broadband interference affecting multiple frequencies near {target_ip}"
        },
        "malware": {
            "type": "Malware Detection",
            "description": "Suspicious executable behavior detected on host system",
            "source": "IDS Engine",
            "reason": "Process injection and network anomaly detected",
            "details": f"Potentially malicious process spawned on {target_ip}"
        },
        "ddos": {
            "type": "DDoS Attack",
            "description": "Distributed denial of service attack targeting critical infrastructure",
            "source": "Network Monitor",
            "reason": "Traffic volume exceeded normal threshold by 400%",
            "details": f"Coordinated attack from multiple sources targeting {target_ip}"
        },
        "data_exfil": {
            "type": "Data Exfiltration",
            "description": "Unauthorized data transfer detected to external destination",
            "source": "DLP System",
            "reason": "Large file transfers to suspicious external IP",
            "details": f"Sensitive data being transmitted from {target_ip} to unknown endpoint"
        },
        "insider_threat": {
            "type": "Insider Threat",
            "description": "Unusual privileged access patterns detected",
            "source": "Behavior Analytics",
            "reason": "User accessing restricted resources outside normal hours",
            "details": f"Administrative account anomaly detected from {target_ip}"
        },
        "zero_day": {
            "type": "Zero-Day Exploit",
            "description": "Unknown exploit pattern targeting system vulnerabilities",
            "source": "Threat Intel",
            "reason": "Novel attack signature not in database",
            "details": f"Previously unseen exploit attempt against {target_ip}"
        }
    }

    template = threat_templates.get(threat_type, threat_templates["malware"])

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": severity,
        "type": template["type"],
        "description": template["description"],
        "source": template["source"],
        "host": target_ip,
        "reason": template["reason"],
        "details": template["details"],
        "id": f"ALERT_{random.randint(1000, 9999)}",
        "status": "active"
    }

def inject_threat(threat_type, severity="HIGH"):
    """Inject a threat into the appropriate data file"""
    alert = generate_threat_alert(threat_type, severity)

    # Determine which file to update based on threat type
    if threat_type in ["gps_spoofing", "jamming"]:
        # Space/GNSS related threats go to sim alerts
        alerts = load_json(LIVE_ALERTS_FILE, [])
        alerts.append(alert)
        save_json_atomic(LIVE_ALERTS_FILE, alerts)

        # Also add to feed data
        feed_data = load_json(LIVE_FEED_FILE, [])
        feed_entry = {
            "timestamp": alert["timestamp"],
            "system": "GNSS",
            "status": "COMPROMISED" if severity in ["CRITICAL", "HIGH"] else "DEGRADED",
            "threat_type": alert["type"],
            "coordinates": f"33.{random.randint(800, 950)}, 35.{random.randint(500, 650)}",
            "signal_strength": random.randint(20, 40) if severity == "HIGH" else random.randint(60, 85)
        }
        feed_data.append(feed_entry)
        save_json_atomic(LIVE_FEED_FILE, feed_data)

    elif threat_type in ["malware", "ddos", "data_exfil", "insider_threat", "zero_day"]:
        # Network/host related threats go to host events
        events = load_json(HOST_EVENTS_FILE, [])
        events.append(alert)
        save_json_atomic(HOST_EVENTS_FILE, events)

    return alert

# --- Custom CSS for Modern Styling ---
CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

/* Global Styles */
.main > div {
    padding-top: 2rem;
}

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Main Header */
.main-header {
    background: linear-gradient(135deg, #0a0e27 0%, #1a1d3a 50%, #0f1419 100%);
    padding: 2rem 3rem;
    border-radius: 20px;
    margin-bottom: 2rem;
    border: 1px solid rgba(79, 172, 254, 0.1);
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
    position: relative;
    overflow: hidden;
}

.main-header::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: 
        radial-gradient(circle at 20% 20%, rgba(79, 172, 254, 0.1) 0%, transparent 50%),
        radial-gradient(circle at 80% 80%, rgba(0, 245, 212, 0.1) 0%, transparent 50%);
    pointer-events: none;
}

.main-header h1 {
    font-size: 3.5rem;
    font-weight: 700;
    background: linear-gradient(135deg, #4facfe 0%, #00f5d4 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0;
    text-shadow: 0 0 30px rgba(79, 172, 254, 0.3);
}

.main-header .subtitle {
    font-size: 1.2rem;
    color: rgba(255, 255, 255, 0.7);
    margin-top: 0.5rem;
    font-weight: 300;
}

/* Status Card */
.status-card {
    background: linear-gradient(135deg, rgba(15, 20, 25, 0.9) 0%, rgba(26, 29, 58, 0.9) 100%);
    border: 1px solid rgba(79, 172, 254, 0.2);
    border-radius: 16px;
    padding: 1.5rem 2rem;
    backdrop-filter: blur(10px);
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    margin: 1rem 0;
    position: relative;
    overflow: hidden;
}

.status-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: linear-gradient(90deg, #4facfe 0%, #00f5d4 100%);
}

.status-indicator {
    display: flex;
    align-items: center;
    gap: 1rem;
    font-size: 1.1rem;
    color: #ffffff;
}

.status-badge {
    padding: 0.5rem 1rem;
    border-radius: 25px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
}

.status-critical { 
    background: linear-gradient(135deg, #ff4757 0%, #ff3838 100%);
    animation: pulse-red 2s infinite;
}

.status-high { 
    background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%);
    animation: pulse-orange 2s infinite;
}

.status-medium { 
    background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%);
}

.status-low { 
    background: linear-gradient(135deg, #48dbfb 0%, #0abde3 100%);
}

# Floating Action Buttons CSS
.status-ok { 
    background: linear-gradient(135deg, #1dd1a1 0%, #55efc4 100%);
}

/* Floating Action Buttons */
.floating-threat-panel {
    position: fixed;
    right: 30px;
    bottom: 30px;
    z-index: 1000;
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.floating-main-btn {
    width: 60px;
    height: 60px;
    border-radius: 50%;
    background: linear-gradient(135deg, #ff4757 0%, #ff3838 100%);
    border: none;
    color: white;
    font-size: 1.5rem;
    cursor: pointer;
    box-shadow: 0 8px 25px rgba(255, 71, 87, 0.4);
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    animation: pulse-main 3s infinite;
}

.floating-main-btn:hover {
    transform: scale(1.1);
    box-shadow: 0 12px 35px rgba(255, 71, 87, 0.6);
}

.floating-threats-menu {
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
    opacity: 0;
    visibility: hidden;
    transform: translateY(20px);
    transition: all 0.3s ease;
}

.floating-threats-menu.active {
    opacity: 1;
    visibility: visible;
    transform: translateY(0);
}

.threat-btn {
    padding: 0.8rem 1.2rem;
    border-radius: 25px;
    border: none;
    color: white;
    font-weight: 600;
    font-size: 0.85rem;
    cursor: pointer;
    transition: all 0.3s ease;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    min-width: 180px;
    text-align: center;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    position: relative;
    overflow: hidden;
}

.threat-btn::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
    transition: left 0.5s;
}

.threat-btn:hover::before {
    left: 100%;
}

.threat-btn:hover {
    transform: translateX(-5px) scale(1.02);
    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.4);
}

.btn-gps { background: linear-gradient(135deg, #4facfe 0%, #00f5d4 100%); }
.btn-jamming { background: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%); }
.btn-malware { background: linear-gradient(135deg, #ff4757 0%, #c44569 100%); }
.btn-ddos { background: linear-gradient(135deg, #5f27cd 0%, #341f97 100%); }
.btn-exfil { background: linear-gradient(135deg, #fd79a8 0%, #e84393 100%); }
.btn-insider { background: linear-gradient(135deg, #fdcb6e 0%, #e17055 100%); }
.btn-zeroday { background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 100%); }

@keyframes pulse-main {
    0%, 100% { 
        box-shadow: 0 8px 25px rgba(255, 71, 87, 0.4);
        transform: scale(1);
    }
    50% { 
        box-shadow: 0 8px 35px rgba(255, 71, 87, 0.6);
        transform: scale(1.05);
    }
}

/* Threat Injection Notification */
.threat-notification {
    position: fixed;
    top: 20px;
    right: 20px;
    background: linear-gradient(135deg, rgba(255, 71, 87, 0.95) 0%, rgba(255, 56, 56, 0.95) 100%);
    color: white;
    padding: 1rem 1.5rem;
    border-radius: 12px;
    font-weight: 600;
    z-index: 1001;
    animation: slideInRight 0.3s ease, fadeOutUp 0.3s ease 3s forwards;
    box-shadow: 0 8px 25px rgba(255, 71, 87, 0.4);
    border: 1px solid rgba(255, 255, 255, 0.2);
}

@keyframes slideInRight {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

@keyframes fadeOutUp {
    from { transform: translateY(0); opacity: 1; }
    to { transform: translateY(-20px); opacity: 0; }
}

/* Quick Threat Stats */
.quick-stats {
    position: fixed;
    left: 30px;
    bottom: 30px;
    background: linear-gradient(135deg, rgba(15, 20, 25, 0.95) 0%, rgba(26, 29, 58, 0.95) 100%);
    border: 1px solid rgba(79, 172, 254, 0.3);
    border-radius: 12px;
    padding: 1rem;
    backdrop-filter: blur(10px);
    z-index: 999;
    color: white;
    font-size: 0.85rem;
    min-width: 200px;
}

.quick-stats h4 {
    margin: 0 0 0.5rem 0;
    color: #4facfe;
    font-size: 0.9rem;
}

.stat-item {
    display: flex;
    justify-content: space-between;
    margin: 0.3rem 0;
    padding: 0.2rem 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.stat-item:last-child {
    border-bottom: none;
}

@keyframes pulse-red {
    0%, 100% { box-shadow: 0 0 0 0 rgba(255, 71, 87, 0.7); }
    70% { box-shadow: 0 0 0 10px rgba(255, 71, 87, 0); }
}

@keyframes pulse-orange {
    0%, 100% { box-shadow: 0 0 0 0 rgba(255, 107, 53, 0.7); }
    70% { box-shadow: 0 0 0 10px rgba(255, 107, 53, 0); }
}

/* Card Components */
.cyber-card {
    background: linear-gradient(135deg, rgba(15, 20, 25, 0.95) 0%, rgba(26, 29, 58, 0.95) 100%);
    border: 1px solid rgba(79, 172, 254, 0.2);
    border-radius: 16px;
    padding: 2rem;
    margin: 1rem 0;
    backdrop-filter: blur(15px);
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    transition: all 0.3s ease;
}

.cyber-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 12px 48px rgba(0, 0, 0, 0.4);
    border-color: rgba(79, 172, 254, 0.4);
}

/* Host Control Panel */
.host-card {
    background: linear-gradient(135deg, rgba(10, 14, 39, 0.9) 0%, rgba(26, 29, 58, 0.9) 100%);
    border: 1px solid rgba(79, 172, 254, 0.2);
    border-radius: 12px;
    padding: 1.5rem;
    margin: 0.8rem 0;
    position: relative;
    transition: all 0.3s ease;
}

.host-card:hover {
    border-color: rgba(0, 245, 212, 0.4);
    transform: translateX(2px);
}

.host-status-released {
    border-left: 4px solid #1dd1a1;
}

.host-status-isolated {
    border-left: 4px solid #ff4757;
    animation: pulse-border 2s infinite;
}

@keyframes pulse-border {
    0%, 100% { border-left-color: #ff4757; }
    50% { border-left-color: #ff6b6b; }
}

.host-info {
    font-size: 0.9rem;
    color: rgba(255, 255, 255, 0.8);
    margin-bottom: 1rem;
}

.host-name {
    font-size: 1.2rem;
    font-weight: 600;
    color: #4facfe;
    margin-bottom: 0.5rem;
}

/* Buttons */
.cyber-button {
    padding: 0.8rem 1.5rem;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-size: 0.85rem;
}

.btn-isolate {
    background: linear-gradient(135deg, #ff4757 0%, #ff3838 100%);
    color: white;
}

.btn-isolate:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 20px rgba(255, 71, 87, 0.4);
}

.btn-release {
    background: linear-gradient(135deg, #1dd1a1 0%, #55efc4 100%);
    color: white;
}

.btn-release:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 20px rgba(29, 209, 161, 0.4);
}

/* Data Tables */
.dataframe {
    background: rgba(15, 20, 25, 0.9) !important;
    border-radius: 12px !important;
    overflow: hidden !important;
    border: 1px solid rgba(79, 172, 254, 0.2) !important;
}

/* Tabs */
.stTabs > div > div > div {
    background: linear-gradient(135deg, rgba(15, 20, 25, 0.9) 0%, rgba(26, 29, 58, 0.9) 100%);
    border-radius: 12px;
    padding: 2rem;
    margin-top: 1rem;
    border: 1px solid rgba(79, 172, 254, 0.2);
}

/* Sidebar */
.css-1d391kg {
    background: linear-gradient(180deg, rgba(10, 14, 39, 0.95) 0%, rgba(15, 20, 25, 0.95) 100%);
    border-right: 1px solid rgba(79, 172, 254, 0.2);
}

/* Loading Animation */
@keyframes matrix-rain {
    0% { opacity: 0; transform: translateY(-20px); }
    50% { opacity: 1; }
    100% { opacity: 0; transform: translateY(20px); }
}

.matrix-bg {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    pointer-events: none;
    z-index: -1;
    background: 
        radial-gradient(circle at 25% 25%, rgba(79, 172, 254, 0.03) 0%, transparent 50%),
        radial-gradient(circle at 75% 75%, rgba(0, 245, 212, 0.03) 0%, transparent 50%);
}
</style>
"""

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

def create_status_card(sev_key, sev_label, total_alerts):
    """Creates a modern status card with threat level indicator"""
    status_classes = {
        'crit': 'status-critical',
        'high': 'status-high',
        'med': 'status-medium',
        'low': 'status-low',
        'ok': 'status-ok'
    }

    status_icons = {
        'crit': '🚨',
        'high': '⚠️',
        'med': '🟡',
        'low': '🔵',
        'ok': '✅'
    }

    status_class = status_classes.get(sev_key, 'status-ok')
    status_icon = status_icons.get(sev_key, '✅')

    return f"""
    <div class="status-card">
        <div class="status-indicator">
            <span style="font-size: 2rem;">{status_icon}</span>
            <div>
                <div style="font-size: 1.4rem; font-weight: 600; color: #ffffff;">THREAT STATUS</div>
                <div class="status-badge {status_class}">{sev_label}</div>
            </div>
            <div style="margin-left: auto; text-align: right; color: rgba(255,255,255,0.7);">
                <div style="font-size: 0.9rem;">Active Alerts</div>
                <div style="font-size: 2rem; font-weight: 700; color: #4facfe;">{total_alerts}</div>
            </div>
        </div>
        <div style="margin-top: 1rem; font-size: 0.9rem; color: rgba(255,255,255,0.6);">
            🛰️ GPS • 🌐 Network • ☀️ Space Weather • 🛡️ IDS
        </div>
    </div>
    """

def create_host_card(asset, status, ts, reason, ip):
    """Creates a modern host control card"""
    name = asset.get("name", "Asset")
    seg = asset.get("segment", "Unknown Segment")
    typ = asset.get("type", "Unknown Type")

    status_class = "host-status-isolated" if status == "isolated" else "host-status-released"
    status_badge = "🔴 ISOLATED" if status == "isolated" else "🟢 ONLINE"
    status_color = "#ff4757" if status == "isolated" else "#1dd1a1"

    return f"""
    <div class="host-card {status_class}">
        <div class="host-name">{name}</div>
        <div class="host-info">
            <strong>IP:</strong> <code>{ip}</code> • 
            <strong>Segment:</strong> {seg} • 
            <strong>Type:</strong> {typ}
        </div>
        <div style="display: flex; align-items: center; gap: 1rem;">
            <span style="color: {status_color}; font-weight: 600;">{status_badge}</span>
            {f'<span style="font-size: 0.8rem; color: rgba(255,255,255,0.6);">{reason} • {ts}</span>' if status == "isolated" else ''}
        </div>
    </div>
    """

def create_metric_cards(sim_alerts, nasa_alerts, host_events):
    """Create modern metric dashboard cards"""
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="cyber-card" style="text-align: center;">
            <div style="font-size: 2.5rem; color: #4facfe; margin-bottom: 0.5rem;">🛰️</div>
            <div style="font-size: 2rem; font-weight: 700; color: #ffffff;">{len(sim_alerts)}</div>
            <div style="color: rgba(255,255,255,0.7);">Sim Alerts</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="cyber-card" style="text-align: center;">
            <div style="font-size: 2.5rem; color: #00f5d4; margin-bottom: 0.5rem;">🚀</div>
            <div style="font-size: 2rem; font-weight: 700; color: #ffffff;">{len(nasa_alerts)}</div>
            <div style="color: rgba(255,255,255,0.7);">NASA Alerts</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="cyber-card" style="text-align: center;">
            <div style="font-size: 2.5rem; color: #ff6b35; margin-bottom: 0.5rem;">🛡️</div>
            <div style="font-size: 2rem; font-weight: 700; color: #ffffff;">{len(host_events)}</div>
            <div style="color: rgba(255,255,255,0.7);">IDS Events</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        total_threats = len(sim_alerts) + len(nasa_alerts) + len(host_events)
        st.markdown(f"""
        <div class="cyber-card" style="text-align: center;">
            <div style="font-size: 2.5rem; color: #feca57; margin-bottom: 0.5rem;">⚡</div>
            <div style="font-size: 2rem; font-weight: 700; color: #ffffff;">{total_threats}</div>
            <div style="color: rgba(255,255,255,0.7);">Total Threats</div>
        </div>
        """, unsafe_allow_html=True)

# --- UI config ---
st.set_page_config(
    layout="wide",
    page_title="CyberNOVA: SpaceShield — Mission Control",
    page_icon="🛰️",
    initial_sidebar_state="expanded"
)

# Inject custom CSS
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Add matrix background
st.markdown('<div class="matrix-bg"></div>', unsafe_allow_html=True)

# Main header
st.markdown("""
<div class="main-header">
    <h1>🛰️ CyberNOVA: SpaceShield</h1>
    <div class="subtitle">Mission Control — Advanced Threat Detection & Response</div>
</div>
""", unsafe_allow_html=True)

# --- Modern Sidebar ---
with st.sidebar:
    st.markdown("### ⚙️ Mission Control")
    refresh_ms = st.slider("🔄 Auto-refresh (ms)", 3000, 30000, 8000, step=1000)

    st.markdown("---")
    st.markdown(f"""
    **Environment:** `{os.environ.get("ISOLATION_MODE", "sim")}`  
    **Status:** 🟢 Operational  
    **UI Port:** `8501`  
    **Events Port:** `8080`
    """)

    st.markdown("---")
    st.markdown("### 🚀 Quick Actions")
    if st.button("🔄 Force Refresh", use_container_width=True):
        st.rerun()

    st.markdown("---")
    st.markdown("### ℹ️ System Info")
    st.caption("Use `docker compose up --build` for full stack deployment.")

# --- load data ---
sim_feed    = load_json(LIVE_FEED_FILE, [])
sim_alerts  = load_json(LIVE_ALERTS_FILE, [])
nasa_feed   = load_json(NASA_FEED_FILE, [])
nasa_alerts = load_json(NASA_ALERTS_FILE, [])
host_events = load_json(HOST_EVENTS_FILE, [])
assets_doc  = load_json(ASSETS_FILE, {"assets": []})
assets      = assets_doc.get("assets", [])
isol_state  = read_isolation_state(ISOL_STATE_FILE)

# --- threat level / triage ---
def triage_table(alerts, title="🎯 Active Threat Triage"):
    """Displays a modern sortable table of alerts."""
    st.markdown(f"### {title}")
    if not alerts:
        st.info("🟢 No active alerts detected.")
        return

    df = pd.DataFrame(alerts)
    cols_order = [c for c in ["timestamp", "source", "severity", "type", "host", "reason", "description"] if c in df.columns]
    df = df[cols_order] if cols_order else df

    if "timestamp" in df.columns:
        df = df.sort_values("timestamp", ascending=False)

    # Style the dataframe
    st.dataframe(
        df,
        use_container_width=True,
        height=400
    )

def threat_level(all_alerts):
    """Calculates and returns the overall threat level based on the highest severity alert."""
    order = {"INFO":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    if not all_alerts: return "ok", "All Systems Normal"
    sev = max(all_alerts, key=lambda a: order.get(a.get("severity","LOW"),1)).get("severity","LOW")
    key = {"CRITICAL":"crit","HIGH":"high","MEDIUM":"med","LOW":"low"}.get(sev,"ok")
    label = {"CRITICAL":"CRITICAL THREAT","HIGH":"HIGH THREAT","MEDIUM":"ELEVATED","LOW":"LOW RISK","INFO":"LOW RISK"}.get(sev,"LOW RISK")
    return key, label

# merge alerts for quick overview
merged_alerts = []
if sim_alerts:   merged_alerts.extend(sim_alerts)
if nasa_alerts:  merged_alerts.extend(nasa_alerts)
if host_events:  merged_alerts.extend(host_events)

sev_key, sev_label = threat_level(merged_alerts)

# Display modern status card
st.markdown(create_status_card(sev_key, sev_label, len(merged_alerts)), unsafe_allow_html=True)

# Floating Threat Injection Panel
if 'show_threat_menu' not in st.session_state:
    st.session_state.show_threat_menu = False

if 'threat_notification' not in st.session_state:
    st.session_state.threat_notification = None

# JavaScript for floating buttons
st.markdown("""
<div class="floating-threat-panel">
    <div class="floating-threats-menu" id="threatMenu">
        <button class="threat-btn btn-gps" onclick="injectThreat('gps_spoofing')">
            🛰️ GPS Spoofing
        </button>
        <button class="threat-btn btn-jamming" onclick="injectThreat('jamming')">
            📡 Signal Jamming
        </button>
        <button class="threat-btn btn-malware" onclick="injectThreat('malware')">
            🦠 Malware Attack
        </button>
        <button class="threat-btn btn-ddos" onclick="injectThreat('ddos')">
            ⚡ DDoS Attack
        </button>
        <button class="threat-btn btn-exfil" onclick="injectThreat('data_exfil')">
            📤 Data Exfiltration
        </button>
        <button class="threat-btn btn-insider" onclick="injectThreat('insider_threat')">
            👤 Insider Threat
        </button>
        <button class="threat-btn btn-zeroday" onclick="injectThreat('zero_day')">
            💀 Zero-Day Exploit
        </button>
    </div>
    <button class="floating-main-btn" onclick="toggleThreatMenu()">
        ⚔️
    </button>
</div>

<script>
let threatMenuVisible = false;

function toggleThreatMenu() {
    const menu = document.getElementById('threatMenu');
    threatMenuVisible = !threatMenuVisible;
    
    if (threatMenuVisible) {
        menu.classList.add('active');
    } else {
        menu.classList.remove('active');
    }
}

function injectThreat(threatType) {
    // Close the menu
    document.getElementById('threatMenu').classList.remove('active');
    threatMenuVisible = false;
    
    // Show injection notification
    showThreatNotification(threatType);
    
    // Trigger Streamlit rerun to update data
    window.parent.postMessage({
        type: 'streamlit:setComponentValue',
        value: {
            action: 'inject_threat',
            threat_type: threatType,
            timestamp: new Date().toISOString()
        }
    }, '*');
    
    // Force refresh after short delay
    setTimeout(() => {
        window.location.reload();
    }, 500);
}

function showThreatNotification(threatType) {
    // Remove existing notification
    const existing = document.querySelector('.threat-notification');
    if (existing) {
        existing.remove();
    }
    
    const threatNames = {
        'gps_spoofing': '🛰️ GPS Spoofing Attack',
        'jamming': '📡 Signal Jamming Attack', 
        'malware': '🦠 Malware Attack',
        'ddos': '⚡ DDoS Attack',
        'data_exfil': '📤 Data Exfiltration',
        'insider_threat': '👤 Insider Threat',
        'zero_day': '💀 Zero-Day Exploit'
    };
    
    const notification = document.createElement('div');
    notification.className = 'threat-notification';
    notification.innerHTML = `<strong>THREAT INJECTED:</strong> ${threatNames[threatType] || threatType}`;
    
    document.body.appendChild(notification);
    
    // Remove after 4 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 4000);
}

// Hide menu when clicking outside
document.addEventListener('click', function(event) {
    const panel = document.querySelector('.floating-threat-panel');
    if (!panel.contains(event.target) && threatMenuVisible) {
        document.getElementById('threatMenu').classList.remove('active');
        threatMenuVisible = false;
    }
});
</script>
""", unsafe_allow_html=True)

# Handle threat injection from JavaScript
if 'component_value' in st.session_state:
    component_data = st.session_state.component_value
    if isinstance(component_data, dict) and component_data.get('action') == 'inject_threat':
        threat_type = component_data.get('threat_type')
        if threat_type:
            try:
                alert = inject_threat(threat_type, "HIGH")
                st.session_state.threat_notification = f"Injected {alert['type']} - {alert['id']}"
                st.rerun()
            except Exception as e:
                st.error(f"Failed to inject threat: {e}")

# Quick threat injection buttons for testing (can be removed in production)
with st.expander("🔧 Quick Threat Injection (Dev Tools)", expanded=False):
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if st.button("🛰️ GPS Spoofing", key="inject_gps"):
            alert = inject_threat("gps_spoofing", "CRITICAL")
            st.success(f"Injected: {alert['type']}")
            st.rerun()

    with col2:
        if st.button("📡 Signal Jamming", key="inject_jam"):
            alert = inject_threat("jamming", "HIGH")
            st.success(f"Injected: {alert['type']}")
            st.rerun()

    with col3:
        if st.button("🦠 Malware", key="inject_malware"):
            alert = inject_threat("malware", "HIGH")
            st.success(f"Injected: {alert['type']}")
            st.rerun()

    with col4:
        if st.button("⚡ DDoS", key="inject_ddos"):
            alert = inject_threat("ddos", "CRITICAL")
            st.success(f"Injected: {alert['type']}")
            st.rerun()

# Quick Stats Panel
threat_stats = {
    'GPS/Space': len([a for a in merged_alerts if a.get('source') in ['GNSS Monitor', 'NASA Feed']]),
    'Network': len([a for a in merged_alerts if a.get('source') in ['Network Monitor', 'IDS Engine']]),
    'Critical': len([a for a in merged_alerts if a.get('severity') == 'CRITICAL']),
    'Active': len([a for a in merged_alerts if a.get('status', 'active') == 'active'])
}

st.markdown(f"""
<div class="quick-stats">
    <h4>📊 Live Threat Stats</h4>
    <div class="stat-item">
        <span>GPS/Space:</span>
        <span style="color: #4facfe; font-weight: 600;">{threat_stats['GPS/Space']}</span>
    </div>
    <div class="stat-item">
        <span>Network:</span>
        <span style="color: #ff6b35; font-weight: 600;">{threat_stats['Network']}</span>
    </div>
    <div class="stat-item">
        <span>Critical:</span>
        <span style="color: #ff4757; font-weight: 600;">{threat_stats['Critical']}</span>
    </div>
    <div class="stat-item">
        <span>Total Active:</span>
        <span style="color: #00f5d4; font-weight: 600;">{threat_stats['Active']}</span>
    </div>
    <div style="margin-top: 0.5rem; font-size: 0.75rem; color: rgba(255,255,255,0.6);">
        Last Update: {datetime.now().strftime('%H:%M:%S')}
    </div>
</div>
""", unsafe_allow_html=True)

# Metrics dashboard
create_metric_cards(sim_alerts, nasa_alerts, host_events)

# --- Create modern tabs ---
tab_mission, tab_feeds, tab_alerts, tab_analytics = st.tabs([
    "🎯 Mission Control",
    "📡 Live Feeds",
    "🚨 Alerts & Triage",
    "📊 Analytics"
])

with tab_mission:
    # --- layout: Lebanon Map (left) + Host Isolation (right) ---
    col_map, col_hosts = st.columns([1.2, 1])

    with col_map:
        st.markdown("### 🗺️ Lebanon Mission Theater")

        # Create a more advanced map with custom styling
        m = folium.Map(
            location=[33.9, 35.6],
            zoom_start=8,
            tiles=None
        )

        # Add custom dark tile layer
        folium.TileLayer(
            tiles='https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
            attr='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
            name='Dark Matter',
            control=False
        ).add_to(m)

        # Add some sample markers for assets
        if assets:
            for i, asset in enumerate(assets[:3]):  # Show first 3 assets on map
                folium.CircleMarker(
                    location=[33.9 + (i * 0.1), 35.6 + (i * 0.1)],
                    radius=10,
                    popup=f"Asset: {asset.get('name', 'Unknown')}",
                    color='#4facfe',
                    fillColor='#00f5d4',
                    fillOpacity=0.7
                ).add_to(m)

        map_data = st_folium(m, width=None, height=450)

    with col_hosts:
        st.markdown("### 🛡️ Host Isolation Control Center")

        if not assets:
            st.markdown("""
            <div class="cyber-card" style="text-align: center; padding: 3rem;">
                <div style="font-size: 3rem; margin-bottom: 1rem;">🔍</div>
                <div style="color: rgba(255,255,255,0.8);">No assets configured</div>
                <div style="color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-top: 0.5rem;">
                    Create data/assets.json to register hosts
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            # Modern host cards
            for asset in assets:
                name = asset.get("name","Asset")
                ips  = asset.get("ips", [])
                ip   = ips[0] if ips else None
                if not ip:
                    continue

                status = isol_state.get(ip, {}).get("status", "released")
                ts     = isol_state.get(ip, {}).get("ts", "")
                reason = isol_state.get(ip, {}).get("reason", "")

                # Display host card
                st.markdown(create_host_card(asset, status, ts, reason, ip), unsafe_allow_html=True)

                # Control buttons
                col1, col2 = st.columns(2)
                with col1:
                    if st.button(f"🔒 Isolate", key=f"isolate_{ip}", use_container_width=True):
                        try:
                            res = isolate_host(ip, reason="Operator action via UI", state_path=ISOL_STATE_FILE)
                            st.success(f"✅ {res}")
                        except Exception as e:
                            st.error(f"❌ Failed to isolate host: {e}")
                        st.rerun()

                with col2:
                    if st.button(f"🔓 Release", key=f"release_{ip}", use_container_width=True):
                        try:
                            res = release_host(ip, state_path=ISOL_STATE_FILE)
                            st.success(f"✅ {res}")
                        except Exception as e:
                            st.error(f"❌ Failed to release host: {e}")
                        st.rerun()

        st.markdown("---")
        # Latest IDS events in modern format
        if host_events:
            st.markdown("### 🛡️ Live IDS Feed")
            recent_events = host_events[-10:]  # Show last 10 events
            for event in reversed(recent_events):
                severity = event.get('severity', 'LOW')
                sev_color = {
                    'CRITICAL': '#ff4757',
                    'HIGH': '#ff6b35',
                    'MEDIUM': '#feca57',
                    'LOW': '#48dbfb'
                }.get(severity, '#48dbfb')

                st.markdown(f"""
                <div style="
                    background: linear-gradient(135deg, rgba(15, 20, 25, 0.8) 0%, rgba(26, 29, 58, 0.8) 100%);
                    border-left: 3px solid {sev_color};
                    padding: 1rem;
                    margin: 0.5rem 0;
                    border-radius: 8px;
                    font-size: 0.85rem;
                ">
                    <strong style="color: {sev_color};">{severity}</strong> • 
                    {event.get('host', 'Unknown')} • 
                    <span style="color: rgba(255,255,255,0.8);">{event.get('description', 'No description')[:60]}...</span>
                    <div style="color: rgba(255,255,255,0.5); font-size: 0.75rem; margin-top: 0.3rem;">
                        {event.get('timestamp', '')}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("🔍 Monitoring for IDS events...")

with tab_feeds:
    st.markdown("### 📡 Real-Time Data Streams")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 🛰️ Simulated GNSS Feed")
        if sim_feed:
            df = pd.DataFrame(sim_feed[-20:])  # Show last 20 entries
            st.dataframe(df, use_container_width=True, height=300)
        else:
            st.info("⏳ Waiting for simulated feed data...")

    with col2:
        st.markdown("#### 🚀 NASA Live Feed")
        if nasa_feed:
            df = pd.DataFrame(nasa_feed[-20:])
            st.dataframe(df, use_container_width=True, height=300)
        else:
            st.info("⏳ Waiting for NASA feed data...")

with tab_alerts:
    triage_table(merged_alerts[-50:], title="🚨 Global Threat Dashboard")

    if merged_alerts:
        # Alert severity breakdown
        severity_counts = {}
        for alert in merged_alerts:
            sev = alert.get('severity', 'LOW')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        st.markdown("---")
        st.markdown("### 📊 Threat Severity Breakdown")

        # Create severity breakdown visualization
        col1, col2 = st.columns([2, 1])

        with col1:
            if severity_counts:
                # Create a modern donut chart
                fig = go.Figure(data=[go.Pie(
                    labels=list(severity_counts.keys()),
                    values=list(severity_counts.values()),
                    hole=0.6,
                    marker=dict(
                        colors=['#ff4757', '#ff6b35', '#feca57', '#48dbfb', '#1dd1a1']
                    )
                )])

                fig.update_layout(
                    title=dict(
                        text="Alert Distribution",
                        font=dict(color='white', size=16)
                    ),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white'),
                    height=300
                )

                st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.markdown("#### 🎯 Quick Stats")
            for sev, count in severity_counts.items():
                color = {
                    'CRITICAL': '#ff4757',
                    'HIGH': '#ff6b35',
                    'MEDIUM': '#feca57',
                    'LOW': '#48dbfb',
                    'INFO': '#1dd1a1'
                }.get(sev, '#48dbfb')

                st.markdown(f"""
                <div style="
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 0.5rem 1rem;
                    margin: 0.3rem 0;
                    background: linear-gradient(135deg, rgba(15, 20, 25, 0.6) 0%, rgba(26, 29, 58, 0.6) 100%);
                    border-left: 3px solid {color};
                    border-radius: 8px;
                ">
                    <span style="color: rgba(255,255,255,0.9);">{sev}</span>
                    <span style="color: {color}; font-weight: 700; font-size: 1.2rem;">{count}</span>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="cyber-card" style="text-align: center; padding: 3rem;">
            <div style="font-size: 4rem; margin-bottom: 1rem;">🛡️</div>
            <div style="font-size: 1.5rem; color: #1dd1a1; margin-bottom: 0.5rem;">All Clear</div>
            <div style="color: rgba(255,255,255,0.6);">No active threats detected</div>
        </div>
        """, unsafe_allow_html=True)

with tab_analytics:
    st.markdown("### 📊 Advanced Analytics Dashboard")

    # Time-based analytics
    if merged_alerts:
        # Create timeline chart
        df_alerts = pd.DataFrame(merged_alerts)
        if 'timestamp' in df_alerts.columns:
            # Convert timestamps and create hourly bins
            df_alerts['timestamp'] = pd.to_datetime(df_alerts['timestamp'], errors='coerce')
            df_alerts = df_alerts.dropna(subset=['timestamp'])
            df_alerts['hour'] = df_alerts['timestamp'].dt.floor('H')

            # Group by hour and severity
            hourly_alerts = df_alerts.groupby(['hour', 'severity']).size().unstack(fill_value=0)

            if not hourly_alerts.empty:
                st.markdown("#### ⏰ Threat Timeline (Last 24 Hours)")

                # Create stacked bar chart
                fig = go.Figure()

                colors = {
                    'CRITICAL': '#ff4757',
                    'HIGH': '#ff6b35',
                    'MEDIUM': '#feca57',
                    'LOW': '#48dbfb',
                    'INFO': '#1dd1a1'
                }

                for severity in hourly_alerts.columns:
                    fig.add_trace(go.Bar(
                        name=severity,
                        x=hourly_alerts.index,
                        y=hourly_alerts[severity],
                        marker_color=colors.get(severity, '#48dbfb')
                    ))

                fig.update_layout(
                    barmode='stack',
                    title=dict(
                        text="Alert Frequency Over Time",
                        font=dict(color='white', size=16)
                    ),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white'),
                    xaxis=dict(
                        title="Time",
                        gridcolor='rgba(255,255,255,0.1)'
                    ),
                    yaxis=dict(
                        title="Alert Count",
                        gridcolor='rgba(255,255,255,0.1)'
                    ),
                    height=400
                )

                st.plotly_chart(fig, use_container_width=True)

    # System metrics simulation
    st.markdown("---")
    st.markdown("#### 🖥️ System Performance Metrics")

    col1, col2, col3 = st.columns(3)

    with col1:
        # CPU usage gauge
        cpu_usage = 67  # Simulated
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = cpu_usage,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "CPU Usage (%)"},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "#4facfe"},
                'steps': [
                    {'range': [0, 50], 'color': "rgba(29, 209, 161, 0.2)"},
                    {'range': [50, 80], 'color': "rgba(254, 202, 87, 0.2)"},
                    {'range': [80, 100], 'color': "rgba(255, 71, 87, 0.2)"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))

        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            font={'color': 'white'},
            height=250
        )

        st.plotly_chart(fig, use_container_width=True)

    with col2:
        # Memory usage gauge
        mem_usage = 45  # Simulated
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = mem_usage,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Memory Usage (%)"},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "#00f5d4"},
                'steps': [
                    {'range': [0, 50], 'color': "rgba(29, 209, 161, 0.2)"},
                    {'range': [50, 80], 'color': "rgba(254, 202, 87, 0.2)"},
                    {'range': [80, 100], 'color': "rgba(255, 71, 87, 0.2)"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))

        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            font={'color': 'white'},
            height=250
        )

        st.plotly_chart(fig, use_container_width=True)

    with col3:
        # Network throughput gauge
        network_usage = 23  # Simulated
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = network_usage,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Network Load (%)"},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "#ff6b35"},
                'steps': [
                    {'range': [0, 50], 'color': "rgba(29, 209, 161, 0.2)"},
                    {'range': [50, 80], 'color': "rgba(254, 202, 87, 0.2)"},
                    {'range': [80, 100], 'color': "rgba(255, 71, 87, 0.2)"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))

        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            font={'color': 'white'},
            height=250
        )

        st.plotly_chart(fig, use_container_width=True)

    # Network topology simulation
    st.markdown("---")
    st.markdown("#### 🌐 Network Topology Status")

    # Create a network visualization
    if assets:
        node_data = []
        edge_data = []

        # Create nodes for each asset
        for i, asset in enumerate(assets):
            status = "isolated" if any(
                isol_state.get(ip, {}).get("status") == "isolated"
                for ip in asset.get("ips", [])
            ) else "online"

            node_data.append({
                'id': i,
                'label': asset.get('name', f'Asset {i}'),
                'status': status,
                'type': asset.get('type', 'Unknown')
            })

        # Create a simple network graph visualization
        fig = go.Figure()

        # Add nodes
        for node in node_data:
            color = '#ff4757' if node['status'] == 'isolated' else '#1dd1a1'
            fig.add_trace(go.Scatter(
                x=[node['id'] % 3],
                y=[node['id'] // 3],
                mode='markers+text',
                marker=dict(size=30, color=color),
                text=node['label'],
                textposition="bottom center",
                textfont=dict(color='white'),
                showlegend=False
            ))

        fig.update_layout(
            title=dict(
                text="Asset Network Status",
                font=dict(color='white', size=16)
            ),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=300
        )

        st.plotly_chart(fig, use_container_width=True)

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: rgba(255,255,255,0.5); padding: 2rem 0;">
    <div style="font-size: 0.9rem;">🛰️ CyberNOVA: SpaceShield — Protecting Critical Infrastructure</div>
    <div style="font-size: 0.8rem; margin-top: 0.5rem;">Advanced Cyber Defense • Real-Time Monitoring • Intelligent Response</div>
</div>
""", unsafe_allow_html=True)

# --- Auto refresh with enhanced UX and instant threat updates ---
count = st_autorefresh(interval=2000, key="auto-refresh-ui")  # Faster refresh for instant updates

# Show refresh indicator with threat injection status
refresh_status = "🔄 Live Monitor"
if st.session_state.get('threat_notification'):
    refresh_status = f"⚠️ {st.session_state.threat_notification}"
    # Clear notification after showing
    if count % 5 == 0:  # Clear after a few refreshes
        st.session_state.threat_notification = None

if count > 0:
    st.markdown(f"""
    <div style="
        position: fixed;
        top: 20px;
        right: 20px;
        background: linear-gradient(135deg, rgba(79, 172, 254, 0.9) 0%, rgba(0, 245, 212, 0.9) 100%);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 25px;
        font-size: 0.8rem;
        font-weight: 600;
        z-index: 1000;
        animation: fadeIn 0.3s ease;
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.2);
    ">
        {refresh_status} • Cycle {count}
    </div>
    """, unsafe_allow_html=True)