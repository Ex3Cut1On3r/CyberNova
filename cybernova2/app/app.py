#!/usr/bin/env python3
# app/app.py — Mission Control (File-based Alert System)
import os, json, datetime, pandas as pd, yaml, streamlit as st
import random
import folium
from streamlit_folium import st_folium
from streamlit_autorefresh import st_autorefresh
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import time
import sys, subprocess
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
ALERTS_FILE       = os.path.join(DATA_DIR, "alerts.json")  # New file for Suricata alerts
ISOLATER_SCRIPT = "/home/charliepro13/isolater.py"

# --- imports for isolation controller ---
try:
    from .isolation_controller import isolate_host, release_host, read_isolation_state
except ImportError:
    try:
        # fallback if run as "streamlit run app/app.py"
        from isolation_controller import isolate_host, release_host, read_isolation_state
    except ImportError:
        # Create stub functions if module not available
        def isolate_host(ip, reason="", state_path=""):
            return f"Simulated isolation of {ip}"
        def release_host(ip, state_path=""):
            return f"Simulated release of {ip}"
        def read_isolation_state(path):
            return {}
        st.warning("Isolation controller not available - using simulation mode")

# Initialize session state for sliding alerts
if "displayed_alerts" not in st.session_state:
    st.session_state.displayed_alerts = set()
if "sliding_alerts" not in st.session_state:
    st.session_state.sliding_alerts = []

def check_new_alerts():
    """Check for new alerts and add them to sliding notifications"""
    alerts = load_json(ALERTS_FILE, [])
    
    # Find new alerts that haven't been displayed yet
    new_alerts = []
    for alert in alerts:
        alert_id = f"{alert.get('timestamp', '')}_{alert.get('src_ip', '')}_{alert.get('dest_ip', '')}"
        if alert_id not in st.session_state.displayed_alerts:
            new_alerts.append(alert)
            st.session_state.displayed_alerts.add(alert_id)
    
    # Add new alerts to sliding queue
    for alert in new_alerts:
        alert_id = f"{alert.get('timestamp', '')}_{alert.get('src_ip', '')}_{alert.get('dest_ip', '')}"
        st.session_state.sliding_alerts.append({
            'id': alert_id,
            'alert': alert,
            'timestamp': time.time()
        })
    
    # Keep only last 5 sliding alerts
    if len(st.session_state.sliding_alerts) > 5:
        st.session_state.sliding_alerts = st.session_state.sliding_alerts[-5:]
    
    return new_alerts

def get_asset_status_from_alerts():
    """Get asset online status from recent alerts"""
    alerts = load_json(ALERTS_FILE, [])
    online_assets = set()
    
    # Look for alerts in the last 5 minutes to determine if asset is online
    current_time = datetime.now()
    cutoff_time = current_time - timedelta(minutes=5)
    
    for alert in alerts:
        try:
            alert_time = datetime.fromisoformat(alert.get('timestamp', '').replace('Z', '+00:00'))
            if alert_time > cutoff_time:
                src_ip = alert.get('src_ip')
                dest_ip = alert.get('dest_ip')
                if src_ip:
                    online_assets.add(src_ip)
                if dest_ip:
                    online_assets.add(dest_ip)
        except Exception:
            continue
    
    return online_assets

# --- helpers ---
def load_json(path, default):
    """Loads a JSON file, returning a default value on error or if the file doesn't exist."""
    try:
        if not os.path.exists(path): 
            return default
        with open(path, "r", encoding="utf-8") as f: 
            return json.load(f)
    except Exception as e:
        st.error(f"Error loading {path}: {e}")
        return default

def save_json_atomic(path, obj):
    """Saves a JSON object to a file atomically to prevent data corruption."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception as e:
        st.error(f"Error saving {path}: {e}")
        
        
def run_isolater_for_ip(ip: str, extra_args=None, timeout_s: int = 30):
    """Execute isolater.py with the current Python interpreter."""
    if extra_args is None:
        extra_args = []

    if not os.path.exists(ISOLATER_SCRIPT):
        return (False, "", f"isolater.py not found at {ISOLATER_SCRIPT}", 127)

    cmd = [sys.executable, ISOLATER_SCRIPT, "--ip", str(ip), *extra_args]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            cwd=os.path.dirname(ISOLATER_SCRIPT) or None,
            env=os.environ.copy(),
        )
        ok = proc.returncode == 0
        return ok, proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        return False, "", f"Timeout after {timeout_s}s", 124
    except Exception as e:
        return False, "", f"Execution error: {e}", 1

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

from html import escape

def create_enhanced_asset_card(asset, online_ips, isol_state):
    """Return an HTML card for an asset (ready for st.markdown(..., unsafe_allow_html=True))."""
    # --- read/derive fields ---
    name        = escape(str(asset.get("name", asset.get("group", "Asset"))))
    ips         = asset.get("ips") or []
    asset_type  = escape(str(asset.get("type", "Network Device")))
    segment     = escape(str(asset.get("segment", "DMZ")))

    if not ips:
        return ""

    primary_ip   = ips[0]
    is_online    = primary_ip in online_ips
    is_isolated  = isol_state.get(primary_ip, {}).get("status") == "isolated"

    # status -> badge/class/color
    if is_isolated:
        status, status_badge, card_class = "isolated", "🔒 ISOLATED", "asset-isolated"
    elif is_online:
        status, status_badge, card_class = "online", "🟢 ONLINE", "asset-online"
    else:
        status, status_badge, card_class = "offline", "🔴 OFFLINE", "asset-offline"

    # metrics
    try:
        all_alerts = load_json(ALERTS_FILE, [])
    except Exception:
        all_alerts = []
    alert_count = sum(
        1 for a in all_alerts
        if a.get("src_ip") == primary_ip or a.get("dest_ip") == primary_ip
    )
    ip_count   = len(ips)
    risk_level = "HIGH" if alert_count > 10 else ("MEDIUM" if alert_count > 3 else "LOW")

    if is_online:
        last_seen = "Active"
    elif is_isolated:
        iso_info  = isol_state.get(primary_ip, {})
        last_seen = str(iso_info.get("ts", "Unknown"))[:16]
    else:
        last_seen = "Unknown"

    # escape any user/display text
    primary_ip_e = escape(str(primary_ip))
    last_seen_e  = escape(str(last_seen))
    status_badge_e = escape(status_badge)
    risk_level_e = escape(risk_level)

    # --- HTML (f-string!) ---
    return f"""
    <div class="asset-card {card_class}">
      <div class="asset-header">
        <h3 class="asset-name">{name}</h3>
        <span class="asset-status-badge status-{status}">{status_badge_e}</span>
      </div>

      <div class="asset-details">
        <div class="asset-detail-item">
          <div class="asset-detail-label">Primary IP</div>
          <div class="asset-detail-value">{primary_ip_e}</div>
        </div>
        <div class="asset-detail-item">
          <div class="asset-detail-label">Asset Type</div>
          <div class="asset-detail-value">{asset_type}</div>
        </div>
        <div class="asset-detail-item">
          <div class="asset-detail-label">Network Segment</div>
          <div class="asset-detail-value">{segment}</div>
        </div>
        <div class="asset-detail-item">
          <div class="asset-detail-label">Last Seen</div>
          <div class="asset-detail-value">{last_seen_e}</div>
        </div>
      </div>

      <div class="asset-metrics">
        <div class="metric-row">
          <span class="metric-label">Alert Count (24h):</span>
          <span class="metric-value">{alert_count}</span>
        </div>
        <div class="metric-row">
          <span class="metric-label">IP Count:</span>
          <span class="metric-value">{ip_count}</span>
        </div>
        <div class="metric-row">
          <span class="metric-label">Risk Level:</span>
          <span class="metric-value">{risk_level_e}</span>
        </div>
      </div>
    </div>
    """

def create_metric_cards(sim_alerts, nasa_alerts, host_events, suricata_alerts):
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
        st.markdown(f"""
        <div class="cyber-card" style="text-align: center;">
            <div style="font-size: 2.5rem; color: #feca57; margin-bottom: 0.5rem;">⚡</div>
            <div style="font-size: 2rem; font-weight: 700; color: #ffffff;">{len(suricata_alerts)}</div>
            <div style="color: rgba(255,255,255,0.7);">Suricata Alerts</div>
        </div>
        """, unsafe_allow_html=True)

def render_sliding_alerts():
    """Render sliding alert notifications"""
    if not st.session_state.sliding_alerts:
        return ""
    
    current_time = time.time()
    active_alerts = []
    
    # Filter alerts that should still be visible (5 seconds)
    for sliding_alert in st.session_state.sliding_alerts:
        if current_time - sliding_alert['timestamp'] < 5:
            active_alerts.append(sliding_alert)
    
    # Update session state
    st.session_state.sliding_alerts = active_alerts
    
    if not active_alerts:
        return ""
    
    alerts_html = '<div class="sliding-alerts-container">'
    
    for i, sliding_alert in enumerate(active_alerts):
        alert = sliding_alert['alert']
        severity = alert.get('severity', 'INFO')
        signature = alert.get('alert', {}).get('signature', 'Unknown Alert')
        src_ip = alert.get('src_ip', 'Unknown')
        dest_ip = alert.get('dest_ip', 'Unknown')
        
        # Truncate long signatures
        if len(signature) > 60:
            signature = signature[:60] + "..."
        
        severity_class = f"severity-{severity.lower()}"
        
        alert_age = current_time - sliding_alert['timestamp']
        delay_style = f"animation-delay: {i * 0.2}s;"
        
        alerts_html += f"""
        <div class="sliding-alert show" style="{delay_style}">
            <div class="sliding-alert-header">
                <span class="sliding-alert-severity {severity_class}">{severity}</span>
                <button class="alert-close-btn" onclick="closeAlert(this)">×</button>
            </div>
            <div class="sliding-alert-title">🚨 {signature}</div>
            <div class="sliding-alert-description">
                <strong>Source:</strong> {src_ip} → <strong>Dest:</strong> {dest_ip}
            </div>
            <div class="sliding-alert-meta">
                <span>Suricata IDS</span>
                <span>{alert.get('timestamp', '')[:19]}</span>
            </div>
        </div>
        """
    
    alerts_html += '</div>'
    
    # Add JavaScript for auto-hide and close functionality
    alerts_html += """
    <script>
    function closeAlert(btn) {
        const alert = btn.closest('.sliding-alert');
        if (alert) {
            alert.classList.add('hide');
            setTimeout(() => {
                alert.remove();
            }, 500);
        }
    }
    
    // Auto-hide alerts after 5 seconds
    setTimeout(() => {
        document.querySelectorAll('.sliding-alert').forEach(alert => {
            alert.classList.add('hide');
            setTimeout(() => {
                if (alert.parentNode) {
                    alert.remove();
                }
            }, 500);
        });
    }, 5000);
    </script>
    """
    
    return alerts_html

# --- Threat simulation functions ---
def generate_threat_alert(threat_type, severity="HIGH", target_ip="192.168.1.250"):
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

# Define the CUSTOM_CSS
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

/* Sliding Alert Container */
.sliding-alerts-container {
    position: fixed;
    top: 100px;
    right: 30px;
    z-index: 1500;
    width: 400px;
    max-height: 80vh;
    overflow: hidden;
    pointer-events: none;
}

.sliding-alert {
    background: linear-gradient(135deg, rgba(15, 20, 25, 0.98) 0%, rgba(26, 29, 58, 0.98) 100%);
    border: 1px solid rgba(79, 172, 254, 0.3);
    border-radius: 16px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    backdrop-filter: blur(20px);
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
    animation: slideInAlert 0.5s ease-out;
    opacity: 0;
    transform: translateX(100%);
    pointer-events: auto;
    position: relative;
    overflow: hidden;
}

.sliding-alert.show {
    opacity: 1;
    transform: translateX(0);
}

.sliding-alert.hide {
    animation: slideOutAlert 0.5s ease-in forwards;
}

.sliding-alert::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(90deg, #ff4757 0%, #ff6b35 50%, #feca57 100%);
    animation: alertProgress 5s linear forwards;
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

.status-ok { 
    background: linear-gradient(135deg, #1dd1a1 0%, #55efc4 100%);
}

/* Enhanced Asset Cards */
.asset-card {
    background: linear-gradient(135deg, rgba(10, 14, 39, 0.95) 0%, rgba(26, 29, 58, 0.95) 100%);
    border: 1px solid rgba(79, 172, 254, 0.2);
    border-radius: 16px;
    padding: 1.8rem;
    margin: 1rem 0;
    position: relative;
    transition: all 0.3s ease;
    backdrop-filter: blur(15px);
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
}

.asset-card:hover {
    border-color: rgba(0, 245, 212, 0.4);
    transform: translateY(-2px);
    box-shadow: 0 12px 48px rgba(0, 0, 0, 0.4);
}

.asset-online {
    border-left: 4px solid #1dd1a1;
}

.asset-offline {
    border-left: 4px solid #ff4757;
}

.asset-isolated {
    border-left: 4px solid #ff4757;
    animation: pulse-border 2s infinite;
}

.asset-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
}

.asset-name {
    font-size: 1.4rem;
    font-weight: 700;
    color: #4facfe;
    margin: 0;
}

.asset-status-badge {
    padding: 0.4rem 1rem;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.status-online {
    background: linear-gradient(135deg, #1dd1a1 0%, #55efc4 100%);
    color: white;
}

.status-offline {
    background: linear-gradient(135deg, #ff4757 0%, #ff3838 100%);
    color: white;
}

.status-isolated {
    background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 100%);
    color: white;
    animation: pulse-isolated 2s infinite;
}

.asset-details {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
    font-size: 0.9rem;
}

.asset-detail-item {
    background: rgba(79, 172, 254, 0.05);
    padding: 0.8rem;
    border-radius: 8px;
    border: 1px solid rgba(79, 172, 254, 0.1);
}

.asset-detail-label {
    color: rgba(255, 255, 255, 0.6);
    font-size: 0.8rem;
    margin-bottom: 0.3rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.asset-detail-value {
    color: #ffffff;
    font-weight: 600;
    font-family: 'Courier New', monospace;
}

.asset-metrics {
    margin-top: 1rem;
    padding-top: 1rem;
    border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.metric-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin: 0.5rem 0;
    font-size: 0.85rem;
}

.metric-label {
    color: rgba(255, 255, 255, 0.7);
}

.metric-value {
    color: #00f5d4;
    font-weight: 600;
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

/* Animations */
@keyframes slideInAlert {
    from {
        opacity: 0;
        transform: translateX(100%);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

@keyframes slideOutAlert {
    from {
        opacity: 1;
        transform: translateX(0);
    }
    to {
        opacity: 0;
        transform: translateX(100%);
    }
}

@keyframes alertProgress {
    from { width: 100%; }
    to { width: 0%; }
}

@keyframes pulse-red {
    0%, 100% { 
        box-shadow: 0 0 0 0 rgba(255, 71, 87, 0.7);
    }
    70% { 
        box-shadow: 0 0 0 10px rgba(255, 71, 87, 0);
    }
}

@keyframes pulse-orange {
    0%, 100% { 
        box-shadow: 0 0 0 0 rgba(255, 107, 53, 0.7);
    }
    70% { 
        box-shadow: 0 0 0 10px rgba(255, 107, 53, 0);
    }
}

@keyframes pulse-isolated {
    0%, 100% { 
        box-shadow: 0 0 0 0 rgba(108, 92, 231, 0.7);
    }
    70% { 
        box-shadow: 0 0 0 10px rgba(108, 92, 231, 0);
    }
}

@keyframes pulse-border {
    0%, 100% { border-left-color: #ff4757; }
    50% { border-left-color: #ff6b6b; }
}
</style>
"""

# --- UI config ---
st.set_page_config(
    layout="wide",
    page_title="CyberNOVA: SpaceShield — Mission Control",
    page_icon="🛰️",
    initial_sidebar_state="expanded"
)

# Inject custom CSS
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Main header
st.markdown("""
<div class="main-header">
    <h1>🛰️ CyberNOVA: SpaceShield</h1>
    <div class="subtitle">Mission Control — Advanced Threat Detection & Response</div>
</div>
""", unsafe_allow_html=True)

# --- Enhanced Sidebar ---
with st.sidebar:
    st.markdown("### ⚙️ Mission Control")
    refresh_ms = st.slider("🔄 Auto-refresh (ms)", 3000, 30000, 5000, step=1000)

    st.markdown("---")
    st.markdown(f"""
    **Environment:** `{os.environ.get("ISOLATION_MODE", "sim")}`  
    **Status:** 🟢 Operational  
    **UI Port:** `8501`  
    **Alerts:** File-based monitoring
    """)

    st.markdown("---")
    st.markdown("### 🚀 Quick Actions")
    if st.button("🔄 Force Refresh", use_container_width=True):
        st.rerun()

    if st.button("🧹 Clear Alert History", use_container_width=True):
        st.session_state.displayed_alerts = set()
        st.session_state.sliding_alerts = []
        st.success("Alert history cleared")

    st.markdown("---")
    st.markdown("### ℹ️ System Info")
    st.caption("Monitoring Suricata alerts via file-based system.")

# --- load data ---
sim_feed    = load_json(LIVE_FEED_FILE, [])
sim_alerts  = load_json(LIVE_ALERTS_FILE, [])
nasa_feed   = load_json(NASA_FEED_FILE, [])
nasa_alerts = load_json(NASA_ALERTS_FILE, [])
host_events = load_json(HOST_EVENTS_FILE, [])
assets_doc  = load_json(ASSETS_FILE, {"assets": []})
assets      = assets_doc.get("assets", [])
isol_state  = read_isolation_state(ISOL_STATE_FILE)
suricata_alerts = load_json(ALERTS_FILE, [])

# Check for new alerts and prepare sliding notifications
new_alerts = check_new_alerts()

# Get asset online status from alerts
online_assets = get_asset_status_from_alerts()

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

    st.dataframe(df, use_container_width=True, height=400)

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
if suricata_alerts: 
    # Convert Suricata alerts to standard format
    for alert in suricata_alerts:
        converted_alert = {
            "timestamp": alert.get("timestamp", ""),
            "severity": alert.get("severity", "MEDIUM"),
            "type": "IDS Alert",
            "description": alert.get("alert", {}).get("signature", "Suricata Detection"),
            "source": "Suricata IDS",
            "host": alert.get("src_ip", "Unknown"),
            "reason": f"Traffic from {alert.get('src_ip', 'Unknown')} to {alert.get('dest_ip', 'Unknown')}",
            "status": "active"
        }
        merged_alerts.append(converted_alert)

sev_key, sev_label = threat_level(merged_alerts)

# Display modern status card
st.markdown(create_status_card(sev_key, sev_label, len(merged_alerts)), unsafe_allow_html=True)

# Render sliding alerts
sliding_alerts_html = render_sliding_alerts()
if sliding_alerts_html:
    st.markdown(sliding_alerts_html, unsafe_allow_html=True)

# Quick threat injection buttons for testing
with st.expander("🔧 Quick Threat Injection (Dev Tools)", expanded=False):
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if st.button("🛰️ GPS Spoofing", key="inject_gps"):
            try:
                alert = inject_threat("gps_spoofing", "CRITICAL")
                st.success(f"✅ Injected: {alert['type']}")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Injection failed: {e}")

    with col2:
        if st.button("📡 Signal Jamming", key="inject_jam"):
            try:
                alert = inject_threat("jamming", "HIGH")
                st.success(f"✅ Injected: {alert['type']}")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Injection failed: {e}")

    with col3:
        if st.button("🦠 Malware", key="inject_malware"):
            try:
                alert = inject_threat("malware", "HIGH")
                st.success(f"✅ Injected: {alert['type']}")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Injection failed: {e}")

    with col4:
        if st.button("⚡ DDoS", key="inject_ddos"):
            try:
                alert = inject_threat("ddos", "CRITICAL")
                st.success(f"✅ Injected: {alert['type']}")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Injection failed: {e}")

# Metrics dashboard
create_metric_cards(sim_alerts, nasa_alerts, host_events, suricata_alerts)

# --- Create modern tabs ---
tab_mission, tab_feeds, tab_alerts, tab_analytics = st.tabs([
    "🎯 Mission Control",
    "📡 Live Feeds", 
    "🚨 Alerts & Triage",
    "📊 Analytics"
])

with tab_mission:
    # ================
    # 1) FULL-WIDTH MAP
    # ================
    st.markdown("### 🗺️ Lebanon Mission Theater")

    try:
        m = folium.Map(location=[33.9, 35.6], zoom_start=8, tiles=None)
        folium.TileLayer(
            tiles='https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
            attr='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
            name='Dark Matter',
            control=False
        ).add_to(m)

        if assets:
            for i, asset in enumerate(assets[:5]):  # keep your 5 demo markers
                ips = asset.get("ips", [])
                if not ips:
                    continue
                primary_ip = ips[0]
                is_online = primary_ip in online_assets
                is_isolated = isol_state.get(primary_ip, {}).get("status") == "isolated"

                lat = 33.9 + (i * 0.1)
                lon = 35.6 + (i * 0.1)

                if is_isolated:
                    color = '#6c5ce7'; fill_color = '#a29bfe'; popup_status = "ISOLATED"
                elif is_online:
                    color = '#1dd1a1'; fill_color = '#55efc4'; popup_status = "ONLINE"
                else:
                    color = '#ff4757'; fill_color = '#ff6b6b'; popup_status = "OFFLINE"

                folium.CircleMarker(
                    location=[lat, lon],
                    radius=12,
                    popup=f"Asset: {asset.get('name', asset.get('group', 'Unknown'))}<br>Status: {popup_status}<br>IP: {primary_ip}",
                    color=color, fillColor=fill_color, fillOpacity=0.7, weight=2
                ).add_to(m)

        st_folium(m, width=None, height=450)
    except Exception as e:
        st.error(f"Map loading error: {e}")
        st.info("Map temporarily unavailable")

    # ================
    # 2) ASSET GRID (full width, cards in rows)
    # ================
    st.markdown("### 🖥️ Asset Management Console")
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
        # how many cards per row (change to 2 or 4 if you prefer)
        COLS_PER_ROW = 3
        cols = st.columns(COLS_PER_ROW, gap="medium")

        for idx, asset in enumerate(assets):
            ips = asset.get("ips", [])
            if not ips:
                continue

            primary_ip = ips[0]
            is_online = primary_ip in online_assets
            is_isolated = isol_state.get(primary_ip, {}).get("status") == "isolated"

            # pick a column for this card
            with cols[idx % COLS_PER_ROW]:
                # the card itself
                st.markdown(
                    create_enhanced_asset_card(asset, online_assets, isol_state),
                    unsafe_allow_html=True
                )

                # --- per-asset controls (each card has its own buttons) ---
                # ONLINE & NOT ISOLATED
                if is_online and not is_isolated:
                    a1, a2, a3 = st.columns(3)
                    with a1:
                        if st.button("🔒 Isolate", key=f"isolate_{primary_ip}", use_container_width=True):
                            try:
                                res = isolate_host(primary_ip, reason="Operator action via UI", state_path=ISOL_STATE_FILE)
                                st.success(f"✅ {res}"); st.rerun()
                            except Exception as e:
                                st.error(f"❌ Failed to isolate host: {e}")
                    with a2:
                        if st.button("📊 Details", key=f"details_{primary_ip}", use_container_width=True):
                            with st.expander(f"📋 Detailed Info — {asset.get('name', 'Asset')}", expanded=True):
                                asset_alerts = [a for a in suricata_alerts
                                                if a.get('src_ip') == primary_ip or a.get('dest_ip') == primary_ip]
                                st.markdown(f"""
                                **Asset Details:**
                                - **Name:** {asset.get('name', asset.get('group', 'Unknown'))}
                                - **Primary IP:** `{primary_ip}`
                                - **All IPs:** {', '.join(f'`{ip}`' for ip in ips)}
                                - **Type:** {asset.get('type', 'Network Device')}
                                - **Segment:** {asset.get('segment', 'DMZ')}
                                - **Status:** {'🟢 Online' if is_online else '🔴 Offline'}
                                - **Recent Alerts:** {len(asset_alerts)}
                                """)
                                if asset_alerts:
                                    st.markdown("**Recent Alert Activity:**")
                                    for a in asset_alerts[-5:]:
                                        ts = a.get('timestamp', '')[:19]
                                        sig = a.get('alert', {}).get('signature', 'Unknown')
                                        st.markdown(f"- `{ts}` — {sig}")
                    with a3:
                        # 🧰 PER-ASSET isolater.py button
                        if st.button("🧰 isolater.py", key=f"run_iso_{primary_ip}", use_container_width=True):
                            with st.spinner(f"Running isolater.py for {primary_ip}..."):
                                ok, out, err, rc = run_isolater_for_ip(primary_ip)
                            if ok:
                                st.success(f"isolater.py exited 0 for {primary_ip}")
                                if out: st.code(out, language="bash")
                                st.rerun()
                            else:
                                st.error(f"isolater.py failed (rc={rc}) for {primary_ip}")
                                if out: st.code(out, language="bash")
                                if err: st.code(err, language="bash")

                # ISOLATED
                elif is_isolated:
                    b1, b2 = st.columns(2)
                    with b1:
                        if st.button("🔓 Release", key=f"release_{primary_ip}", use_container_width=True):
                            try:
                                res = release_host(primary_ip, state_path=ISOL_STATE_FILE)
                                st.success(f"✅ {res}"); st.rerun()
                            except Exception as e:
                                st.error(f"❌ Failed to release host: {e}")
                    with b2:
                        if st.button("🧰 isolater.py", key=f"run_iso_{primary_ip}", use_container_width=True):
                            with st.spinner(f"Running isolater.py for {primary_ip}..."):
                                ok, out, err, rc = run_isolater_for_ip(primary_ip)
                            if ok:
                                st.success(f"isolater.py exited 0 for {primary_ip}")
                                if out: st.code(out, language="bash")
                                st.rerun()
                            else:
                                st.error(f"isolater.py failed (rc={rc}) for {primary_ip}")
                                if out: st.code(out, language="bash")
                                if err: st.code(err, language="bash")
                    # isolated pill for context (kept your style)
                    st.markdown("""
                    <div style="
                        text-align: center; 
                        padding: 0.6rem; 
                        color: #6c5ce7; 
                        font-weight: 600;
                        background: rgba(108, 92, 231, 0.1);
                        border-radius: 8px;
                        border: 1px solid rgba(108, 92, 231, 0.3);
                        margin-top: 0.4rem;
                    ">
                        🔒 ISOLATED
                    </div>
                    """, unsafe_allow_html=True)

                # OFFLINE / WAITING
                else:
                    st.markdown("""
                    <div style="text-align: center; padding: 0.6rem; color: rgba(255,255,255,0.6);">
                        ⏳ Waiting for Suricata to detect this asset...
                    </div>
                    """, unsafe_allow_html=True)
                    if st.button("🧰 isolater.py", key=f"run_iso_{primary_ip}", use_container_width=True):
                        with st.spinner(f"Running isolater.py for {primary_ip}..."):
                            ok, out, err, rc = run_isolater_for_ip(primary_ip)
                        if ok:
                            st.success(f"isolater.py exited 0 for {primary_ip}")
                            if out: st.code(out, language="bash")
                            st.rerun()
                        else:
                            st.error(f"isolater.py failed (rc={rc}) for {primary_ip}")
                            if out: st.code(out, language="bash")
                            if err: st.code(err, language="bash")

    # ================
    # 3) SURICATA FEED (kept, now below grid)
    # ================
    st.markdown("---")
    if suricata_alerts:
        st.markdown("### 🛡️ Live Suricata Feed")
        recent_alerts = suricata_alerts[-8:]
        for alert in reversed(recent_alerts):
            severity = alert.get('severity', 'LOW')
            sev_color = {
                'CRITICAL': '#ff4757','HIGH': '#ff6b35','MEDIUM': '#feca57','LOW': '#48dbfb','INFO': '#1dd1a1'
            }.get(severity, '#48dbfb')
            signature = alert.get('alert', {}).get('signature', 'Unknown Alert')
            truncated_sig = signature[:50] + "..." if len(signature) > 50 else signature
            src_ip = alert.get('src_ip', 'Unknown')
            dest_ip = alert.get('dest_ip', 'Unknown')

            st.markdown(f"""
            <div style="
                background: linear-gradient(135deg, rgba(15, 20, 25, 0.8) 0%, rgba(26, 29, 58, 0.8) 100%);
                border-left: 3px solid {sev_color};
                padding: 1rem; margin: 0.5rem 0; border-radius: 8px; font-size: 0.85rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <strong style="color: {sev_color};">{severity}</strong>
                    <span style="color: rgba(255,255,255,0.5); font-size: 0.75rem;">
                        {alert.get('timestamp', '')[:19]}
                    </span>
                </div>
                <div style="color: rgba(255,255,255,0.9); margin-bottom: 0.3rem;">
                    {truncated_sig}
                </div>
                <div style="color: rgba(255,255,255,0.6); font-size: 0.8rem;">
                    {src_ip} → {dest_ip}
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("🔍 Monitoring for Suricata alerts...")


with tab_feeds:
    st.markdown("### 📡 Real-Time Data Streams")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 🛰️ Simulated GNSS Feed")
        if sim_feed:
            try:
                df = pd.DataFrame(sim_feed[-20:])  # Show last 20 entries
                st.dataframe(df, use_container_width=True, height=300)
            except Exception as e:
                st.error(f"Error displaying sim feed: {e}")
        else:
            st.info("⏳ Waiting for simulated feed data...")

    with col2:
        st.markdown("#### 🚀 NASA Live Feed")
        if nasa_feed:
            try:
                df = pd.DataFrame(nasa_feed[-20:])
                st.dataframe(df, use_container_width=True, height=300)
            except Exception as e:
                st.error(f"Error displaying NASA feed: {e}")
        else:
            st.info("⏳ Waiting for NASA feed data...")

    # Suricata alerts section
    st.markdown("---")
    st.markdown("#### 🛡️ Suricata IDS Feed")
    if suricata_alerts:
        try:
            # Create a DataFrame from Suricata alerts
            suricata_df = []
            for alert in suricata_alerts[-20:]:  # Last 20 alerts
                suricata_df.append({
                    'Timestamp': alert.get('timestamp', '')[:19],
                    'Severity': alert.get('severity', 'INFO'),
                    'Source IP': alert.get('src_ip', 'Unknown'),
                    'Dest IP': alert.get('dest_ip', 'Unknown'),
                    'Signature': alert.get('alert', {}).get('signature', 'Unknown')[:60],
                    'Category': alert.get('alert', {}).get('category', 'Unknown')
                })
            
            if suricata_df:
                df_suricata = pd.DataFrame(suricata_df)
                st.dataframe(df_suricata, use_container_width=True, height=300)
        except Exception as e:
            st.error(f"Error displaying Suricata feed: {e}")
    else:
        st.info("⏳ Waiting for Suricata alerts...")

with tab_alerts:
    triage_table(merged_alerts[-50:], title="🚨 Global Threat Dashboard")

    if merged_alerts:
        # Alert severity breakdown
        severity_counts = {}
        source_counts = {}
        for alert in merged_alerts:
            sev = alert.get('severity', 'LOW')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            source = alert.get('source', 'Unknown')
            source_counts[source] = source_counts.get(source, 0) + 1

        st.markdown("---")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 📊 Threat Severity Breakdown")
            if severity_counts:
                try:
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
                            text="Alert Distribution by Severity",
                            font=dict(color='white', size=16)
                        ),
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='white'),
                        height=300
                    )

                    st.plotly_chart(fig, use_container_width=True)
                except Exception as e:
                    st.error(f"Error creating severity chart: {e}")

        with col2:
            st.markdown("### 🔍 Alert Sources")
            if source_counts:
                try:
                    # Create source breakdown chart
                    fig = go.Figure(data=[go.Bar(
                        x=list(source_counts.keys()),
                        y=list(source_counts.values()),
                        marker=dict(
                            color=['#4facfe', '#00f5d4', '#ff6b35', '#feca57', '#6c5ce7'][:len(source_counts)]
                        )
                    )])

                    fig.update_layout(
                        title=dict(
                            text="Alerts by Source System",
                            font=dict(color='white', size=16)
                        ),
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='white'),
                        xaxis=dict(
                            title="Source",
                            gridcolor='rgba(255,255,255,0.1)'
                        ),
                        yaxis=dict(
                            title="Alert Count",
                            gridcolor='rgba(255,255,255,0.1)'
                        ),
                        height=300
                    )

                    st.plotly_chart(fig, use_container_width=True)
                except Exception as e:
                    st.error(f"Error creating source chart: {e}")

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

    if merged_alerts:
        try:
            # Create timeline chart
            df_alerts = pd.DataFrame(merged_alerts)

            if 'timestamp' in df_alerts.columns:
                # Convert timestamps safely
                df_alerts['timestamp'] = pd.to_datetime(
                    df_alerts['timestamp'], errors='coerce', utc=True
                )

                # Drop invalid rows
                df_alerts = df_alerts.dropna(subset=['timestamp'])

                if not df_alerts.empty:
                    # Make sure it's datetime
                    if pd.api.types.is_datetime64_any_dtype(df_alerts['timestamp']):
                        df_alerts['hour'] = df_alerts['timestamp'].dt.floor('H')

                        hourly_alerts = (
                            df_alerts.groupby(['hour', 'severity'])
                                     .size()
                                     .unstack(fill_value=0)
                        )

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
        except Exception as e:
            st.error(f"Error creating analytics: {e}")


# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: rgba(255,255,255,0.5); padding: 2rem 0;">
    <div style="font-size: 0.9rem;">🛰️ CyberNOVA: SpaceShield — Protecting Critical Infrastructure</div>
    <div style="font-size: 0.8rem; margin-top: 0.5rem;">Advanced Cyber Defense • Real-Time Monitoring • Intelligent Response</div>
    <div style="font-size: 0.75rem; margin-top: 0.5rem; color: rgba(255,255,255,0.4);">
        File-based Alert System • Suricata Integration • Asset Status Monitoring
    </div>
</div>
""", unsafe_allow_html=True)

# Auto refresh
try:
    count = st_autorefresh(interval=refresh_ms, key="auto-refresh-ui")

    if count > 0:
        new_alert_count = len(new_alerts) if new_alerts else 0
        refresh_status = f"🔄 Live Monitor"
        if new_alert_count > 0:
            refresh_status = f"🚨 {new_alert_count} New Alert{'s' if new_alert_count > 1 else ''}"

        st.markdown(f"""
        <div style="
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: linear-gradient(135deg, rgba(15, 20, 25, 0.95) 0%, rgba(26, 29, 58, 0.95) 100%);
            border: 1px solid rgba(79, 172, 254, 0.3);
            border-radius: 12px;
            padding: 0.8rem 1.2rem;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            z-index: 1000;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        ">
            <div style="color: #4facfe; font-weight: 600;">{refresh_status}</div>
            <div style="color: rgba(255,255,255,0.6); font-size: 0.8rem;">Auto-refresh: {refresh_ms/1000}s</div>
        </div>
        """, unsafe_allow_html=True)
except Exception as e:
    st.error(f"Auto-refresh error: {e}")
