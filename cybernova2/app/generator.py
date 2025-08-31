import os, json, time, random, datetime, yaml
from typing import List, Dict
from .utils import sha1_fingerprint, haversine_m, now_iso, uuid_str
from .alert_schema import Alert

BASE_LAT = 33.8953
BASE_LON = 35.4744

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(BASE_DIR, "data")

CONFIG_PATH = os.path.join(BASE_DIR, "config.yaml")
with open(CONFIG_PATH, 'r') as f:
    CFG = yaml.safe_load(f)

FEED_PATH = os.path.join(DATA_DIR, "live_feed_data.json")
ALERTS_PATH = os.path.join(DATA_DIR, "live_alerts.json")

MAX_FEED = CFG['retention']['max_feed_items']
MAX_ALERTS = CFG['retention']['max_alerts']

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

def severity_from_type(t: str) -> str:
    mapping = {
        "High Temp": "HIGH",
        "Low Battery": "HIGH",
        "High CPU": "MEDIUM",
        "Unauthorized Command": "HIGH",
        "Critical Command": "CRITICAL",
        "Failed Login": "LOW",
        "DDoS": "HIGH",
        "Large Packet": "MEDIUM",
        "GPS Spoofing": "HIGH",
        "GPS Accuracy": "MEDIUM",
        "GPS Jamming": "HIGH",
        "GPS Speed Gate": "HIGH",
    }
    return mapping.get(t, "LOW")

def gen_telemetry(anom=False):
    ts = now_iso()
    battery = random.uniform(70, 99)
    temp = random.uniform(20, 35)
    cpu = random.uniform(20, 50)
    if anom:
        which = random.choice(["HIGH_TEMP","LOW_BATTERY","HIGH_CPU"])
        if which == "HIGH_TEMP": temp = random.uniform(80, 120)
        elif which == "LOW_BATTERY": battery = random.uniform(5, 20)
        else: cpu = random.uniform(80,100)
    return {
        "feed_type": "TELEMETRY", "timestamp": ts,
        "satellite_id": "LEB-SAT-001", "battery_level": round(battery,2),
        "temperature_c": round(temp,2), "cpu_load_percent": round(cpu,1),
    }

def gen_command(anom=False):
    ts = now_iso()
    source_ips = ["192.168.1.10","192.168.1.11","192.168.1.12"]
    cmd_types = ["ORBIT_ADJUST","DOWNLOAD_DATA","ACTIVATE_SENSOR","STATUS_CHECK"]
    user_ids = ["operator_alpha","operator_beta","system_auto"]
    ip = random.choice(source_ips); user = random.choice(user_ids)
    cmd = random.choice(cmd_types); status = "SUCCESS"
    if anom:
        which = random.choice(["UNAUTHORIZED_IP","CRITICAL_CMD","FAILED_LOGIN"])
        if which == "UNAUTHORIZED_IP":
            ip = f"203.0.113.{random.randint(1,254)}"; user="unknown"; status="FAILED_AUTH"
        elif which == "CRITICAL_CMD":
            cmd="DEACTIVATE_TRANSPONDER"; user="unknown_hacker"; status="FAILED_AUTH"
        else:
            cmd="LOGIN_ATTEMPT"; status="FAILED"
    return {
        "feed_type":"COMMAND_LOG","timestamp":ts,"source_ip":ip,
        "user_id":user,"command_type":cmd,"status":status
    }

def gen_net(anom=False):
    ts = now_iso()
    src = f"192.168.1.{random.randint(10,20)}"
    pkts = random.randint(50,200)
    vol = random.randint(100,500)
    if anom:
        which = random.choice(["DDoS_SPIKE","LARGE_PACKET"])
        if which=="DDoS_SPIKE":
            pkts=random.randint(2000,5000); vol=random.randint(5000,10000); src=f"172.16.0.{random.randint(1,254)}"
        else:
            pkts=random.randint(10,20); vol=random.randint(1000,3000)
    return {"feed_type":"NETWORK_TRAFFIC","timestamp":ts,"source_ip":src,"dest_ip":"10.0.0.5",
            "packet_count":pkts,"data_volume_kb":vol}

def gen_gps(prev_lat, prev_lon, anom=False):
    ts = now_iso()
    lat = round(prev_lat + random.uniform(-0.00005, 0.00005), 6)
    lon = round(prev_lon + random.uniform(-0.00005, 0.00005), 6)
    acc = round(random.uniform(1.5,5.0),1)
    ss = random.randint(-125,-115)
    if anom:
        which = random.choice(["GPS_SPOOF","JAM"])
        if which=="GPS_SPOOF":
            lat = round(BASE_LAT + random.uniform(0.01,0.05),6)
            lon = round(BASE_LON + random.uniform(0.01,0.05),6)
            acc = round(random.uniform(10.0,50.0),1)
        else:
            acc = round(random.uniform(50.0,200.0),1); ss = random.randint(-160,-140)
    return {"feed_type":"GPS_SIGNAL","timestamp":ts,"receiver_id":"BEY_AIRPORT_GPS_01",
            "latitude":lat,"longitude":lon,"accuracy_m":acc,"signal_strength_db":ss}

def detect(feed: Dict, prev_gps: Dict):
    alerts = []
    t = feed["feed_type"]
    if t=="TELEMETRY":
        if feed["temperature_c"] > CFG['telemetry']['high_temp_c']:
            alerts.append(("High Temp", f"{feed['satellite_id']} - High Temperature ({feed['temperature_c']}°C)"))
        if feed["battery_level"] < CFG['telemetry']['low_battery_percent']:
            alerts.append(("Low Battery", f"{feed['satellite_id']} - Critical Low Battery ({feed['battery_level']}%)"))
        if feed["cpu_load_percent"] > CFG['telemetry']['high_cpu_percent']:
            alerts.append(("High CPU", f"{feed['satellite_id']} - High CPU Load ({feed['cpu_load_percent']}%)"))
    elif t=="COMMAND_LOG":
        whitelist = ["192.168.1.10","192.168.1.11","192.168.1.12"]
        critical = ["DEACTIVATE_TRANSPONDER","FACTORY_RESET","ORBIT_DECAY"]
        if feed["source_ip"] not in whitelist and feed.get("user_id")=="unknown":
            alerts.append(("Unauthorized Command", f"Unauthorized IP ({feed['source_ip']}) attempting '{feed['command_type']}'"))
        if feed["command_type"] in critical and feed.get("user_id")=="unknown_hacker":
            alerts.append(("Critical Command", f"Critical '{feed['command_type']}' from unknown user"))
        if "FAILED" in feed["status"] and feed["command_type"]=="LOGIN_ATTEMPT":
            alerts.append(("Failed Login", f"Failed login from {feed['source_ip']}"))
    elif t=="NETWORK_TRAFFIC":
        if feed["packet_count"] > CFG['network']['ddos_packets_min']:
            alerts.append(("DDoS", f"Traffic Spike ({feed['packet_count']} pkts) from {feed['source_ip']}"))
        if feed["data_volume_kb"] > CFG['network']['large_packet_kb_min'] and feed["packet_count"] < CFG['network']['large_packet_packets_max']:
            alerts.append(("Large Packet", f"Large Packet ({feed['data_volume_kb']}KB) from {feed['source_ip']}"))
    elif t=="GPS_SIGNAL":
        # spoofing by jump
        if prev_gps:
            dist_m = haversine_m(prev_gps['latitude'], prev_gps['longitude'], feed['latitude'], feed['longitude'])
            # compute time diff ~ assuming ~1s cadence
            if dist_m > CFG['gps']['spoofing_deg_threshold']*111000:  # approx deg->m
                alerts.append(("GPS Spoofing", f"{feed['receiver_id']} - Position jump {int(dist_m)} m"))
            # speed gate
            # If we had accurate dt we could divide; assume 1s interval for generator
            if dist_m > CFG['gps']['speed_m_s_threshold']:
                alerts.append(("GPS Speed Gate", f"{feed['receiver_id']} - Unrealistic move {int(dist_m)} m/s"))
        if feed["accuracy_m"] > CFG['gps']['degraded_accuracy_m']:
            alerts.append(("GPS Accuracy", f"{feed['receiver_id']} - Degraded accuracy ({feed['accuracy_m']} m)"))
        if feed["signal_strength_db"] < CFG['gps']['weak_signal_db']:
            alerts.append(("GPS Jamming", f"{feed['receiver_id']} - Weak signal ({feed['signal_strength_db']} dB)"))
    return alerts

def build_alert(src, typ, desc):
    ts = now_iso()
    fp = sha1_fingerprint(src, typ, desc, ts[:16])  # minute bucket
    return Alert(
        id=uuid_str(), source=src, type=typ, severity=severity_from_type(typ),
        timestamp=ts, labels={}, description=desc, fingerprint=fp
    ).model_dump()

def run():
    feed = load_json(FEED_PATH, [])
    alerts = load_json(ALERTS_PATH, [])
    prev_gps = None
    for it in feed[::-1]:
        if it.get("feed_type")=="GPS_SIGNAL":
            prev_gps = it; break

    print("[SIM] Starting generator. Writing to", FEED_PATH, ALERTS_PATH)
    while True:
        anom = random.random() < 0.18
        items = [
            gen_telemetry(anom), gen_command(anom),
            gen_net(anom), gen_gps(prev_gps['latitude'] if prev_gps else BASE_LAT,
                                    prev_gps['longitude'] if prev_gps else BASE_LON, anom)
        ]

        # detect
        cycle_alerts = []
        for it in items:
            for typ, desc in detect(it, prev_gps if it['feed_type']=="GPS_SIGNAL" else {}):
                cycle_alerts.append(build_alert("SIM", typ, desc))
            if it['feed_type']=="GPS_SIGNAL":
                prev_gps = it

        # append & cap
        feed.extend(items); feed = feed[-MAX_FEED:]
        # de-dupe recent (by fingerprint) within last 100 alerts
        seen = {a.get('id') for a in alerts[-100:] if 'id' in a}

        for a in cycle_alerts:
            if a['fingerprint'] not in seen:
                alerts.append(a); seen.add(a['fingerprint'])
        alerts = alerts[-MAX_ALERTS:]

        save_json(FEED_PATH, feed); save_json(ALERTS_PATH, alerts)
        time.sleep(1)

if __name__ == "__main__":
    run()
