#!/usr/bin/env python3
# suricata_ingest.py - File-based alert system with asset status tracking
import os
import json
import time
import logging
from pathlib import Path
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# File paths
EVE_JSON_PATH = "/var/log/suricata/eve.json"
ASSETS_FILE = "data/assets.json"
ALERTS_FILE = "data/alerts.json"
ASSET_STATUS_FILE = "data/asset_status.json"

# --- Load assets ---
def load_assets():
    """Load asset configuration from assets.json"""
    assets = {}
    if os.path.exists(ASSETS_FILE):
        try:
            with open(ASSETS_FILE) as f:
                data = json.load(f)
                for asset in data.get("assets", []):
                    for ip in asset.get("ips", []):
                        assets[ip] = {
                            "name": asset.get("name", asset.get("group", "Unknown")),
                            "type": asset.get("type", "Network Device"),
                            "segment": asset.get("segment", "DMZ"),
                            "group": asset.get("group", "default"),
                            "status": "offline",
                            "alert_count": 0,
                            "last_seen": None,
                            "first_detection": None
                        }
            logger.info(f"[Assets] Loaded {len(assets)} IPs from {ASSETS_FILE}")
        except Exception as e:
            logger.error(f"[Assets] Failed to load assets: {e}")
    return assets

# --- Save asset status ---
def save_asset_status(assets):
    """Save current asset status to JSON file"""
    try:
        os.makedirs(os.path.dirname(ASSET_STATUS_FILE), exist_ok=True)
        
        status_data = {
            "last_updated": datetime.now().isoformat(),
            "assets": {}
        }
        
        for ip, info in assets.items():
            status_data["assets"][ip] = {
                "name": info.get("name", "Unknown"),
                "type": info.get("type", "Network Device"),
                "segment": info.get("segment", "DMZ"),
                "group": info.get("group", "default"),
                "status": info.get("status", "offline"),
                "alert_count": info.get("alert_count", 0),
                "last_seen": info.get("last_seen"),
                "first_detection": info.get("first_detection")
            }
        
        with open(ASSET_STATUS_FILE, "w") as f:
            json.dump(status_data, f, indent=2)
        
        logger.info(f"[Assets] Updated asset status file")
        
    except Exception as e:
        logger.error(f"[Assets] Failed to save asset status: {e}")

# --- Save alerts ---
def save_alerts(alerts):
    """Save alerts to alerts.json file atomically"""
    try:
        os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
        
        # Keep only last 1000 alerts to prevent file from growing too large
        if len(alerts) > 1000:
            alerts = alerts[-1000:]
        
        # Write atomically to prevent corruption
        temp_file = ALERTS_FILE + ".tmp"
        with open(temp_file, "w") as f:
            json.dump(alerts, f, indent=2)
        
        os.replace(temp_file, ALERTS_FILE)
        logger.info(f"[Alerts] Saved {len(alerts)} alerts to {ALERTS_FILE}")
        
    except Exception as e:
        logger.error(f"[Alerts] Failed to save alerts: {e}")

# --- Load existing alerts ---
def load_alerts():
    """Load existing alerts from alerts.json"""
    try:
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE) as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"[Alerts] Failed to load alerts: {e}")
    return []

# --- Process Suricata alert ---
def process_suricata_alert(alert_data, assets, all_alerts):
    """Process a single Suricata alert and update asset status"""
    try:
        # Extract key information
        src_ip = alert_data.get("src_ip")
        dest_ip = alert_data.get("dest_ip")
        timestamp = alert_data.get("timestamp", datetime.now().isoformat())
        alert_info = alert_data.get("alert", {})
        
        # Determine severity based on alert signature and category
        signature = alert_info.get("signature", "").lower()
        category = alert_info.get("category", "").lower()
        
        # Basic severity mapping
        severity = "INFO"
        if any(keyword in signature for keyword in ["trojan", "malware", "virus", "backdoor"]):
            severity = "CRITICAL"
        elif any(keyword in signature for keyword in ["attack", "exploit", "intrusion", "suspicious"]):
            severity = "HIGH"
        elif any(keyword in signature for keyword in ["scan", "probe", "recon"]):
            severity = "MEDIUM"
        elif "policy" in category or "protocol" in category:
            severity = "LOW"
        
        # Enhanced alert object
        processed_alert = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "severity": severity,
            "alert": alert_info,
            "flow_id": alert_data.get("flow_id"),
            "proto": alert_data.get("proto"),
            "app_proto": alert_data.get("app_proto"),
            "processed_at": datetime.now().isoformat()
        }
        
        # Add to alerts list
        all_alerts.append(processed_alert)
        
        # Update asset status for both source and destination IPs
        current_time = datetime.now().isoformat()
        
        for ip in [src_ip, dest_ip]:
            if ip and ip in assets:
                assets[ip]["alert_count"] += 1
                assets[ip]["last_seen"] = current_time
                
                # Mark as online if we see traffic
                if assets[ip]["status"] != "online":
                    assets[ip]["status"] = "online" 
                    assets[ip]["first_detection"] = current_time
                    logger.info(f"[Asset] {ip} ({assets[ip]['name']}) marked ONLINE - Alert count: {assets[ip]['alert_count']}")
                
                # Log significant alert activity
                if assets[ip]["alert_count"] % 10 == 0:
                    logger.warning(f"[Asset] {ip} has {assets[ip]['alert_count']} alerts - High activity detected")
        
        return processed_alert
        
    except Exception as e:
        logger.error(f"[Processing] Failed to process alert: {e}")
        return None

# --- Asset status cleanup ---
def cleanup_offline_assets(assets):
    """Mark assets as offline if no alerts seen in last 10 minutes"""
    try:
        cutoff_time = datetime.now() - timedelta(minutes=10)
        
        for ip, info in assets.items():
            if info["status"] == "online" and info["last_seen"]:
                try:
                    last_seen = datetime.fromisoformat(info["last_seen"])
                    if last_seen < cutoff_time:
                        info["status"] = "offline"
                        logger.info(f"[Asset] {ip} ({info['name']}) marked OFFLINE - No recent activity")
                except Exception:
                    # If timestamp parsing fails, mark as offline
                    info["status"] = "offline"
                    
    except Exception as e:
        logger.error(f"[Cleanup] Asset cleanup error: {e}")

# --- Main monitoring function ---
def monitor_alerts():
    """Main function to monitor Suricata alerts and update asset status"""
    assets = load_assets()
    all_alerts = load_alerts()
    
    # Ensure eve.json exists
    if not os.path.exists(EVE_JSON_PATH):
        Path(EVE_JSON_PATH).touch()
        logger.warning(f"[IDS] Created empty eve.json at {EVE_JSON_PATH}")
    
    logger.info(f"[IDS] Starting monitoring of {EVE_JSON_PATH}")
    logger.info(f"[IDS] Tracking {len(assets)} assets")
    
    last_cleanup = time.time()
    last_save = time.time()
    
    try:
        with open(EVE_JSON_PATH, "r") as f:
            # Start from end of file to catch new alerts
            f.seek(0, os.SEEK_END)
            
            logger.info("[IDS] Monitoring started - waiting for new alerts...")
            
            while True:
                line = f.readline()
                
                if not line:
                    # No new data, sleep briefly
                    time.sleep(0.1)
                    
                    # Periodic cleanup and save (every 60 seconds)
                    current_time = time.time()
                    if current_time - last_cleanup > 60:
                        cleanup_offline_assets(assets)
                        last_cleanup = current_time
                    
                    if current_time - last_save > 30:
                        save_asset_status(assets)
                        save_alerts(all_alerts)
                        last_save = current_time
                    
                    continue
                
                try:
                    # Parse JSON line
                    data = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue
                
                # Only process alert events
                if data.get("event_type") != "alert":
                    continue
                
                # Process the alert
                processed_alert = process_suricata_alert(data, assets, all_alerts)
                if processed_alert:
                    logger.info(f"[Alert] Processed {processed_alert['severity']} alert: "
                              f"{processed_alert['src_ip']} → {processed_alert['dest_ip']}")
                
                    # Save immediately for high/critical alerts
                    if processed_alert['severity'] in ['HIGH', 'CRITICAL']:
                        save_alerts(all_alerts)
                        save_asset_status(assets)
                        logger.warning(f"[Alert] {processed_alert['severity']} alert - immediate save triggered")
                
    except Exception as e:
        logger.error(f"[IDS] Monitoring error: {e}")
        
    finally:
        # Final save on exit
        try:
            save_asset_status(assets)
            save_alerts(all_alerts)
            logger.info("[IDS] Final save completed")
        except Exception as e:
            logger.error(f"[IDS] Final save error: {e}")

# --- Status reporting ---
def print_status_report(assets):
    """Print a status report of all tracked assets"""
    logger.info("=== ASSET STATUS REPORT ===")
    
    online_count = sum(1 for info in assets.values() if info["status"] == "online")
    offline_count = len(assets) - online_count
    
    logger.info(f"Total Assets: {len(assets)} (Online: {online_count}, Offline: {offline_count})")
    
    for ip, info in assets.items():
        status_icon = "🟢" if info["status"] == "online" else "🔴"
        logger.info(f"{status_icon} {info['name']} ({ip}) - {info['status']} - Alerts: {info['alert_count']}")
    
    logger.info("=== END REPORT ===")

# --- Main entry point ---
if __name__ == "__main__":
    logger.info("🚀 Starting CyberNOVA Suricata Ingest - File-based Alert System")
    logger.info(f"📁 Monitoring: {EVE_JSON_PATH}")
    logger.info(f"📋 Assets: {ASSETS_FILE}")
    logger.info(f"🚨 Alerts Output: {ALERTS_FILE}")
    logger.info(f"📊 Status Output: {ASSET_STATUS_FILE}")
    
    # Initial status report
    assets = load_assets()
    print_status_report(assets)
    
    try:
        monitor_alerts()
    except KeyboardInterrupt:
        logger.info("🛑 Monitoring stopped by user")
        # Final status report
        assets = load_assets()
        print_status_report(assets)
    except Exception as e:
        logger.error(f"💥 Fatal error: {e}")
        raise
