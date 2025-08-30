#!/usr/bin/env python3
# suricata_ingest.py - Enhanced Suricata eve.json log processor
import os, json, time, datetime, hashlib
import threading
from collections import defaultdict

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
EVE_PATH = os.path.join(DATA_DIR, "suricata", "eve.json")
HOST_EVENTS_PATH = os.path.join(DATA_DIR, "host_isolation_events.json")
SURICATA_STATE_PATH = os.path.join(DATA_DIR, "suricata_state.json")

# Configuration
MAX_EVENTS = 1000  # Maximum events to keep in memory
DEDUP_WINDOW = 300  # 5 minutes deduplication window
BATCH_SIZE = 50    # Process alerts in batches
CHECK_INTERVAL = 1  # Check eve.json every second

def load_json(path, default):
    """Load JSON file with error handling"""
    try:
        if not os.path.exists(path):
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[IDS] Error loading {path}: {e}")
        return default

def save_json_atomic(path, obj):
    """Atomically save JSON to prevent corruption"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception as e:
        print(f"[IDS] Error saving {path}: {e}")

def get_severity_from_priority(priority):
    """Map Suricata priority to severity levels"""
    try:
        prio = int(priority)
        if prio == 1:
            return "CRITICAL"
        elif prio == 2:
            return "HIGH"
        elif prio == 3:
            return "MEDIUM"
        else:
            return "LOW"
    except (ValueError, TypeError):
        return "MEDIUM"

def get_alert_category(signature):
    """Categorize alerts based on signature content"""
    sig_lower = signature.lower() if signature else ""

    if any(keyword in sig_lower for keyword in ["trojan", "malware", "backdoor", "virus"]):
        return "Malware"
    elif any(keyword in sig_lower for keyword in ["dos", "flood", "scan"]):
        return "Network Attack"
    elif any(keyword in sig_lower for keyword in ["exploit", "shellcode", "rce"]):
        return "Exploitation"
    elif any(keyword in sig_lower for keyword in ["dns", "domain", "c2", "botnet"]):
        return "C2 Communication"
    elif any(keyword in sig_lower for keyword in ["web", "http", "sql", "xss"]):
        return "Web Attack"
    else:
        return "General"

def create_alert_hash(alert_data):
    """Create hash for deduplication"""
    key_data = f"{alert_data.get('src_ip')}-{alert_data.get('dest_ip')}-{alert_data.get('signature_id')}"
    return hashlib.md5(key_data.encode()).hexdigest()[:12]

def parse_suricata_alert(eve_line):
    """Parse a single line from eve.json into standardized alert format"""
    try:
        obj = json.loads(eve_line.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    # Only process alert events
    if obj.get("event_type") != "alert":
        return None

    alert = obj.get("alert", {})
    flow = obj.get("flow", {})

    # Extract key information
    timestamp = obj.get("timestamp", datetime.datetime.utcnow().isoformat() + "Z")
    src_ip = obj.get("src_ip", "unknown")
    dest_ip = obj.get("dest_ip", "unknown")
    src_port = obj.get("src_port", 0)
    dest_port = obj.get("dest_port", 0)

    signature = alert.get("signature", "Unknown Alert")
    signature_id = alert.get("signature_id", 0)
    category = alert.get("category", "Unknown")
    priority = alert.get("priority", 3)

    # Enhanced severity mapping
    severity = get_severity_from_priority(priority)
    alert_category = get_alert_category(signature)

    # Protocol information
    protocol = obj.get("proto", "unknown").upper()
    flow_state = flow.get("state", "unknown")

    # Create standardized alert
    parsed_alert = {
        "id": f"SUR_{signature_id}_{create_alert_hash(obj)}",
        "timestamp": timestamp,
        "source": "Suricata IDS",
        "severity": severity,
        "priority": int(priority),
        "type": alert_category,
        "signature": signature,
        "signature_id": int(signature_id),
        "category": category,
        "host": src_ip,  # Primary host for isolation targeting
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": int(src_port),
        "dest_port": int(dest_port),
        "protocol": protocol,
        "flow_state": flow_state,
        "description": f"{signature} ({protocol} {src_ip}:{src_port} -> {dest_ip}:{dest_port})",
        "reason": f"Suricata Rule {signature_id}: {category}",
        "details": f"Alert triggered by signature '{signature}' from {src_ip} to {dest_ip}",
        "status": "active",
        "raw_event": obj  # Keep original for debugging
    }

    return parsed_alert

class SuricataProcessor:
    """Enhanced Suricata log processor with deduplication and batching"""

    def __init__(self):
        self.last_position = 0
        self.alert_cache = {}  # For deduplication
        self.stats = {
            "processed": 0,
            "alerts": 0,
            "duplicates": 0,
            "errors": 0,
            "last_update": None
        }
        self.load_state()

    def load_state(self):
        """Load processor state from disk"""
        state = load_json(SURICATA_STATE_PATH, {})
        self.last_position = state.get("last_position", 0)
        self.stats.update(state.get("stats", {}))

    def save_state(self):
        """Save processor state to disk"""
        state = {
            "last_position": self.last_position,
            "stats": self.stats,
            "updated": datetime.datetime.utcnow().isoformat() + "Z"
        }
        save_json_atomic(SURICATA_STATE_PATH, state)

    def cleanup_old_alerts(self, alerts):
        """Remove old alerts and duplicates"""
        now = datetime.datetime.utcnow()
        cutoff = now - datetime.timedelta(seconds=DEDUP_WINDOW)

        # Clean up alert cache
        keys_to_remove = []
        for key, timestamp in self.alert_cache.items():
            if datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00')) < cutoff:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.alert_cache[key]

        # Keep only recent alerts
        return alerts[-MAX_EVENTS:]

    def is_duplicate(self, alert):
        """Check if alert is a recent duplicate"""
        alert_hash = create_alert_hash(alert.get("raw_event", {}))
        current_time = alert.get("timestamp")

        if alert_hash in self.alert_cache:
            last_seen = self.alert_cache[alert_hash]
            last_time = datetime.datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
            current_dt = datetime.datetime.fromisoformat(current_time.replace('Z', '+00:00'))

            # If we've seen this alert recently, it's a duplicate
            if (current_dt - last_time).total_seconds() < DEDUP_WINDOW:
                self.stats["duplicates"] += 1
                return True

        # Not a duplicate, cache it
        self.alert_cache[alert_hash] = current_time
        return False

    def process_new_lines(self):
        """Process new lines from eve.json since last check"""
        if not os.path.exists(EVE_PATH):
            return []

        try:
            current_size = os.path.getsize(EVE_PATH)

            # If file was rotated/truncated, reset position
            if current_size < self.last_position:
                self.last_position = 0

            # If no new data, return empty
            if current_size == self.last_position:
                return []

            new_alerts = []

            with open(EVE_PATH, "r", encoding="utf-8") as f:
                f.seek(self.last_position)

                lines_processed = 0
                for line in f:
                    self.stats["processed"] += 1
                    lines_processed += 1

                    try:
                        alert = parse_suricata_alert(line)
                        if alert and not self.is_duplicate(alert):
                            new_alerts.append(alert)
                            self.stats["alerts"] += 1
                    except Exception as e:
                        self.stats["errors"] += 1
                        print(f"[IDS] Parse error: {e}")

                    # Process in batches to avoid memory issues
                    if lines_processed >= BATCH_SIZE:
                        break

                self.last_position = f.tell()

            if new_alerts:
                print(f"[IDS] Processed {len(new_alerts)} new alerts from Suricata")

            return new_alerts

        except Exception as e:
            print(f"[IDS] Error processing eve.json: {e}")
            self.stats["errors"] += 1
            return []

    def update_host_events(self, new_alerts):
        """Update host events file with new alerts"""
        if not new_alerts:
            return

        events = load_json(HOST_EVENTS_PATH, [])
        events.extend(new_alerts)

        # Clean up old events
        events = self.cleanup_old_alerts(events)

        save_json_atomic(HOST_EVENTS_PATH, events)
        self.stats["last_update"] = datetime.datetime.utcnow().isoformat() + "Z"
        self.save_state()

        print(f"[IDS] Updated host events with {len(new_alerts)} new alerts")

def monitor_suricata():
    """Main monitoring function"""
    processor = SuricataProcessor()

    print(f"[IDS] Starting Suricata monitor")
    print(f"[IDS] Eve.json path: {EVE_PATH}")
    print(f"[IDS] Host events path: {HOST_EVENTS_PATH}")
    print(f"[IDS] Deduplication window: {DEDUP_WINDOW}s")
    print(f"[IDS] Max events: {MAX_EVENTS}")

    consecutive_errors = 0
    max_consecutive_errors = 10

    while True:
        try:
            new_alerts = processor.process_new_lines()
            processor.update_host_events(new_alerts)

            # Reset error counter on success
            consecutive_errors = 0

            # Print stats periodically
            if processor.stats["processed"] % 100 == 0 and processor.stats["processed"] > 0:
                print(f"[IDS] Stats - Processed: {processor.stats['processed']}, "
                      f"Alerts: {processor.stats['alerts']}, "
                      f"Duplicates: {processor.stats['duplicates']}, "
                      f"Errors: {processor.stats['errors']}")

            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("[IDS] Shutting down Suricata monitor")
            break
        except Exception as e:
            consecutive_errors += 1
            print(f"[IDS] Monitor error ({consecutive_errors}/{max_consecutive_errors}): {e}")

            if consecutive_errors >= max_consecutive_errors:
                print("[IDS] Too many consecutive errors, exiting")
                break

            time.sleep(5)  # Longer sleep on error

def create_test_alerts():
    """Generate test alerts for development/testing"""
    test_alerts = [
        {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event_type": "alert",
            "src_ip": "192.168.56.101",
            "dest_ip": "10.0.0.1",
            "src_port": 54321,
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature": "ET TROJAN Possible Malware Communication",
                "signature_id": 2001234,
                "priority": 1,
                "category": "Trojan"
            }
        },
        {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event_type": "alert",
            "src_ip": "10.0.0.50",
            "dest_ip": "192.168.56.101",
            "src_port": 12345,
            "dest_port": 22,
            "proto": "TCP",
            "alert": {
                "signature": "ET SCAN SSH Brute Force Login Attempt",
                "signature_id": 2001471,
                "priority": 2,
                "category": "Attempted Login"
            }
        },
        {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event_type": "alert",
            "src_ip": "192.168.56.101",
            "dest_ip": "8.8.8.8",
            "src_port": 53281,
            "dest_port": 53,
            "proto": "UDP",
            "alert": {
                "signature": "ET DNS Query for Suspicious Domain",
                "signature_id": 2008545,
                "priority": 2,
                "category": "Potentially Bad Traffic"
            }
        }
    ]

    # Write test alerts to eve.json
    os.makedirs(os.path.dirname(EVE_PATH), exist_ok=True)
    with open(EVE_PATH, "w", encoding="utf-8") as f:
        for alert in test_alerts:
            f.write(json.dumps(alert) + "\n")

    print(f"[IDS] Created {len(test_alerts)} test alerts in {EVE_PATH}")

def validate_eve_format():
    """Validate that eve.json exists and has correct format"""
    if not os.path.exists(EVE_PATH):
        print(f"[IDS] Warning: eve.json not found at {EVE_PATH}")
        return False

    try:
        with open(EVE_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
            if not lines:
                print("[IDS] Warning: eve.json is empty")
                return False

            # Check first few lines for valid JSON
            valid_count = 0
            for i, line in enumerate(lines[:5]):
                try:
                    obj = json.loads(line.strip())
                    if obj.get("event_type"):
                        valid_count += 1
                except:
                    continue

            if valid_count == 0:
                print("[IDS] Warning: No valid JSON events found in eve.json")
                return False

            print(f"[IDS] eve.json validation passed ({len(lines)} lines, {valid_count}/5 valid)")
            return True

    except Exception as e:
        print(f"[IDS] Error validating eve.json: {e}")
        return False

class SuricataStats:
    """Track and display Suricata processing statistics"""

    def __init__(self):
        self.reset()

    def reset(self):
        self.start_time = datetime.datetime.utcnow()
        self.total_lines = 0
        self.total_alerts = 0
        self.total_duplicates = 0
        self.total_errors = 0
        self.alert_types = defaultdict(int)
        self.severity_counts = defaultdict(int)

    def update(self, alerts):
        """Update stats with new alerts"""
        for alert in alerts:
            self.total_alerts += 1
            self.alert_types[alert.get("type", "Unknown")] += 1
            self.severity_counts[alert.get("severity", "LOW")] += 1

    def get_summary(self):
        """Get formatted statistics summary"""
        runtime = datetime.datetime.utcnow() - self.start_time

        return {
            "runtime_seconds": int(runtime.total_seconds()),
            "total_lines": self.total_lines,
            "total_alerts": self.total_alerts,
            "total_duplicates": self.total_duplicates,
            "total_errors": self.total_errors,
            "alerts_per_minute": round(self.total_alerts / max(runtime.total_seconds() / 60, 1), 2),
            "alert_types": dict(self.alert_types),
            "severity_counts": dict(self.severity_counts)
        }

def run_enhanced_monitor():
    """Enhanced monitoring with stats and better error handling"""
    processor = SuricataProcessor()
    stats = SuricataStats()

    print("[IDS] Enhanced Suricata Monitor Starting")
    print(f"[IDS] Monitoring: {EVE_PATH}")
    print(f"[IDS] Output: {HOST_EVENTS_PATH}")
    print(f"[IDS] Check interval: {CHECK_INTERVAL}s")
    print(f"[IDS] Deduplication window: {DEDUP_WINDOW}s")

    # Validate setup
    if not validate_eve_format():
        print("[IDS] Consider running with --create-test to generate sample data")

    last_stats_print = time.time()

    while True:
        try:
            new_alerts = processor.process_new_lines()

            if new_alerts:
                processor.update_host_events(new_alerts)
                stats.update(new_alerts)

                print(f"[IDS] Added {len(new_alerts)} new alerts to triage feed")

                # Print sample of new alerts
                for alert in new_alerts[:3]:  # Show first 3
                    print(f"[IDS]   -> {alert['severity']} | {alert['src_ip']} | {alert['signature']}")

            # Print periodic stats
            if time.time() - last_stats_print > 60:  # Every minute
                summary = stats.get_summary()
                print(f"[IDS] Stats: {summary['total_alerts']} alerts, "
                      f"{summary['alerts_per_minute']} alerts/min, "
                      f"Runtime: {summary['runtime_seconds']}s")
                last_stats_print = time.time()

            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("\n[IDS] Shutting down Suricata monitor")
            break
        except Exception as e:
            print(f"[IDS] Monitor error: {e}")
            stats.total_errors += 1
            time.sleep(5)

    # Final stats
    final_stats = stats.get_summary()
    print(f"[IDS] Final Stats: {json.dumps(final_stats, indent=2)}")

# Legacy function for backward compatibility
def tail_eve():
    """Legacy function - redirects to enhanced monitor"""
    run_enhanced_monitor()

if __name__ == "__main__":
    import sys

    if "--create-test" in sys.argv:
        create_test_alerts()
        print("[IDS] Test alerts created. Run without --create-test to start monitoring.")
    elif "--validate" in sys.argv:
        validate_eve_format()
    elif "--stats" in sys.argv:
        state = load_json(SURICATA_STATE_PATH, {})
        print(f"[IDS] Current state: {json.dumps(state, indent=2)}")
    else:
        run_enhanced_monitor()