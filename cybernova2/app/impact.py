def impact_from_alert(alert):
    t = (alert.get("type") or "").lower()
    impacts = []

    def add(domain, level, note):
        impacts.append({"domain": domain, "level": level, "note": note})

    if "gps" in t:
        add("Aviation", "HIGH", "Navigation integrity risk near airport/flight routes")
        add("Maritime", "MEDIUM", "Course deviation risk for port approaches")
        add("Telecom", "LOW", "Timing source degradation")
    if "ddos" in t or "network" in t:
        add("Telecom", "HIGH", "Traffic saturation / packet loss")
        add("Operations", "MEDIUM", "Service degradation for ground stations")
    if "solar flare" in t or "cme" in t or "geomagnetic" in t:
        add("Aviation", "MEDIUM", "HF comms degraded; GNSS accuracy impacted")
        add("Power", "MEDIUM", "Geomagnetically induced currents risk")
        add("Telecom", "MEDIUM", "Ionospheric disturbance → signal noise")
    if "critical command" in t or "unauthorized" in t:
        add("Operations", "HIGH", "Potential hostile control attempt")
        add("Security", "HIGH", "Access control failure")
    if not impacts:
        add("General", "LOW", "Monitor")

    return impacts
