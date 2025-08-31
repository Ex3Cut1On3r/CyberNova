# CyberNOVA: SpaceShield — Mission Control (Lebanon)

**See the Storm, Stop the Threat.**  
A hackathon-ready platform fusing **space weather intelligence (NASA DONKI)** with **cyber anomaly detection** to protect Lebanon’s critical infrastructure (aviation, maritime, telecom, power).

## 🔧 Quick Start (Local)

```bash
cd CyberNOVA_SpaceShield
python -m app.generator &
python -m app.nasa_ingest &
streamlit run app/app.py
```

> Optional: export `NASA_API_KEY` for live DONKI pulls. Without it, the app uses the sample data in `./data/`.

## 🐳 One-Click (Docker)

```bash
cd CyberNOVA_SpaceShield
# Optional: set your key
# export NASA_API_KEY=DEMO_KEY
docker compose up --build
# Open http://localhost:8501
```

## 📁 Structure
```
app/
  app.py            # Streamlit Mission Control
  generator.py      # Local cyber + GPS simulation + detections (deduped alerts)
  nasa_ingest.py    # NASA DONKI ingest (or local fallback), rate anomaly alerts
  alert_schema.py   # Pydantic alert model
  utils.py          # hashing, haversine, time helpers
data/
  live_feed_data.json       # simulator feed
  live_alerts.json          # simulator alerts
  nasa_live_feed_data.json  # NASA fallback feed (sample)
  nasa_live_alerts.json     # NASA fallback alerts (sample)
config.yaml         # thresholds & policies
Dockerfile
docker-compose.yml
requirements.txt
Makefile
```

## 🧠 What’s New vs Original
- **No infinite loops in UI** (auto-refresh instead)
- **Alert fingerprinting + dedupe** (no spam)
- **GPS speed-gate + Haversine spoof detection**
- **Unified Ops + Space Weather dashboards**
- **Env-based NASA API key**, clean Docker
- **Configurable thresholds** via `config.yaml`

## 🎤 Pitch (Use This)
> Lebanon doesn’t need to *own* satellites to lead in **space–cyber defense**. We already rely on satellites for GPS, aviation, ports, telecom. CyberNOVA fuses NASA space-weather signals with cyber anomaly detection to predict disruptions, stop spoofing/jamming, and protect our critical infrastructure. **See the storm, stop the threat.**
