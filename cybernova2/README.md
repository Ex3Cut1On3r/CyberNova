cd CyberNOVA_SpaceShield
python -m app.generator &
python -m app.nasa_ingest &
streamlit run app/app.py


(usually u use wlan0)
# in another terminal
suricata -c /etc/suricata/suricata.yaml -i <your_interface>



or if using docker use this:
cd CyberNOVA_SpaceShield
docker compose up --build



structure: (minimal---> I didnt have time to upload the actual structure)
app/
  app.py
  generator.py
  nasa_ingest.py
  alert_schema.py
  utils.py
data/
  live_feed_data.json
  live_alerts.json
  nasa_live_feed_data.json
  nasa_live_alerts.json
config.yaml
Dockerfile
docker-compose.yml
requirements.txt
Makefile