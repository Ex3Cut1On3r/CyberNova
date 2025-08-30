from sklearn.ensemble import IsolationForest
import numpy as np

class MLAnomalyDetector:
    def __init__(self, contamination=0.05, random_state=42):
        self.model = IsolationForest(contamination=contamination, random_state=random_state)
        self.trained = False

    def fit_on_feed(self, feed, feature="packet_count"):
        vals = [it.get(feature) for it in feed if it.get("feed_type")=="NETWORK_TRAFFIC" and isinstance(it.get(feature),(int,float))]
        if len(vals) < 30:
            return False
        X = np.array(vals[-500:]).reshape(-1,1)
        self.model.fit(X)
        self.trained = True
        return True

    def score_latest(self, feed, feature="packet_count"):
        if not self.trained:
            return None
        vals = [it.get(feature) for it in feed if it.get("feed_type")=="NETWORK_TRAFFIC" and isinstance(it.get(feature),(int,float))]
        if not vals:
            return None
        latest = np.array([[vals[-1]]])
        pred = self.model.predict(latest)[0]   # -1 = anomaly, 1 = normal
        score = self.model.decision_function(latest)[0]
        return {"anomaly": pred==-1, "score": float(score), "value": float(latest[0][0])}
