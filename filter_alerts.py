import json
import os
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def filter_alerts(input_file, output_file):
    logs = []
    filtered_alerts = []

    try:
        with open(input_file, "r") as f:
            try:
                alerts = json.load(f)
                if not isinstance(alerts, list):
                    raise ValueError("Input must be a JSON array")
            except json.JSONDecodeError:
                f.seek(0)
                alerts = [json.loads(line.strip()) for line in f.read().splitlines() if line.strip()]
    except Exception as e:
        logs.append(f"Error reading {input_file}: {str(e)}")
        return filtered_alerts, logs

    for alert in alerts:
        severity = alert.get("rule", {}).get("level", "N/A")
        if severity == "N/A" or int(severity) < 5:
            continue
        filtered = {
            "timestamp": alert.get("timestamp", "N/A"),
            "event_id": alert.get("rule", {}).get("id", "N/A"),
            "description": alert.get("rule", {}).get("description", "N/A"),
            "severity": severity,
            "agent_id": alert.get("agent", {}).get("id", "N/A"),
            "agent_name": alert.get("agent", {}).get("name", "N/A"),
            "source_ip": alert.get("data", {}).get("srcip", "N/A"),
            "destination_ip": alert.get("data", {}).get("dstip", "N/A"),
            "source_port": alert.get("data", {}).get("srcport", "N/A"),
            "destination_port": alert.get("data", {}).get("dstport", "N/A"),
            "protocol": alert.get("data", {}).get("protocol", "N/A"),
            "file_path": alert.get("data", {}).get("file", "N/A"),
            "file_hash": alert.get("data", {}).get("sha256", alert.get("data", {}).get("md5", "N/A")),
            "event_details": {},
            "raw_log": alert.get("full_log", "N/A")[:50],
            "category": alert.get("rule", {}).get("groups", ["N/A"])[0]
        }
        filtered_alerts.append(filtered)

    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(filtered_alerts, f, indent=2)
        logs.append(f"Filtered {len(filtered_alerts)} alerts into {output_file}")
    except Exception as e:
        logs.append(f"Error writing to {output_file}: {str(e)}")

    return filtered_alerts, logs

if __name__ == "__main__":
    input_file = os.path.join(os.path.dirname(__file__), "..", "data", "alerts.json")
    output_file = os.path.join(os.path.dirname(__file__), "..", "data", "filtered_alerts.json")
    _, logs = filter_alerts(input_file, output_file)
    for log in logs:
        logger.info(log)