import json
import os
import hashlib
import numpy as np
from datetime import datetime, timedelta
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import re
from scipy.stats import entropy
import asyncio
import aiohttp
from aiohttp import ClientTimeout
from collections import defaultdict
import pytz
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
import requests
from web3 import Web3
from tenacity import retry, wait_exponential, stop_after_attempt
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")
PINATA_API_KEY = os.getenv("PINATA_API_KEY")
PINATA_API_SECRET = os.getenv("PINATA_API_SECRET")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")

# Define constants
CRITICAL_KEYWORDS = {"trojan", "malware", "ransomware", "exploit", "critical", "root", "bash", "signature", "error"}
CRITICAL_PATHS = {"/bin", "/usr/bin", "system32"}
BENIGN_SERVICES = {"MpKsl", "NordVPN", "Windows Defender"}
TIME_WINDOW = timedelta(minutes=30)
THREAT_CACHE = defaultdict(dict)
BATCH_SIZE = 10  # Number of alerts to process in each batch
SUBMITTED_INCIDENTS_FILE = "submitted_incidents.json"  # File to track submitted incidents

# Load or initialize submitted incidents tracking
if os.path.exists(SUBMITTED_INCIDENTS_FILE):
    with open(SUBMITTED_INCIDENTS_FILE, "r") as f:
        SUBMITTED_INCIDENTS = set(json.load(f))
else:
    SUBMITTED_INCIDENTS = set()

# Initialize Web3.py for blockchain interaction
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))  # Adjust to your blockchain node URL
if not w3.is_connected():
    raise Exception("Failed to connect to blockchain node")
account = w3.eth.account.from_key(PRIVATE_KEY)

# Load smart contract ABI
contract_path = os.path.join(
    os.path.dirname(__file__), "..", "blockchain", "artifacts", "contracts",
    "IncidentResponse.sol", "IncidentResponse.json"
)
with open(contract_path, "r") as f:
    contract_abi = json.load(f)["abi"]
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)

# Mapping for smart contract enums and levels
CLASSIFICATION_MAP = {
    "REAL_THREAT": 0,
    "FALSE_POSITIVE": 1,
    "POTENTIAL_FALSE_NEGATIVE": 2
}
INCIDENT_LEVEL_MAP = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3
}

async def fetch_threat_intel(session, alert, retries=3, timeout=5):
    """
    Fetch threat intelligence from VirusTotal, OTX, and GreyNoise for an alert.
    """
    src_ip = alert.get("source_ip", "N/A")
    file_path = alert.get("file_path", "N/A")
    service_name = alert.get("event_details", {}).get("serviceName", "N/A")
    full_log = alert.get("raw_log", "") or ""
    filename = file_path.split('/')[-1].split('\\')[-1] if file_path != "N/A" else None
    intel = {"is_known_threat": False, "reputation_score": 0.0, "threat_confidence": 0.0}

    async def query_vt(identifier):
        if not VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal API key not provided")
            return 0, 0
        if identifier in THREAT_CACHE["vt"]:
            return THREAT_CACHE["vt"][identifier]
        try:
            async with session.get(
                f"https://www.virustotal.com/api/v3/files/{identifier}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=ClientTimeout(total=timeout)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    positives = stats.get("malicious", 0)
                    total = sum(stats.values())
                    confidence = positives / total if total > 0 else 0
                    THREAT_CACHE["vt"][identifier] = (positives, confidence)
                    return positives, confidence
                return 0, 0
        except Exception as e:
            logger.warning(f"VirusTotal query failed: {e}")
            return 0, 0

    async def query_otx(identifier, type_="file"):
        if not OTX_API_KEY:
            logger.warning("OTX API key not provided")
            return 0, 0
        if identifier in THREAT_CACHE["otx"]:
            return THREAT_CACHE["otx"][identifier]
        try:
            async with session.get(
                f"https://otx.alienvault.com/api/v1/indicators/{type_}/{identifier}/general",
                headers={"X-OTX-API-KEY": OTX_API_KEY},
                timeout=ClientTimeout(total=timeout)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    pulse_count = data.get("pulse_info", {}).get("count", 0)
                    confidence = min(1.0, pulse_count * 0.15)
                    THREAT_CACHE["otx"][identifier] = (pulse_count, confidence)
                    return pulse_count, confidence
                return 0, 0
        except Exception as e:
            logger.warning(f"OTX query failed: {e}")
            return 0, 0

    try:
        if src_ip != "N/A" and GREYNOISE_API_KEY:
            async with session.get(
                f"https://api.greynoise.io/v3/noise/quick/{src_ip}",
                headers={"key": GREYNOISE_API_KEY}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("noise", False):
                        intel["reputation_score"] = -0.6
                        intel["threat_confidence"] = 0.0
                        return intel

        if src_ip != "N/A" and OTX_API_KEY:
            pulse_count, confidence = await query_otx(src_ip, "IPv4")
            if pulse_count > 0:
                intel["is_known_threat"] = True
                intel["reputation_score"] = min(1.0, pulse_count * 0.3)
                intel["threat_confidence"] = confidence

        if filename and OTX_API_KEY:
            pulse_count, confidence = await query_otx(filename)
            if pulse_count > 0:
                intel["is_known_threat"] = True
                intel["reputation_score"] = min(1.0, pulse_count * 0.3)
                intel["threat_confidence"] = max(intel["threat_confidence"], confidence)

        hash_pattern = r'[a-fA-F0-9]{32,64}'
        hashes = re.findall(hash_pattern, full_log)
        if hashes and VIRUSTOTAL_API_KEY:
            positives, confidence = await query_vt(hashes[0])
            if positives > 0:
                intel["is_known_threat"] = True
                intel["reputation_score"] = min(1.0, positives * 0.2)
                intel["threat_confidence"] = confidence
        elif filename and VIRUSTOTAL_API_KEY:
            positives, confidence = await query_vt(filename)
            if positives > 0:
                intel["is_known_threat"] = True
                intel["reputation_score"] = min(1.0, positives * 0.2)
                intel["threat_confidence"] = confidence

        if service_name != "N/A" and any(s in service_name for s in BENIGN_SERVICES):
            intel["reputation_score"] = max(intel["reputation_score"], -0.7)
            intel["threat_confidence"] = 0.0

    except Exception as e:
        logger.warning(f"Threat intel fetch failed for {alert.get('timestamp', 'N/A')}: {e}")

    return intel

def extract_features(alert, intel):
    """
    Extract features from an alert for ML analysis.
    """
    try:
        ts = datetime.fromisoformat(alert.get("timestamp", "").replace("+0100", "+01:00"))
    except (ValueError, TypeError):
        logger.warning(f"Invalid timestamp in alert: {alert.get('timestamp', 'N/A')}")
        return None
    minutes_since_midnight = (ts.hour * 60) + ts.minute
    rule_level = alert.get("severity", 0)
    full_log = alert.get("raw_log", "") or alert.get("description", "") or ""
    file_path = alert.get("file_path", "N/A")

    words = re.findall(r'\w+', full_log.lower())
    keyword_count = sum(1 for word in words if word in CRITICAL_KEYWORDS)
    keyword_density = min(1.0, keyword_count * 0.15)
    log_length = len(full_log) / 1000.0
    char_counts = np.array([full_log.count(c) for c in set(full_log)])
    log_entropy = entropy(char_counts) if len(char_counts) > 0 else 0
    is_critical_path = 1 if any(p in file_path for p in CRITICAL_PATHS) else 0
    threat_rep = intel["reputation_score"]
    threat_conf = intel["threat_confidence"]

    return [minutes_since_midnight, rule_level, keyword_density, log_length, log_entropy, is_critical_path, threat_rep, threat_conf]

def compute_temporal_correlation(alerts, alert):
    """
    Compute temporal correlation score for an alert.
    """
    try:
        alert_ts = datetime.fromisoformat(alert.get("timestamp", "").replace("+0100", "+01:00"))
    except (ValueError, TypeError):
        return 0.0
    src_ip = alert.get("source_ip", "unknown")
    window_start = alert_ts - TIME_WINDOW
    related_count = sum(1 for a in alerts if 
                        datetime.fromisoformat(a.get("timestamp", "").replace("+0100", "+01:00")) >= window_start and
                        a.get("source_ip", "unknown") == src_ip)
    return min(1.0, related_count * 0.25)

def upload_to_ipfs(alert, pinata_api_key, pinata_api_secret):
    """
    Upload alert data to IPFS via Pinata and return the CID.
    """
    if not pinata_api_key or not pinata_api_secret:
        logger.error("Pinata API keys missing")
        raise ValueError("Pinata API keys are required for IPFS upload")
    url = "https://api.pinata.cloud/pinning/pinJSONToIPFS"
    headers = {
        "pinata_api_key": pinata_api_key,
        "pinata_secret_api_key": pinata_api_secret,
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(url, headers=headers, json=alert, timeout=30)
        response.raise_for_status()
        cid = response.json()["IpfsHash"]
        logger.info(f"Uploaded to IPFS: CID {cid}")
        return cid
    except requests.RequestException as e:
        logger.error(f"Failed to upload alert to IPFS: {str(e)}")
        raise

@retry(wait=wait_exponential(multiplier=1, min=4, max=10), stop=stop_after_attempt(5))
def submit_batch_to_blockchain(batch):
    """Submit a batch of alerts to the blockchain and process event logs for automated responses."""
    try:
        # Prepare batch data for the smart contract
        hashes = [hashlib.sha256(json.dumps(alert["original_alert"]).encode()).digest() for alert in batch]
        ipfs_cids = [alert["ipfsCid"] for alert in batch]
        details_digests = [w3.keccak(text=json.dumps(alert["details"], sort_keys=True)) for alert in batch]
        classifications = [CLASSIFICATION_MAP[alert["classification"]] for alert in batch]
        incident_levels = [INCIDENT_LEVEL_MAP[alert["threatLevel"]] for alert in batch]

        # Build and sign the transaction
        tx = contract.functions.logIncidentsBatch(
            hashes, ipfs_cids, details_digests, classifications, incident_levels
        ).build_transaction({
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "gas": 5000000,  # Adjust gas limit based on batch size
            "gasPrice": w3.eth.gas_price,
            "chainId": 31337  # Adjust to your network's chain ID
        })

        signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        logger.info(f"Submitted batch to blockchain: {tx_hash.hex()}")

        # Wait for transaction receipt
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status == 1:
            for alert in batch:
                alert["blockchain_tx_hash"] = tx_hash.hex()
                SUBMITTED_INCIDENTS.add(alert["blockchain_metadata"]["alert_hash"])
                logger.info(f"Batch confirmed: CID {alert['ipfsCid']} stored on chain")

            # Process event logs to extract automated responses
            action_triggered_topic = w3.keccak(text="ActionTriggered(bytes32,string)").hex()
            manual_review_topic = w3.keccak(text="ManualReviewNeeded(bytes32,string)").hex()
            duplicate_skipped_topic = w3.keccak(text="DuplicateIncidentSkipped(bytes32)").hex()

            for log in receipt.logs:
                if log["address"] == CONTRACT_ADDRESS:
                    topic = log["topics"][0].hex()
                    if topic in (action_triggered_topic, manual_review_topic, duplicate_skipped_topic):
                        # Extract alert hash from topics[1] (indexed parameter)
                        alert_hash = log["topics"][1].hex()
                        # Match event to the correct alert
                        for alert in batch:
                            if alert["blockchain_metadata"]["alert_hash"] == "0x" + alert_hash:
                                if topic == action_triggered_topic:
                                    # Decode action string from log data
                                    data = log["data"][2:] if isinstance(log["data"], str) else log["data"].hex()
                                    action_length = int(data[64:128], 16)  # Offset 32-64 bytes
                                    action_start = 128  # After length field
                                    action_end = action_start + action_length * 2
                                    action = bytes.fromhex(data[action_start:action_end]).decode('utf-8')
                                    alert["automated_response"] = action
                                    logger.info(f"Automated response for {alert_hash}: {action}")
                                elif topic == manual_review_topic:
                                    alert["automated_response"] = "Manual review needed"
                                    logger.info(f"Manual review needed for {alert_hash}")
                                elif topic == duplicate_skipped_topic:
                                    logger.info(f"Duplicate incident skipped for {alert_hash}")
                                break

            # Save updated submitted incidents
            with open(SUBMITTED_INCIDENTS_FILE, "w") as f:
                json.dump(list(SUBMITTED_INCIDENTS), f)

        else:
            logger.error(f"Batch transaction failed: {tx_hash.hex()}")
            raise Exception("Transaction failed")

    except Exception as e:
        logger.error(f"Batch blockchain submission failed: {str(e)}")
        raise

async def analyze_alerts(alerts):
    """
    Analyze a list of alerts using ML and threat intelligence, upload to IPFS, and submit to blockchain in batches.
    """
    if not alerts:
        return []

    async with aiohttp.ClientSession() as session:
        intel_tasks = [fetch_threat_intel(session, alert) for alert in alerts]
        threat_intel = await asyncio.gather(*intel_tasks)

    features = [extract_features(alert, threat_intel[i]) for i, alert in enumerate(alerts)]
    valid_indices = [i for i, f in enumerate(features) if f is not None]
    valid_features = [f for f in features if f is not None]
    if not valid_features:
        logger.warning("No valid features extracted from alerts")
        return []

    # Normalize features and apply Isolation Forest
    features_array = StandardScaler().fit_transform(np.array(valid_features))
    iso_forest = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    iso_scores = iso_forest.fit_predict(features_array)
    initial_labels = np.where(iso_scores == -1, 1, 0)

    # Train XGBoost model
    scale_pos_weight = (len(initial_labels) - sum(initial_labels)) / sum(initial_labels) if sum(initial_labels) > 0 else 1
    xgb_model = xgb.XGBClassifier(
        n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42,
        scale_pos_weight=scale_pos_weight, eval_metric='logloss'
    )
    X_train, X_test, y_train, y_test = train_test_split(features_array, initial_labels, test_size=0.2, random_state=42)
    xgb_model.fit(X_train, y_train)
    threat_probs = xgb_model.predict_proba(features_array)[:, 1]

    logger.info(f"XGBoost Classification Report:\n{classification_report(y_test, xgb_model.predict(X_test), target_names=['Benign', 'Threat'])}")

    filtered_alerts = []
    batch = []
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor() as pool:
        for i in valid_indices:
            alert = alerts[i]
            intel = threat_intel[i]
            threat_prob = float(threat_probs[valid_indices.index(i)])

            # Determine base threat level
            rule_level = int(alert.get("severity", 0))
            base_threat = "LOW" if rule_level <= 5 else "MEDIUM" if rule_level <= 10 else "HIGH" if rule_level <= 13 else "CRITICAL"

            # Compute additional scores
            temporal_score = await loop.run_in_executor(pool, compute_temporal_correlation, alerts, alert)
            full_log = alert.get("raw_log", "") or alert.get("description", "") or ""
            keyword_count = sum(1 for w in re.findall(r'\w+', full_log.lower()) if w in CRITICAL_KEYWORDS)
            criticality = min(1.0, keyword_count * 0.15)

            # Adjust scores based on threat intel
            if intel["is_known_threat"]:
                criticality = min(1.0, criticality + intel["threat_confidence"] * 0.5)
                threat_prob = min(1.0, threat_prob + intel["threat_confidence"] * 0.3)
            elif intel["reputation_score"] < 0:
                criticality = max(0.0, criticality - 0.4)
                threat_prob = max(0.0, threat_prob - abs(intel["reputation_score"]) * 0.5)

            # Apply time decay
            current_time = datetime.now(pytz.UTC)
            try:
                alert_ts = datetime.fromisoformat(alert.get("timestamp", "").replace("+0100", "+01:00")).astimezone(pytz.UTC)
            except (ValueError, TypeError):
                alert_ts = current_time
            decay_factor = max(0.2, 1 - ((current_time - alert_ts).total_seconds() / 3600) / 24)

            # Calculate final threat score
            severity_boost = 0.3 if rule_level > 10 else 0.0
            threat_score = (
                threat_prob * 0.35 +
                criticality * 0.25 +
                intel["reputation_score"] * 0.3 +
                temporal_score * 0.1 +
                severity_boost
            ) * 100 * decay_factor

            # Adaptive threshold based on alert surge
            ALERT_SURGE_THRESHOLD = 100  # Alerts per minute
            alert_rate = len(alerts) / (TIME_WINDOW.total_seconds() / 60)
            REAL_THREAT_THRESHOLD = 0.5 if alert_rate > ALERT_SURGE_THRESHOLD else 0.65

            # Classify threat
            if threat_prob > REAL_THREAT_THRESHOLD or (intel["is_known_threat"] and threat_score > 55):
                classification = "REAL_THREAT"
            elif threat_prob < 0.2 and criticality < 0.1 and threat_score < 20 and intel["reputation_score"] <= 0:
                classification = "FALSE_POSITIVE"
            else:
                classification = "POTENTIAL_FALSE_NEGATIVE"

            final_threat = base_threat if classification != "REAL_THREAT" else "CRITICAL" if threat_score > 70 else "HIGH"

            # Prepare alert data
            alert_data = {
                "threatLevel": final_threat,
                "description": alert.get("description", ""),
                "classification": classification,
                "details": {
                    "timestamp": alert.get("timestamp", "N/A"),
                    "agent_id": alert.get("agent_id", "unknown"),
                    "rule_id": alert.get("event_id", "N/A"),
                    "source_ip": alert.get("source_ip", "N/A"),
                    "threat_score": float(round(threat_score, 2)),
                    "criticality_weight": float(round(criticality, 2)),
                    "threat_probability": float(round(threat_prob, 2)),
                    "temporal_score": float(round(temporal_score, 2)),
                    "threat_intel_confirmed": intel["is_known_threat"]
                },
                "blockchain_metadata": {
                    "alert_hash": "0x" + hashlib.sha256(json.dumps(alert).encode()).hexdigest(),
                    "timestamp_unix": int(current_time.timestamp())
                },
                "original_alert": alert
            }

            # Skip if already submitted
            if alert_data["blockchain_metadata"]["alert_hash"] in SUBMITTED_INCIDENTS:
                logger.info(f"Skipping already submitted incident: {alert_data['blockchain_metadata']['alert_hash']}")
                continue

            # Upload to IPFS
            try:
                ipfs_cid = await loop.run_in_executor(pool, upload_to_ipfs, alert_data, PINATA_API_KEY, PINATA_API_SECRET)
                alert_data["ipfsCid"] = ipfs_cid
            except Exception as e:
                logger.error(f"Skipping alert due to IPFS upload failure: {e}")
                continue

            # Add to batch
            batch.append(alert_data)
            filtered_alerts.append(alert_data)

            if len(batch) >= BATCH_SIZE:
                await loop.run_in_executor(pool, submit_batch_to_blockchain, batch)
                batch = []

        # Submit any remaining alerts
        if batch:
            await loop.run_in_executor(pool, submit_batch_to_blockchain, batch)

    return filtered_alerts

def save_alerts_to_json(alerts, output_file):
    """
    Save analyzed alerts to a JSON file.
    """
    try:
        def convert(obj):
            if isinstance(obj, (np.float32, np.float64)):
                return float(obj)
            if isinstance(obj, (np.int32, np.int64)):
                return int(obj)
            if isinstance(obj, dict):
                return {k: convert(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [convert(item) for item in obj]
            return obj

        cleaned_alerts = [{k: v for k, v in alert.items() if k != "original_alert"} for alert in alerts]
        converted_alerts = convert(cleaned_alerts)
        with open(output_file, "w") as f:
            json.dump(converted_alerts, f, indent=4)
        logger.info(f"Saved {len(alerts)} alerts to {output_file}")
    except Exception as e:
        logger.error(f"Failed to save alerts to {output_file}: {e}")

async def process_alerts(input_file, output_file=os.path.join(os.path.dirname(__file__), "..", "data", "threat_analysis_realtime.json")):
    """
    Process alerts from an input JSON file and save results.
    """
    logs = []
    try:
        if not os.path.exists(input_file):
            logs.append(f"Error: Input file {input_file} does not exist")
            return [], logs
        with open(input_file, "r") as f:
            alerts = json.load(f)
        if not alerts:
            logs.append("No alerts found in input file")
            return [], logs

        filtered_alerts = await analyze_alerts(alerts)
        if filtered_alerts:
            save_alerts_to_json(filtered_alerts, output_file)
            logs.append(f"Saved {len(filtered_alerts)} alerts to {output_file}")
        else:
            logs.append("No alerts processed")
        return filtered_alerts, logs
    except Exception as e:
        logs.append(f"Error processing alerts: {e}")
        return [], logs

def run_process_alerts(input_file, output_file):
    """
    Run the alert processing asynchronously.
    """
    return asyncio.run(process_alerts(input_file, output_file))

if __name__ == "__main__":
    input_file = os.path.join(os.path.dirname(__file__), "..", "data", "filtered_alerts.json")
    output_file = os.path.join(os.path.dirname(__file__), "..", "data", "threat_analysis_realtime.json")
    analyzed_alerts, logs = run_process_alerts(input_file, output_file)
    for log in logs:
        logger.info(log)