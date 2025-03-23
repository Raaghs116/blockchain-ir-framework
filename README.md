# Blockchain-Based Incident Response Framework

This repository contains the source code for a blockchain-based cybersecurity incident response (IR) framework developed for my MSc thesis.

## Files
- `filter_alerts.py`: Filters Wazuh SIEM alerts for preprocessing.
- `threat_analysis_realtime_blockchain.py`: Performs real-time threat classification using XGBoost and IsolationForest.
- `contracts/IncidentResponse.sol`: Solidity smart contract for automated responses and logging.
- `scripts/deploy.js`: JavaScript script for deploying the smart contract via Hardhat.

## Setup Instructions
1. **System Requirements:** Ubuntu 20.04/Windows OS, 16GB RAM, 500GB SSD.
2. **Software Installation:**
   - Python 3.9: `sudo apt update && sudo apt install python3.9 python3-pip`
   - Node.js v16: `curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash - && sudo apt install -y nodejs`
   - Hardhat: `npm install -g hardhat`
   - Wazuh 4.3: Follow https://documentation.wazuh.com/4.3/installation-guide/
3. **Dependencies:**
   - Python: `pip install xgboost web3.py asyncio requests`
   - Node.js: `npm install ethers @pinata/sdk`
   - OpenZeppelin: `npm install @openzeppelin/contracts-upgradeable`
4. **Clone Repository:** `git clone [repo-url] && cd blockchain-ir-framework`
5. **Execution:**
   - Start Hardhat node: `npx hardhat node` (runs at 127.0.0.1:8545)
   - Deploy contract: `npx hardhat run scripts/deploy.js --network localhost`
   - Filter alerts: `python filter_alerts.py`
   - Analyze threats: `python threat_analysis_realtime_blockchain.py`
6. **Outputs:** Blockchain logs at `http://127.0.0.1:8545`, IPFS hashes via Pinata (requires API key from pinata.cloud), terminal classification results.

## Citation
Madhusudan, R. J. (2025). Blockchain-based incident response framework source code [Computer software]. GitHub. https://github.com/Raaghs116/blockchain-ir-framework