// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <=0.9.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

contract IncidentResponse is Initializable, AccessControlUpgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable {
    bytes32 public constant LOGGER_ROLE = keccak256("LOGGER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    uint256 public constant VERSION = 1;
    uint256 public constant MAX_BATCH_SIZE = 50;

    enum Classification { REAL_THREAT, FALSE_POSITIVE, POTENTIAL_FALSE_NEGATIVE }

    struct Incident {
        bytes32 hash;
        string ipfsCid;
        bytes32 detailsDigest;
        uint256 recordedAt;
        Classification classification;
        uint8 incidentLevel;
        bool hasResponse;
        bool pendingReview;
        address recordedBy;
    }

    mapping(bytes32 => Incident) public incidents;
    uint256 public incidentCount;
    mapping(uint256 => bytes32) public incidentIds;
    mapping(uint8 => string) private responses;

    uint8 public constant LOW = 0;
    uint8 public constant MEDIUM = 1;
    uint8 public constant HIGH = 2;
    uint8 public constant CRITICAL = 3;

    event IncidentLogged(
        bytes32 indexed hash,
        string ipfsCid,
        bytes32 detailsDigest,
        Classification classification,
        uint8 incidentLevel,
        uint256 timestamp,
        address indexed recordedBy
    );
    event ActionTriggered(bytes32 indexed hash, string action);
    event ManualReviewNeeded(bytes32 indexed hash, string ipfsCid);
    event ResponseUpdated(uint8 indexed incidentLevel, string newResponse);
    event DuplicateIncidentSkipped(bytes32 indexed hash);

    function initialize() external initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(LOGGER_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);

        responses[LOW] = "Monitor";
        responses[MEDIUM] = "IsolateEndpoint";
        responses[HIGH] = "BlockIP";
        responses[CRITICAL] = "FullLockdown";
    }

    function _processIncident(
        bytes32 hash,
        string calldata ipfsCid,
        bytes32 detailsDigest,
        Classification classification,
        uint8 incidentLevel
    ) internal whenNotPaused {
        if (incidents[hash].hash != bytes32(0)) {
            emit DuplicateIncidentSkipped(hash);
            return;  // Skip duplicate without reverting
        }

        require(bytes(ipfsCid).length >= 46, "Invalid IPFS CID");
        require(incidentLevel <= CRITICAL, "Invalid incident level");

        incidents[hash] = Incident({
            hash: hash,
            ipfsCid: ipfsCid,
            detailsDigest: detailsDigest,
            recordedAt: block.timestamp,
            classification: classification,
            incidentLevel: incidentLevel,
            hasResponse: false,
            pendingReview: false,
            recordedBy: msg.sender
        });
        incidentIds[incidentCount] = hash;
        incidentCount++;

        if (classification == Classification.REAL_THREAT) {
            string memory action = responses[incidentLevel];
            incidents[hash].hasResponse = true;
            emit ActionTriggered(hash, action);
        } else {
            incidents[hash].pendingReview = true;
            emit ManualReviewNeeded(hash, ipfsCid);
        }

        emit IncidentLogged(hash, ipfsCid, detailsDigest, classification, incidentLevel, block.timestamp, msg.sender);
    }

    function logIncident(
        bytes32 hash,
        string calldata ipfsCid,
        bytes32 detailsDigest,
        Classification classification,
        uint8 incidentLevel
    ) external onlyRole(LOGGER_ROLE) nonReentrant {
        _processIncident(hash, ipfsCid, detailsDigest, classification, incidentLevel);
    }

    function logIncidentsBatch(
        bytes32[] calldata hashes,
        string[] calldata ipfsCids,
        bytes32[] calldata detailsDigests,
        Classification[] calldata classifications,
        uint8[] calldata incidentLevels
    ) external onlyRole(LOGGER_ROLE) nonReentrant {
        require(hashes.length <= MAX_BATCH_SIZE, "Batch size exceeds limit");
        require(
            hashes.length == ipfsCids.length &&
            ipfsCids.length == detailsDigests.length &&
            detailsDigests.length == classifications.length &&
            classifications.length == incidentLevels.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < hashes.length; i++) {
            _processIncident(
                hashes[i],
                ipfsCids[i],
                detailsDigests[i],
                classifications[i],
                incidentLevels[i]
            );
        }
    }

    function setResponse(bytes32 hash, string calldata action) external onlyRole(ADMIN_ROLE) nonReentrant whenNotPaused {
        Incident storage incident = incidents[hash];
        require(incident.hash != bytes32(0), "Incident not found");
        require(incident.pendingReview, "No review required");
        require(!incident.hasResponse, "Already responded");

        incident.hasResponse = true;
        incident.pendingReview = false;
        emit ActionTriggered(hash, action);
    }

    function updateResponse(uint8 incidentLevel, string calldata newResponse) external onlyRole(ADMIN_ROLE) {
        require(incidentLevel <= CRITICAL, "Invalid incident level");
        responses[incidentLevel] = newResponse;
        emit ResponseUpdated(incidentLevel, newResponse);
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    function getIncident(bytes32 hash) external view returns (Incident memory) {
        return incidents[hash];
    }

    function getIncidentIds(uint256 start, uint256 count) external view returns (bytes32[] memory) {
        require(start < incidentCount, "Invalid start index");
        uint256 end = start + count > incidentCount ? incidentCount : start + count;
        bytes32[] memory ids = new bytes32[](end - start);
        for (uint256 i = start; i < end; i++) {
            ids[i - start] = incidentIds[i];
        }
        return ids;
    }

    function getResponse(uint8 incidentLevel) external view returns (string memory) {
        return responses[incidentLevel];
    }

    function getVersion() external pure returns (uint256) {
        return VERSION;
    }

    uint256[50] private __gap;
}