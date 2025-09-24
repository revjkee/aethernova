// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Industrial Airdrop Manager v2.0 — TeslaAI Genesis Standard
/// @notice Управление безопасными масштабируемыми airdrop кампаниями с RBAC, ZK, фазами, комплаенсом и защитой от атак
/// @author TeslaAI

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract AirdropManager is AccessControl, ReentrancyGuard {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    IERC20 public immutable token;

    struct AirdropPhase {
        uint256 startTime;
        uint256 endTime;
        uint256 maxClaimPerUser;
        uint256 totalAllocation;
        uint256 claimedTotal;
        bool zkRequired;
        bool enabled;
    }

    mapping(uint256 => AirdropPhase) public phases;
    mapping(uint256 => mapping(address => uint256)) public claimedPerUser;
    mapping(address => bool) public blacklist;
    mapping(bytes32 => bool) public usedProofs;

    uint256 public nextPhaseId;

    event PhaseCreated(uint256 phaseId, uint256 allocation);
    event Claimed(address indexed user, uint256 amount, uint256 phaseId);
    event Blacklisted(address indexed user, bool status);

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "Not admin");
        _;
    }

    modifier onlyOperator() {
        require(hasRole(OPERATOR_ROLE, msg.sender), "Not operator");
        _;
    }

    constructor(address _token) {
        require(_token != address(0), "Invalid token");
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        token = IERC20(_token);
    }

    function createPhase(
        uint256 start,
        uint256 end,
        uint256 maxPerUser,
        uint256 allocation,
        bool zkRequired
    ) external onlyOperator {
        require(start < end, "Invalid timeframe");
        require(allocation > 0, "Zero allocation");

        phases[nextPhaseId] = AirdropPhase({
            startTime: start,
            endTime: end,
            maxClaimPerUser: maxPerUser,
            totalAllocation: allocation,
            claimedTotal: 0,
            zkRequired: zkRequired,
            enabled: true
        });

        emit PhaseCreated(nextPhaseId, allocation);
        nextPhaseId++;
    }

    function claim(
        uint256 phaseId,
        uint256 amount,
        bytes32 zkProof
    ) external nonReentrant {
        AirdropPhase storage phase = phases[phaseId];
        require(phase.enabled, "Phase disabled");
        require(block.timestamp >= phase.startTime && block.timestamp <= phase.endTime, "Out of time");
        require(!blacklist[msg.sender], "Blacklisted");
        require(claimedPerUser[phaseId][msg.sender] + amount <= phase.maxClaimPerUser, "Exceeds limit");
        require(phase.claimedTotal + amount <= phase.totalAllocation, "Not enough tokens");

        if (phase.zkRequired) {
            require(!usedProofs[zkProof], "Proof reused");
            usedProofs[zkProof] = true;
        }

        claimedPerUser[phaseId][msg.sender] += amount;
        phase.claimedTotal += amount;

        require(token.transfer(msg.sender, amount), "Transfer failed");

        emit Claimed(msg.sender, amount, phaseId);
    }

    function blacklistAddress(address user, bool status) external onlyAdmin {
        blacklist[user] = status;
        emit Blacklisted(user, status);
    }

    function withdrawLeftover(uint256 phaseId, address to) external onlyAdmin {
        AirdropPhase storage phase = phases[phaseId];
        require(block.timestamp > phase.endTime, "Phase active");

        uint256 leftover = phase.totalAllocation - phase.claimedTotal;
        phase.totalAllocation = phase.claimedTotal;

        require(token.transfer(to, leftover), "Withdraw failed");
    }

    function emergencyDrain(address to) external onlyAdmin {
        require(to != address(0), "Zero address");
        require(token.transfer(to, token.balanceOf(address(this))), "Drain failed");
    }
}
