// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title SupplyController — AI-модуль управления инфляцией $NEURO
/// @notice Регулирует supply по данным AI-моделей (KPI, Webhook, Oracle)
contract SupplyController is AccessControl, Pausable {
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    IERC20 public immutable neuroToken;
    address public mintTarget;

    uint256 public lastMint;
    uint256 public mintInterval = 12 hours;
    uint256 public kpiThreshold = 75;           // % (0-100)
    uint256 public maxDailyEmission = 1_000_000 * 1e18;

    mapping(bytes32 => uint256) public kpiValues; // KPI name => value

    event MintExecuted(address to, uint256 amount, bytes32 reason);
    event KPIUpdated(bytes32 indexed kpi, uint256 value);
    event MintTargetUpdated(address newTarget);

    constructor(address tokenAddress, address initialTarget) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ORACLE_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);

        neuroToken = IERC20(tokenAddress);
        mintTarget = initialTarget;
    }

    /// @notice Webhook или AI-модуль передаёт актуальные KPI
    function updateKPI(bytes32 name, uint256 value) external onlyRole(ORACLE_ROLE) {
        require(value <= 100, "Invalid KPI %");
        kpiValues[name] = value;
        emit KPIUpdated(name, value);
    }

    /// @notice Выпуск токенов — только если KPI выше порога и интервал соблюдён
    function mintIfAllowed(bytes32 kpiName, uint256 amount) external onlyRole(MINTER_ROLE) whenNotPaused {
        require(block.timestamp >= lastMint + mintInterval, "Too early");
        require(kpiValues[kpiName] >= kpiThreshold, "KPI too low");
        require(amount <= maxDailyEmission, "Amount too high");

        lastMint = block.timestamp;
        _callMint(mintTarget, amount);
        emit MintExecuted(mintTarget, amount, kpiName);
    }

    /// @notice Вызов mint на токене
    function _callMint(address to, uint256 amount) internal {
        (bool success, ) = address(neuroToken).call(
            abi.encodeWithSignature("mint(address,uint256)", to, amount)
        );
        require(success, "Mint failed");
    }

    /// @notice Обновление цели минта (например, в DAO, фонд, квест-модуль)
    function setMintTarget(address newTarget) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newTarget != address(0), "Invalid target");
        mintTarget = newTarget;
        emit MintTargetUpdated(newTarget);
    }

    /// @notice Установка нового порога KPI
    function setKPIThreshold(uint256 newThreshold) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newThreshold <= 100, "Invalid");
        kpiThreshold = newThreshold;
    }

    function setMaxDailyEmission(uint256 newMax) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxDailyEmission = newMax;
    }

    function setMintInterval(uint256 newInterval) external onlyRole(DEFAULT_ADMIN_ROLE) {
        mintInterval = newInterval;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
