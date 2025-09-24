// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

interface IAIOracle {
    function isAllowedMint(address caller, uint256 amount) external view returns (bool);
}

/// @title TokenMinter — модуль безопасного AI-минтинга для $NEURO
/// @notice Поддержка AI Oracle, ролей, лимитов и подписей
contract TokenMinter is AccessControl, Pausable {
    using ECDSA for bytes32;

    bytes32 public constant AI_MINTER_ROLE = keccak256("AI_MINTER_ROLE");
    IERC20 public immutable token;
    IAIOracle public aiOracle;

    mapping(address => uint256) public totalMinted;
    uint256 public maxPerAddress = 1_000_000 * 1e18;

    event Minted(address indexed to, uint256 amount, string tag);
    event MinterLimitsUpdated(address indexed minter, uint256 maxAmount);
    event OracleUpdated(address indexed oracle);

    constructor(address tokenAddress, address aiOracleAddress) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(AI_MINTER_ROLE, msg.sender);

        token = IERC20(tokenAddress);
        aiOracle = IAIOracle(aiOracleAddress);
    }

    /// @notice AI-интерфейс: минт по решению oracle
    function mint(address to, uint256 amount, string calldata tag) external whenNotPaused onlyRole(AI_MINTER_ROLE) {
        require(to != address(0), "Invalid recipient");
        require(totalMinted[to] + amount <= maxPerAddress, "Per-address cap exceeded");

        bool allowed = aiOracle.isAllowedMint(msg.sender, amount);
        require(allowed, "AI oracle rejected mint");

        totalMinted[to] += amount;
        _callMint(to, amount);

        emit Minted(to, amount, tag);
    }

    /// @notice Админское минтинг
    function adminMint(address to, uint256 amount, string calldata reason) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _callMint(to, amount);
        emit Minted(to, amount, reason);
    }

    /// @notice Модификация лимитов на адрес
    function setMaxPerAddress(uint256 newMax) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxPerAddress = newMax;
    }

    /// @notice Подключение нового AI oracle
    function setAIOracle(address newOracle) external onlyRole(DEFAULT_ADMIN_ROLE) {
        aiOracle = IAIOracle(newOracle);
        emit OracleUpdated(newOracle);
    }

    /// @notice Внутренний вызов mint у токена
    function _callMint(address to, uint256 amount) internal {
        // безопасно вызвать mint через low-level (если токен — Ownable с minter'ом)
        (bool success, ) = address(token).call(
            abi.encodeWithSignature("mint(address,uint256)", to, amount)
        );
        require(success, "Mint call failed");
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
