// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Context.sol";

/// @title $NEURO — основной токен проекта TeslaAI/NeuroCity
/// @notice Поддержка Permit (EIP-2612), Mint, Burn, Ownable контроля
contract NEUROToken is Context, ERC20Burnable, ERC20Permit, Ownable {
    uint256 public constant MAX_SUPPLY = 1_000_000_000 * 1e18; // 1 млрд токенов

    /// @notice Отображает факт заморозки адреса
    mapping(address => bool) public frozen;

    event Frozen(address indexed user, bool status);

    constructor()
        ERC20("Neuro Token", "NEURO")
        ERC20Permit("Neuro Token")
    {
        _mint(_msgSender(), 100_000_000 * 1e18); // Генезис минт (10%)
    }

    /// @notice Минт новых токенов (AI или owner)
    function mint(address to, uint256 amount) public onlyOwner {
        require(totalSupply() + amount <= MAX_SUPPLY, "NEURO: cap exceeded");
        _mint(to, amount);
    }

    /// @notice Заморозка/разморозка (опционально для DAO/модерации)
    function setFrozen(address user, bool status) external onlyOwner {
        frozen[user] = status;
        emit Frozen(user, status);
    }

    /// @dev Проверка заморозки при переводах
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        require(!frozen[from], "NEURO: sender is frozen");
        require(!frozen[to], "NEURO: receiver is frozen");
        super._beforeTokenTransfer(from, to, amount);
    }

    /// @dev Поддержка permit через EIP-2612 (gasless approve)
    function nonces(address owner) public view override(ERC20Permit) returns (uint256) {
        return super.nonces(owner);
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return super._domainSeparatorV4();
    }
}
