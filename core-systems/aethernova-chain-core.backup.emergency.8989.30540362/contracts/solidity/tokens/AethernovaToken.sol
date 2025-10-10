// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/**
 * AethernovaToken — промышленный ERC20:
 * - AccessControl: DEFAULT_ADMIN_ROLE, MINTER_ROLE, PAUSER_ROLE, BLACKLISTER_ROLE
 * - ERC20Permit (EIP-2612) для подписи разрешений без газа
 * - ERC20Votes для делегирования голосов и чекпойнтов
 * - ERC20Pausable для аварийной паузы
 * - ERC20Burnable для сжигания
 * - CAP на общее предложение
 * - Чёрный список отправителей и получателей
 * - Rescue-функция для выведения случайно присланных токенов
 *
 * ВНИМАНИЕ: перед деплоем убедитесь, что сборка использует OpenZeppelin Contracts v5.x.
 */

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC20.sol";

contract AethernovaToken is
    ERC20,
    ERC20Permit,
    ERC20Votes,
    ERC20Burnable,
    ERC20Pausable,
    AccessControl
{
    using SafeERC20 for IERC20;

    // ---------- Роли ----------
    bytes32 public constant MINTER_ROLE       = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE       = keccak256("PAUSER_ROLE");
    bytes32 public constant BLACKLISTER_ROLE  = keccak256("BLACKLISTER_ROLE");

    // ---------- Ошибки ----------
    error ZeroAddress();
    error CapExceeded();
    error Blacklisted(address account);

    // ---------- Параметры выпуска ----------
    uint256 public immutable CAP; // максимально допустимое предложение

    // ---------- Blacklist ----------
    mapping(address => bool) private _blacklist;

    // ---------- События ----------
    event BlacklistUpdated(address indexed account, bool isBlacklisted);

    /**
     * @param name_   имя токена
     * @param symbol_ символ токена
     * @param admin   адрес администратора (DEFAULT_ADMIN_ROLE)
     * @param initialSupply начальный выпуск (будет отправлен admin)
     * @param cap_    жёсткий предел общего предложения
     */
    constructor(
        string memory name_,
        string memory symbol_,
        address admin,
        uint256 initialSupply,
        uint256 cap_
    )
        ERC20(name_, symbol_)
        ERC20Permit(name_)
    {
        if (admin == address(0)) revert ZeroAddress();
        if (cap_ == 0) revert CapExceeded();
        if (initialSupply > cap_) revert CapExceeded();

        CAP = cap_;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(BLACKLISTER_ROLE, admin);

        // Начальный выпуск под CAP-контроль
        if (initialSupply > 0) {
            _internalMint(admin, initialSupply);
        }
    }

    // ---------- Публичные вьюхи ----------

    function isBlacklisted(address account) external view returns (bool) {
        return _blacklist[account];
    }

    // ---------- Админ/роль-ограниченные операции ----------

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// Установка/снятие бана адреса на отправку/получение.
    function setBlacklisted(address account, bool value) external onlyRole(BLACKLISTER_ROLE) {
        if (account == address(0)) revert ZeroAddress();
        _blacklist[account] = value;
        emit BlacklistUpdated(account, value);
    }

    /// Минт с учётом CAP.
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _internalMint(to, amount);
    }

    /// Пакетный минт (операционно удобно).
    function batchMint(address[] calldata to, uint256[] calldata amounts) external onlyRole(MINTER_ROLE) {
        uint256 len = to.length;
        if (len != amounts.length) revert();
        for (uint256 i = 0; i < len; ++i) {
            _internalMint(to[i], amounts[i]);
        }
    }

    /// Спасение токенов других контрактов, ошибочно отправленных на этот адрес.
    function rescueERC20(address token, address to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (token == address(0) || to == address(0)) revert ZeroAddress();
        // Запрещаем спасать сам этот токен через эту функцию
        require(token != address(this), "Self rescue disabled");
        IERC20(token).safeTransfer(to, amount);
    }

    // ---------- Внутренние утилиты ----------

    function _internalMint(address to, uint256 amount) internal {
        if (to == address(0)) revert ZeroAddress();
        if (totalSupply() + amount > CAP) revert CapExceeded();
        _mint(to, amount);
    }

    // ---------- Хуки и множественное наследование ----------

    /**
     * Комбинированный хук обновления балансов:
     * - проверка паузы (ERC20Pausable)
     * - проверка чёрного списка
     * - корректная интеграция с ERC20Votes (чекпойнты)
     *
     * Порядок super._update() следует линейзации наследования Solidity.
     */
    function _update(address from, address to, uint256 value)
        internal
        override(ERC20, ERC20Pausable, ERC20Votes)
    {
        if (from != address(0) && _blacklist[from]) revert Blacklisted(from);
        if (to   != address(0) && _blacklist[to])   revert Blacklisted(to);

        super._update(from, to, value);
    }

    /**
     * Требуется Solidity для корректной поддержки множественного наследования.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    // ---------- Метаданные ----------

    /// По умолчанию 18; переопределите при необходимости.
    function decimals() public pure override returns (uint8) {
        return 18;
    }
}
