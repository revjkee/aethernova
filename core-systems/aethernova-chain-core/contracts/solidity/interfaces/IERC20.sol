// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IERC20
 * @notice ERC-20 Token Standard.
 * @dev Спецификация: https://eips.ethereum.org/EIPS/eip-20
 *      Этот интерфейс намеренно содержит только обязательные методы и события ERC-20.
 *      OPTIONAL-поля метаданных (name/symbol/decimals) не включены в базовый интерфейс.
 */
interface IERC20 {
    /**
     * @dev Должно эмититься при любых переводах, включая нулевые суммы.
     *      При чеканке токенов рекомендуется эмитить Transfer с from = address(0).
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Должно эмититься при успешном вызове approve(owner -> spender, value).
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @notice Общее предложение токенов.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @notice Баланс аккаунта.
     * @param account Адрес владельца.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @notice Перевод токенов получателю.
     * @param to Получатель.
     * @param value Количество токенов.
     * @return success true при успехе.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @notice Остаток делегированного лимита spender от имени owner.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @notice Установить лимит списания для spender.
     * @param spender Уполномоченный списыватель.
     * @param value Лимит.
     * @return success true при успехе.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @notice Перевод токенов со счета from на счет to, используя allowance.
     * @param from Отправитель (владелец средств).
     * @param to Получатель.
     * @param value Количество.
     * @return success true при успехе.
     */
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/**
 * @title IERC20Errors
 * @notice Стандартные custom-ошибки для ERC-20 из EIP-6093.
 * @dev Спецификация: https://eips.ethereum.org/EIPS/eip-6093
 *      Реализации МОГУТ использовать эти ошибки для более дешевой и машиночитаемой сигнализации причин revert.
 */
interface IERC20Errors {
    /// Недостаточный баланс отправителя при переводе.
    error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);

    /// Некорректный адрес отправителя (например, address(0)).
    error ERC20InvalidSender(address sender);

    /// Некорректный адрес получателя (например, address(0) или неразрешенный контракт).
    error ERC20InvalidReceiver(address receiver);

    /// Недостаточный allowance для spender при transferFrom.
    error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed);

    /// Некорректный адрес утверждающего (например, address(0)).
    error ERC20InvalidApprover(address approver);

    /// Некорректный адрес получателя разрешения (например, address(0) или сам владелец).
    error ERC20InvalidSpender(address spender);
}
