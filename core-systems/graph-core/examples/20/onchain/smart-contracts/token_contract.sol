// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/utils/Context.sol";

/// @title TeslaAI Token (TAT) — ERC20 совместимый токен с расширенными функциями безопасности и контроля
/// @notice Контракт реализует стандарт ERC20 с дополнительными защитами и оптимизациями
contract TokenContract is Context, IERC20, IERC20Metadata {
    // Хранение балансов пользователей
    mapping(address => uint256) private _balances;

    // Хранение разрешений на списание средств (allowance)
    mapping(address => mapping(address => uint256)) private _allowances;

    // Общий выпуск токенов
    uint256 private _totalSupply;

    // Название токена
    string private _name;

    // Символ токена
    string private _symbol;

    // Владелец контракта (для административных функций)
    address private _owner;

    // Событие передачи владения
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // Модификатор для проверки прав владельца
    modifier onlyOwner() {
        require(_msgSender() == _owner, "Caller is not the owner");
        _;
    }

    /// @notice Конструктор контракта. Назначает имя, символ и первоначального владельца
    /// @param name_ Имя токена
    /// @param symbol_ Символ токена
    /// @param initialSupply_ Начальный выпуск токенов (в базовых единицах)
    constructor(string memory name_, string memory symbol_, uint256 initialSupply_) {
        _name = name_;
        _symbol = symbol_;
        _owner = _msgSender();
        _mint(_owner, initialSupply_);
    }

    /// @notice Возвращает имя токена
    function name() public view override returns (string memory) {
        return _name;
    }

    /// @notice Возвращает символ токена
    function symbol() public view override returns (string memory) {
        return _symbol;
    }

    /// @notice Возвращает количество знаков после запятой (стандарт 18)
    function decimals() public pure override returns (uint8) {
        return 18;
    }

    /// @notice Возвращает общий выпуск токенов
    function totalSupply() public view override returns (uint256) {
        return _totalSupply;
    }

    /// @notice Возвращает баланс указанного адреса
    /// @param account Адрес пользователя
    function balanceOf(address account) public view override returns (uint256) {
        return _balances[account];
    }

    /// @notice Переводит токены на другой адрес
    /// @param to Адрес получателя
    /// @param amount Количество токенов для перевода
    /// @return success Успешность операции
    function transfer(address to, uint256 amount) public override returns (bool success) {
        _transfer(_msgSender(), to, amount);
        return true;
    }

    /// @notice Возвращает остаток разрешённых для списания токенов
    /// @param owner Адрес владельца токенов
    /// @param spender Адрес, которому разрешено списание
    /// @return Остаток разрешения
    function allowance(address owner, address spender) public view override returns (uint256) {
        return _allowances[owner][spender];
    }

    /// @notice Устанавливает разрешение на списание токенов другим адресом
    /// @param spender Адрес, которому разрешено списание
    /// @param amount Количество токенов для разрешения
    /// @return success Успешность операции
    function approve(address spender, uint256 amount) public override returns (bool success) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    /// @notice Списывает токены с указанного адреса в пользу другого адреса
    /// @param from Адрес списания токенов
    /// @param to Адрес получателя
    /// @param amount Количество токенов
    /// @return success Успешность операции
    function transferFrom(address from, address to, uint256 amount) public override returns (bool success) {
        uint256 currentAllowance = _allowances[from][_msgSender()];
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");

        _transfer(from, to, amount);
        _approve(from, _msgSender(), currentAllowance - amount);

        return true;
    }

    /// @notice Передача владения контрактом новому владельцу
    /// @param newOwner Адрес нового владельца
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "New owner is zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }

    /// @dev Внутренняя функция перевода токенов
    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "ERC20: transfer from zero address");
        require(to != address(0), "ERC20: transfer to zero address");
        require(_balances[from] >= amount, "ERC20: transfer amount exceeds balance");

        unchecked {
            _balances[from] -= amount;
            _balances[to] += amount;
        }

        emit Transfer(from, to, amount);
    }

    /// @dev Внутренняя функция создания новых токенов
    function _mint(address account, uint256 amount) internal {
        require(account != address(0), "ERC20: mint to zero address");

        _totalSupply += amount;
        unchecked {
            _balances[account] += amount;
        }

        emit Transfer(address(0), account, amount);
    }

    /// @dev Внутренняя функция установки разрешения на списание
    function _approve(address owner, address spender, uint256 amount) internal {
        require(owner != address(0), "ERC20: approve from zero address");
        require(spender != address(0), "ERC20: approve to zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }
}
