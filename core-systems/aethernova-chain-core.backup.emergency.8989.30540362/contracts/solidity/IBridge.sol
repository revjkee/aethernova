// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IBridge — кроссчейн интерфейсы сообщений и токен-переводов
/// @notice Интерфейс «промышленного» моста: сообщения, депозиты/финализация,
///         анти-replay по nonce, детерминированные ID, совместимость с ERC-165,
///         EIP-712 DOMAIN_SEPARATOR для оффчейн подписей.
/// @dev  Документация по NatSpec/Errors: Solidity Docs.
///       EIP-712 (typed data): eips.ethereum.org/EIPS/eip-712.
///       EIP-1271 (контрактные подписи): eips.ethereum.org/EIPS/eip-1271.
///       ERC-165 (обнаружение интерфейсов): eips.ethereum.org/EIPS/eip-165.
///       Глобальные переменные/chainid: Solidity Docs.
//  Sources: NatSpec, Errors, chainid: https://docs.soliditylang.org (latest)
//           EIP-712: https://eips.ethereum.org/EIPS/eip-712
//           EIP-1271: https://eips.ethereum.org/EIPS/eip-1271
//           ERC-165: https://eips.ethereum.org/EIPS/eip-165

/* ─────────────────────────────────────────────────────────────────────────────
 *                               Минимальные интерфейсы
 * ────────────────────────────────────────────────────────────────────────────*/

/// @dev ERC-165 минимальный интерфейс (для самодостаточности файла).
interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

/// @dev ERC-20 минимальный интерфейс, используемый для bridgeERC20.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address owner, address to, uint256 amount) external returns (bool);
    function balanceOf(address owner) external view returns (uint256);
    function decimals() external view returns (uint8);
}

/* ─────────────────────────────────────────────────────────────────────────────
 *                               События и ошибки
 * ────────────────────────────────────────────────────────────────────────────*/

/// @dev Общие события и ошибки моста.
interface IBridgeEventsAndErrors {
    /* --------------------------------- Events -------------------------------- */

    /// @notice Отправка сообщения из src→dst.
    /// @param messageId детерминированный ID сообщения (см. реализацию)
    /// @param srcChainId исходная сеть
    /// @param dstChainId сеть назначения
    /// @param sender отправитель (в src сети)
    /// @param recipient получатель (в dst сети)
    /// @param nonce монотонный счетчик для (sender,dstChainId)
    /// @param fee фактически удержанная комиссия (в msg.value, если применимо)
    /// @param data полезная нагрузка
    event MessageSent(
        bytes32 indexed messageId,
        uint256 indexed srcChainId,
        uint256 indexed dstChainId,
        address sender,
        address recipient,
        uint256 nonce,
        uint256 fee,
        bytes data
    );

    /// @notice Доставка/прием сообщения на стороне назначения.
    /// @param messageId ID принятого сообщения
    /// @param srcChainId исходная сеть
    /// @param dstChainId сеть назначения (должна равняться block.chainid)
    /// @param recipient адрес получателя в dst сети
    /// @param success успешна ли обработка
    event MessageReceived(
        bytes32 indexed messageId,
        uint256 indexed srcChainId,
        uint256 indexed dstChainId,
        address recipient,
        bool success
    );

    /// @notice Инициация депозита ERC20 в мост (src→dst).
    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed token,
        address indexed from,
        address to,
        uint256 amount,
        uint256 srcChainId,
        uint256 dstChainId,
        uint256 nonce
    );

    /// @notice Финализация вывода ERC20 на стороне назначения (dst).
    event WithdrawalFinalized(
        bytes32 indexed withdrawalId,
        address indexed token,
        address indexed to,
        uint256 amount,
        uint256 srcChainId,
        uint256 dstChainId,
        uint256 nonce
    );

    /// @notice Обновление корня состояния/коммитмента, подтверждающего доказательства.
    event StateCommitmentUpdated(
        uint256 indexed srcChainId,
        bytes32 indexed commitment, // форма коммитмента зависит от реализации (state root/Merkle root)
        uint256 batchId
    );

    /* --------------------------------- Errors -------------------------------- */

    /// @notice Ошибка: контракт/адрес не авторизован выполнять действие.
    error Unauthorized();

    /// @notice Ошибка: контракт в паузе.
    error Paused();

    /// @notice Ошибка: неверный chainId (анти-replay защита).
    error InvalidChainId();

    /// @notice Ошибка: неподдерживаемая сеть назначения.
    error UnsupportedDestination();

    /// @notice Ошибка: повторная обработка сообщения/депозита.
    error AlreadyProcessed();

    /// @notice Ошибка: некорректное/недостаточное доказательство.
    error InvalidProof();

    /// @notice Ошибка: nonce не совпадает или не монотонен.
    error InvalidNonce();

    /// @notice Ошибка: комиссия занижена относительно расчета.
    error FeeTooLow();

    /// @notice Ошибка: нулевой адрес.
    error ZeroAddress();

    /// @notice Ошибка: превышен лимит/квота.
    error RateLimitExceeded();
}

/* ─────────────────────────────────────────────────────────────────────────────
 *                               Структуры/типы
 * ────────────────────────────────────────────────────────────────────────────*/

/// @dev Общие типы для сообщений/платежей.
interface IBridgeTypes {
    /// @notice Структура сообщения для EIP-712 и трассировки.
    /// @dev Конкретная реализация может хэшировать поля по EIP-712.
    struct Message {
        uint256 srcChainId;
        uint256 dstChainId;
        address sender;
        address recipient;
        uint256 nonce;
        bytes data; // произвольная полезная нагрузка
    }

    /// @notice Параметры для бриджа ERC20.
    struct ERC20Transfer {
        address token;
        address from;
        address to;
        uint256 amount;
        uint256 dstChainId;
        uint256 nonce;
    }

    /// @notice Метаданные котировки комиссии на отправку сообщения/перевода.
    struct FeeQuote {
        uint256 fee;      // требуемая комиссия в native токене (wei)
        uint256 deadline; // UNIX-время «годен до»
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 *                               Основные интерфейсы
 * ────────────────────────────────────────────────────────────────────────────*/

/// @title IBridgeCore
/// @notice Основные методы моста: сообщения и ERC20-переводы.
/// @dev Реализация ДОЛЖНА объявлять поддержку ERC-165 для IBridgeCore/IBridgeView/IBridgeAdmin.
interface IBridgeCore is IERC165, IBridgeEventsAndErrors, IBridgeTypes {
    /* ---------------------------- Отправка сообщений ---------------------------*/

    /// @notice Вернуть котировку комиссии на отправку произвольного сообщения.
    /// @dev Реализация может учитывать размер `data`, dstChainId, нагрузку, приоритет и т.д.
    function quoteSend(bytes calldata data, uint256 dstChainId) external view returns (FeeQuote memory);

    /// @notice Отправить сообщение в сеть назначения.
    /// @param recipient адрес получателя в сети назначения
    /// @param dstChainId chainId сети назначения (EVM: см. block.chainid)
    /// @param data полезная нагрузка
    /// @param refundAddress куда вернуть излишек msg.value (если поддерживается)
    /// @return messageId детерминированный идентификатор сообщения
    /// @dev msg.value должен покрывать рассчитанную комиссию (см. quoteSend).
    function sendMessage(
        address recipient,
        uint256 dstChainId,
        bytes calldata data,
        address refundAddress
    ) external payable returns (bytes32 messageId);

    /// @notice Принять/подтвердить сообщение на стороне назначения.
    /// @param message структура сообщения (src→dst)
    /// @param proof   доказательство включения/валидности (формат зависит от реализации)
    /// @return messageId идентификатор принятого сообщения
    function receiveMessage(
        Message calldata message,
        bytes calldata proof
    ) external returns (bytes32 messageId);

    /* ---------------------------- ERC20 переводы -------------------------------*/

    /// @notice Инициировать депозит ERC20 для мостирования.
    /// @param token ERC20 токен в исходной сети
    /// @param to получатель в сети назначения
    /// @param amount сумма перевода
    /// @param dstChainId сеть назначения
    /// @return depositId идентификатор депозита
    /// @dev Реализация ожидает prior `approve` и вызывает transferFrom.
    function bridgeERC20(
        address token,
        address to,
        uint256 amount,
        uint256 dstChainId
    ) external returns (bytes32 depositId);

    /// @notice Финализировать вывод ERC20 на стороне назначения.
    /// @param transfer параметры перевода (src→dst)
    /// @param proof    доказательство валидности события/состояния из исходной сети
    /// @return withdrawalId идентификатор финализации
    function finalizeERC20(
        ERC20Transfer calldata transfer,
        bytes calldata proof
    ) external returns (bytes32 withdrawalId);
}

/// @title IBridgeView
/// @notice Набор view-методов для интеграторов/индексов.
interface IBridgeView is IERC165, IBridgeTypes {
    /// @notice Текущая версия/семантика интерфейса реализации.
    function version() external view returns (string memory);

    /// @notice EIP-712 DOMAIN_SEPARATOR для оффчейн подписей/аудита.
    function DOMAIN_SEPARATOR() external view returns (bytes32);

    /// @notice Текущий nonce исходящих сообщений для (sender, dstChainId).
    function outboundNonce(address sender, uint256 dstChainId) external view returns (uint256);

    /// @notice Последний обработанный nonce входящих сообщений от (sender, srcChainId).
    function inboundNonce(address sender, uint256 srcChainId) external view returns (uint256);

    /// @notice Было ли сообщение/депозит обработано.
    function isProcessed(bytes32 id) external view returns (bool);

    /// @notice Возвращает актуальный коммитмент источника (например, root пакета).
    function latestCommitment(uint256 srcChainId) external view returns (bytes32 commitment, uint256 batchId);
}

/// @title IBridgeAdmin
/// @notice Административные хуки для управления реализацией моста.
/// @dev Реализация должна ограничивать доступ (например, AccessControl/Ownable) и может быть Pausable.
interface IBridgeAdmin is IERC165 {
    /// @notice Поставить мост на паузу/снять с паузы.
    function pause() external;
    function unpause() external;

    /// @notice Обновить коммитмент (например, root) для srcChainId.
    /// @dev В реальности это может делать «оратор» (oracle/relayer set) по безопасной процедуре.
    function updateCommitment(uint256 srcChainId, bytes32 commitment, uint256 batchId) external;

    /// @notice Установить квоту/лимит для переносов токена (в единицах токена).
    function setTokenRateLimit(address token, uint256 perBatchLimit, uint256 perBlockLimit) external;

    /// @notice Установить базовую формулу комиссии (параметры реализации).
    function setFeeParams(bytes calldata encodedParams) external;
}

/* ─────────────────────────────────────────────────────────────────────────────
 *                               Идентификаторы интерфейсов (ERC-165)
 * ────────────────────────────────────────────────────────────────────────────*/

/// @title IBridgeIds
/// @notice Константы интерфейс-идентификаторов по ERC-165.
/// @dev Значения должны вычисляться как XOR всех селекторов функций интерфейса.
///      Конкретная реализация может вернуть те же ID из supportsInterface.
///      (Показаны как example-константы; реализация может верифицировать.)
interface IBridgeIds {
    /// @dev bytes4(keccak256("supportsInterface(bytes4)"))
    function ERC165_ID() external pure returns (bytes4);

    /// @dev bytes4 ID интерфейса IBridgeCore
    function IBRIDGE_CORE_ID() external pure returns (bytes4);

    /// @dev bytes4 ID интерфейса IBridgeView
    function IBRIDGE_VIEW_ID() external pure returns (bytes4);

    /// @dev bytes4 ID интерфейса IBridgeAdmin
    function IBRIDGE_ADMIN_ID() external pure returns (bytes4);
}
