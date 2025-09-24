// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// @title ShieldedTransferVerifier
/// @notice Абстрактный верификатор доказательств для шифрованных/экранированных переводов.
/// @dev Контракт не реализует конкретную схему доказательств.
///      Он делегирует проверку внешнему верификатору через IProofVerifier
///      и инкапсулирует операционные инварианты (нулификаторы, окна корней, пауза).
///
/// ВАЖНО:
/// - Порядок publicInputs должен соответствовать порядку, закодированному в цепочке/схеме.
/// - Контракт не хранит сами деревья; он доверяет реестру допустимых корней с окном актуальности.
/// - Нулификаторы считаются одноразовыми; повтор — отклоняется.
///
/// Архитектурные элементы:
/// - IProofVerifier: verify(proof, publicInputs) -> bool
/// - Root registry: корень => блок добавления; валиден не дольше rootTTLBlocks
/// - Nullifier set: bytes32 => spent
/// - Verifier rotation (2-step): schedule -> apply по прошествии delay блоков
/// - Безопасность: Pausable, ReentrancyGuard, строгие require, событийная телеметрия
interface IProofVerifier {
    /// @notice Проверка криптодоказательства против массива публичных входов.
    /// @param proof   Серилизация доказательства (схема-зависимая)
    /// @param inputs  Публичные входы в формате, ожидаемом верификатором/арбитром схемы
    /// @return ok     true если доказательство валидно
    function verify(bytes calldata proof, uint256[] calldata inputs) external view returns (bool ok);
}

/* ─────────────────────────────────────────────────────────────────────────────
 *                         МИНИМАЛЬНЫЕ БАЗОВЫЕ МИКСИНЫ
 *   (В целях самодостаточности не тянем сторонние либы; простые аналоги OZ)
 * ───────────────────────────────────────────────────────────────────────────── */

abstract contract Ownable2Step {
    address public owner;
    address public pendingOwner;

    event OwnershipTransferStarted(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotPendingOwner();

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() public {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }
}

abstract contract Pausable is Ownable2Step {
    bool public paused;

    event Paused(address indexed by);
    event Unpaused(address indexed by);

    error IsPaused();

    modifier whenNotPaused() {
        if (paused) revert IsPaused();
        _;
    }

    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }
}

abstract contract ReentrancyGuard {
    uint256 private constant _ENTERED = 2;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private _status = _NOT_ENTERED;

    modifier nonReentrant() {
        if (_status == _ENTERED) revert();
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 *                              ОСНОВНОЙ КОНТРАКТ
 * ───────────────────────────────────────────────────────────────────────────── */

contract ShieldedTransferVerifier is Pausable, ReentrancyGuard {
    // ── Параметры и лимиты
    uint256 public constant MAX_PUBLIC_INPUTS = 128;
    uint256 public constant MAX_NULLIFIERS   = 64;
    uint256 public constant MAX_COMMITMENTS  = 64;

    // ── Внешний верификатор
    IProofVerifier public verifier;

    // ── Двухшаговое обновление верификатора
    address public nextVerifier;
    uint64  public verifierUpdateEta;      // блок, начиная с которого можно применить
    uint64  public verifierUpdateDelay;    // задержка в блоках (напр., ~ L1 финализация)

    // ── Реестр корней дерева (root => блок добавления)
    mapping(bytes32 => uint64) public rootAddedAt;
    uint64 public rootTTLBlocks; // окно актуальности в блоках

    // ── Нулификаторы (spent set)
    mapping(bytes32 => bool) public nullifierSpent;

    // ── События
    event VerifierScheduled(address indexed current, address indexed next, uint64 applyAfterBlock);
    event VerifierUpdated(address indexed previous, address indexed current);
    event RootAdded(bytes32 indexed root, uint64 atBlock);
    event RootEvicted(bytes32 indexed root);
    event NullifierSpent(bytes32 indexed nullifier);
    event ProofVerified(
        bytes32 indexed merkleRoot,
        bytes32[] nullifiers,
        bytes32[] commitments,
        address indexed sender
    );

    // ── Ошибки
    error InvalidArrayLength();
    error InputsTooLarge();
    error NullifiersTooMany();
    error CommitmentsTooMany();
    error RootUnknownOrExpired();
    error NullifierAlreadySpent(bytes32 nf);
    error VerifierRotationNotReady();
    error ZeroAddress();

    constructor(
        address initialVerifier,
        uint64 _rootTTLBlocks,
        uint64 _verifierUpdateDelay
    ) {
        if (initialVerifier == address(0)) revert ZeroAddress();
        verifier = IProofVerifier(initialVerifier);
        rootTTLBlocks = _rootTTLBlocks;
        verifierUpdateDelay = _verifierUpdateDelay;
    }

    /* ───────────────────────────── Администрирование ───────────────────────── */

    /// @notice Запланировать обновление адреса внешнего верификатора.
    function scheduleVerifierUpdate(address _next) external onlyOwner {
        if (_next == address(0)) revert ZeroAddress();
        nextVerifier = _next;
        verifierUpdateEta = uint64(block.number) + verifierUpdateDelay;
        emit VerifierScheduled(address(verifier), _next, verifierUpdateEta);
    }

    /// @notice Применить ранее запланированное обновление верификатора.
    function applyVerifierUpdate() external onlyOwner {
        if (nextVerifier == address(0) || block.number < verifierUpdateEta) {
            revert VerifierRotationNotReady();
        }
        address prev = address(verifier);
        verifier = IProofVerifier(nextVerifier);
        nextVerifier = address(0);
        verifierUpdateEta = 0;
        emit VerifierUpdated(prev, address(verifier));
    }

    /// @notice Установить TTL для корней в блоках.
    function setRootTTL(uint64 ttlBlocks) external onlyOwner {
        rootTTLBlocks = ttlBlocks;
    }

    /// @notice Установить задержку (в блоках) для ротации верификатора.
    function setVerifierUpdateDelay(uint64 delayBlocks) external onlyOwner {
        verifierUpdateDelay = delayBlocks;
    }

    /// @notice Массовое добавление допустимых корней.
    function addRoots(bytes32[] calldata roots) external onlyOwner {
        uint64 at = uint64(block.number);
        for (uint256 i = 0; i < roots.length; ++i) {
            rootAddedAt[roots[i]] = at;
            emit RootAdded(roots[i], at);
        }
    }

    /// @notice Явное выселение корней (например, при компрометации).
    function evictRoots(bytes32[] calldata roots) external onlyOwner {
        for (uint256 i = 0; i < roots.length; ++i) {
            if (rootAddedAt[roots[i]] != 0) {
                delete rootAddedAt[roots[i]];
                emit RootEvicted(roots[i]);
            }
        }
    }

    /* ───────────────────────────── Пользовательское API ───────────────────── */

    /// @notice Проверка shielded-перевода и пометка нулификаторов как потраченных.
    /// @dev Все массивы проверяются на безопасные лимиты. Контракт НЕ перестраивает inputs;
    ///      он передает их внешнему верификатору как есть.
    /// @param proof        байтовое доказательство (схема-зависимое)
    /// @param publicInputs публичные входы для схемы
    /// @param merkleRoot   корень меркл-дерева, который должен быть валиден и не устаревшим
    /// @param nullifiers   нулификаторы, которые станут «spent» при успехе
    /// @param commitments  новые commitments, эмитятся в событии (для наблюдателей)
    function verifyShieldedTransfer(
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes32   merkleRoot,
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments
    ) external whenNotPaused nonReentrant returns (bool ok) {
        // ── базовые лимиты
        if (publicInputs.length == 0 || publicInputs.length > MAX_PUBLIC_INPUTS) revert InputsTooLarge();
        if (nullifiers.length == 0 || nullifiers.length > MAX_NULLIFIERS) revert NullifiersTooMany();
        if (commitments.length > MAX_COMMITMENTS) revert CommitmentsTooMany();

        // ── корень: известен и не просрочен
        uint64 at = rootAddedAt[merkleRoot];
        if (at == 0) revert RootUnknownOrExpired();
        if (rootTTLBlocks != 0 && uint64(block.number) > at + rootTTLBlocks) revert RootUnknownOrExpired();

        // ── запрет повтора: нулификаторы не должны быть потрачены
        for (uint256 i = 0; i < nullifiers.length; ++i) {
            if (nullifierSpent[nullifiers[i]]) revert NullifierAlreadySpent(nullifiers[i]);
        }

        // ── внешняя криптопроверка
        ok = verifier.verify(proof, publicInputs);
        if (!ok) return false;

        // ── фиксация нулификаторов
        for (uint256 i = 0; i < nullifiers.length; ++i) {
            nullifierSpent[nullifiers[i]] = true;
            emit NullifierSpent(nullifiers[i]);
        }

        emit ProofVerified(merkleRoot, nullifiers, commitments, msg.sender);
        return true;
    }

    /* ───────────────────────────── Вспомогательные view ───────────────────── */

    /// @notice Проверить, допустим ли корень с учётом TTL окна.
    function isRootValid(bytes32 root) external view returns (bool) {
        uint64 at = rootAddedAt[root];
        if (at == 0) return false;
        if (rootTTLBlocks == 0) return true;
        return uint64(block.number) <= at + rootTTLBlocks;
    }

    /// @notice Проверить, помечен ли нулификатор как «spent».
    function isNullifierSpent(bytes32 nf) external view returns (bool) {
        return nullifierSpent[nf];
    }

    /// @notice Текущая конфигурация ротации верификатора.
    function verifierRotationConfig() external view returns (address current, address next, uint64 eta, uint64 delayBlocks) {
        return (address(verifier), nextVerifier, verifierUpdateEta, verifierUpdateDelay);
    }
}
