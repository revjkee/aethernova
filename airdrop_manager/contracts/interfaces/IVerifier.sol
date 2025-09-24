// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IVerifier
 * @notice Унифицированный интерфейс верификатора доказательств для Airdrop-менеджера.
 *         Поддерживает несколько криптосхем (Merkle/ZK и др.) через идентификатор схемы.
 * @dev    Реализации обязаны возвращать корректные значения и НЕ модифицировать состояние.
 *         Интерфейс совместим с ERC-165 (supportsInterface).
 */
interface IVerifier {
    /**
     * @notice Идентификаторы поддерживаемых схем рекомендуется получать через `getSupportedSchemes()`.
     * @dev     Для конвенции можно использовать bytes4(keccak256("MERKLE")), "GROTH16", "PLONK" и т.д.
     *          Конкретные значения schemeId — деталь реализации.
     */
    // Примерные семантические идентификаторы (не обязательны к реализации как константы):
    // bytes4 constant SCHEME_MERKLE = 0x4d45524b; // "MERK" (пример)
    // bytes4 constant SCHEME_GROTH16 = 0x47524f54; // "GROT" (пример)
    // bytes4 constant SCHEME_PLONK   = 0x504c4f4e; // "PLON" (пример)

    /**
     * @dev Структура заявки, используемая Airdrop-менеджером.
     * @param airdropId  Идентификатор дроп-кампании.
     * @param account    Адрес получателя.
     * @param amount     Сумма токенов для выдачи.
     * @param nonce      Нонcе для защиты от повторов/связывания.
     * @param deadline   UNIX-время (секунды), до которого заявка действительна.
     */
    struct Claim {
        uint256 airdropId;
        address account;
        uint256 amount;
        uint64  nonce;
        uint64  deadline;
    }

    /**
     * @notice Событие аудита успешной/неуспешной верификации обобщенного доказательства.
     * @param schemeId   Идентификатор криптосхемы.
     * @param context    Произвольный контекст (например, keccak хедера заявки/коммитмента).
     * @param account    Адрес, для которого выполнялась проверка (если применимо).
     * @param ok         Результат проверки.
     */
    event ProofVerified(bytes4 indexed schemeId, bytes32 indexed context, address indexed account, bool ok);

    /**
     * @notice Событие аудита Merkle-проверки.
     * @param root       Корневой хэш дерева.
     * @param leaf       Проверяемый лист.
     * @param ok         Результат проверки.
     */
    event MerkleVerified(bytes32 indexed root, bytes32 indexed leaf, bool ok);

    /// @notice Схема не поддерживается.
    error UnsupportedScheme(bytes4 schemeId);

    /// @notice Доказательство некорректно или невалидно для переданных данных.
    error ProofVerificationFailed(bytes4 schemeId, string reason);

    /// @notice Неверные параметры вызова (пустые/рассинхронизированные входы).
    error InvalidParameters(string what);

    /**
     * @notice Проверяет универсальное доказательство для заданной схемы.
     * @dev    Реализации могут интерпретировать `publicInputs` и `expectedCommitment` по-разному,
     *         но обязаны документировать формат. Функция НЕ должна модифицировать состояние.
     *
     * @param schemeId           Идентификатор схемы (например, MERKLE/GROTH16/PLONK).
     * @param proof              Байт-массив доказательства в формате реализации.
     * @param publicInputs       Публичные входы/сигналы (ABI-кодированные).
     * @param expectedCommitment Ожидаемый коммитмент/хэш (например, публичный коммит к заявке).
     * @return ok                true, если доказательство валидно; false — в противном случае.
     *
     * Реализация ДОЛЖНА:
     *  - вернуть false или выбрать revert с ProofVerificationFailed при невалидности;
     *  - revert UnsupportedScheme для неизвестной схемы;
     *  - НЕ записывать состояние (view).
     */
    function verifyProof(
        bytes4 schemeId,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 expectedCommitment
    ) external view returns (bool ok);

    /**
     * @notice Упрощенная проверка для Merkle-дерева (часто для airdrop-листов).
     * @dev    Реализация может быть pure/view. Интерфейс допускает pure.
     * @param root    Корень дерева.
     * @param leaf    Проверяемый лист (обычно хэш заявки).
     * @param proof   Массив хэшей от листа к корню.
     * @param index   Индекс листа (или битовая маска направлений) — по соглашению реализации.
     * @return ok     true, если путь валиден и восстанавливает root.
     */
    function verifyMerkle(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof,
        uint256 index
    ) external pure returns (bool ok);

    /**
     * @notice Вычисляет канонический leaf заявки для Merkle-дерева.
     * @dev    Должна совпадать с формулой, принятой реализацией верификатора и менеджера.
     *         Рекомендуется: keccak256(abi.encode(airdropId, account, amount, nonce, deadline)).
     * @param claim   Структура заявки.
     * @return leaf   Хэш-лист.
     */
    function leafOf(Claim calldata claim) external pure returns (bytes32 leaf);

    /**
     * @notice Возвращает true, если схема поддерживается реализацией.
     * @param schemeId   Идентификатор схемы.
     */
    function isSupported(bytes4 schemeId) external view returns (bool);

    /**
     * @notice Полный список поддерживаемых схем.
     */
    function getSupportedSchemes() external view returns (bytes4[] memory);

    /**
     * @notice Версионирование реализации (semver).
     * @return major, minor, patch
     */
    function version() external pure returns (uint64 major, uint64 minor, uint64 patch);

    /**
     * @notice ERC-165 поддержка интерфейсов.
     * @param interfaceId bytes4 идентификатор интерфейса.
     * @return true если поддерживается.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
