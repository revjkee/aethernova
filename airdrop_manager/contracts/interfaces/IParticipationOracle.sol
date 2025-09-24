// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IParticipationOracle
/// @notice Интерфейс оракула участия для airdrop/allowlist/рейтинговых систем.
/// @dev Промышленный интерфейс:
/// - Совместимость с ERC-165 (supportsInterface)
/// - Две модели подтверждения: подпись уполномоченного (EIP-191) и Merkle-доказательство
/// - Кампании (campaignId) и снапшоты состояний
/// - Скоринг, уровни (tier), флаги eligibility
/// - Богатые события для off-chain индексов
/// - Кастомные ошибки для газ-эффективной диагностики
interface IParticipationOracle /* is IERC165 */ {
    // ---------------------------------------------------------------------
    //                              Типы
    // ---------------------------------------------------------------------

    /// @notice Режим проверки права участия.
    /// @dev MERKLE — проверка по корню дерева; SIGNATURE — по подписи доверенного подписанта.
    enum VerifyMode {
        MERKLE,
        SIGNATURE
    }

    /// @notice Класс участия получателя на момент снапшота/кампании.
    struct ParticipationClass {
        // Монотонно возрастает при каждом изменении параметров кампании
        uint64 snapshotId;
        // Момент формирования данных (UTC сек.)
        uint64 asOf;
        // Уровень доступа/поощрения (напр., 0..n)
        uint16 tier;
        // Нормированный балл 0..1e6 (или произвольная шкала, определяется интеграцией)
        uint32 score;
        // Флаг базовой пригодности
        bool eligible;
    }

    /// @notice Результат проверки участия/подтверждения.
    struct VerifyResult {
        bool eligible;             // Итоговое право участия
        uint16 tier;               // Уровень
        uint32 score;              // Балл
        uint64 snapshotId;         // Идентификатор снапшота
        bytes32 evidenceDigest;    // Хеш доказательства/сообщения
        VerifyMode mode;           // Использованный режим
    }

    // ---------------------------------------------------------------------
    //                              События
    // ---------------------------------------------------------------------

    /// @notice Обновление параметров кампании (метаданных/политик/лимитов).
    event CampaignParametersUpdated(
        uint256 indexed campaignId,
        uint64 snapshotId,
        address indexed updater,
        bytes paramsCID // например, IPFS/Arweave CID или произвольные ABI-данные
    );

    /// @notice Обновление Merkle-корня для кампании.
    event MerkleRootUpdated(
        uint256 indexed campaignId,
        uint64 snapshotId,
        bytes32 oldRoot,
        bytes32 newRoot,
        address indexed updater
    );

    /// @notice Обновление доверенного подписанта для кампании (режим SIGNATURE).
    event CampaignSignerUpdated(
        uint256 indexed campaignId,
        address oldSigner,
        address newSigner,
        address indexed updater
    );

    /// @notice Лог успешной верификации участия.
    event ParticipationVerified(
        uint256 indexed campaignId,
        address indexed account,
        VerifyMode mode,
        uint16 tier,
        uint32 score,
        uint64 snapshotId,
        bytes32 evidenceDigest
    );

    // ---------------------------------------------------------------------
    //                               Ошибки
    // ---------------------------------------------------------------------

    error InvalidArguments();
    error UnsupportedVerifyMode();
    error CampaignNotInitialized(uint256 campaignId);
    error StaleSnapshot(uint64 required, uint64 provided);
    error MerkleProofInvalid();
    error SignatureInvalid();
    error NotEligible();
    error AccessDenied(address caller);
    error ZeroAddress();

    // ---------------------------------------------------------------------
    //                        Метаданные/совместимость
    // ---------------------------------------------------------------------

    /// @notice Совместимость с ERC-165.
    /// @dev bytes4(keccak256("supportsInterface(bytes4)")) = 0x01ffc9a7
    function supportsInterface(bytes4 interfaceId) external view returns (bool);

    /// @notice Версия оракула (семантическая).
    function oracleVersion() external view returns (string memory);

    /// @notice Тип/семейство оракула (например, keccak256("AIRDROP_PARTICIPATION_V1")).
    function oracleType() external view returns (bytes32);

    // ---------------------------------------------------------------------
    //                         Параметры кампаний
    // ---------------------------------------------------------------------

    /// @notice Текущий снапшот кампании.
    function campaignSnapshotId(uint256 campaignId) external view returns (uint64);

    /// @notice Merkle-корень для кампании (если режим MERKLE используется).
    function campaignMerkleRoot(uint256 campaignId) external view returns (bytes32);

    /// @notice Доверенный подписант (если режим SIGNATURE используется).
    function campaignSigner(uint256 campaignId) external view returns (address);

    /// @notice Необязательные ABI-кодированные параметры кампании (off-chain CID/метаданные).
    function campaignParameters(uint256 campaignId) external view returns (bytes memory);

    // ---------------------------------------------------------------------
    //                           Чтение состояния
    // ---------------------------------------------------------------------

    /// @notice Возвращает агрегированную «классификацию» участия аккаунта в кампании.
    function getParticipationClass(uint256 campaignId, address account)
        external
        view
        returns (ParticipationClass memory cls);

    /// @notice Быстрый предикат пригодности без извлечения всех полей.
    function isEligible(uint256 campaignId, address account) external view returns (bool);

    // ---------------------------------------------------------------------
    //                       Верификация: Merkle / Signature
    // ---------------------------------------------------------------------

    /// @notice Проверка по Merkle-доказательству.
    /// @dev expectedLeaf формируется на стороне издателя (например, keccak256(abi.encode(account, tier, score, snapshotId))).
    /// @param campaignId Идентификатор кампании.
    /// @param account Проверяемый адрес.
    /// @param tier Ожидаемый уровень.
    /// @param score Ожидаемый балл.
    /// @param snapshotId Снапшот, для которого строился корень.
    /// @param merkleProof Массив sibling-хешей.
    function verifyWithMerkle(
        uint256 campaignId,
        address account,
        uint16 tier,
        uint32 score,
        uint64 snapshotId,
        bytes32[] calldata merkleProof
    ) external view returns (VerifyResult memory result);

    /// @notice Проверка по подписи доверенного подписанта (EIP-191).
    /// @dev messageDigest — заранее согласованный хэш сообщения, например keccak256(abi.encodePacked(
    ///      "\x19Ethereum Signed Message:\n32", keccak256(abi.encode(campaignId, account, tier, score, snapshotId))
    /// )).
    /// @param signature Подпись подписанта кампании.
    function verifyWithSignature(
        uint256 campaignId,
        address account,
        uint16 tier,
        uint32 score,
        uint64 snapshotId,
        bytes32 messageDigest,
        bytes calldata signature
    ) external view returns (VerifyResult memory result);

    // ---------------------------------------------------------------------
    //                   Административные апдейты (поверх ACL)
    // ---------------------------------------------------------------------

    /// @notice Устанавливает/обновляет Merkle-корень и снапшот кампании.
    /// @dev Ожидается контроль доступа в реализации (например, OWNER/ADMIN роль).
    function setCampaignMerkleRoot(
        uint256 campaignId,
        bytes32 newRoot,
        uint64 snapshotId
    ) external;

    /// @notice Устанавливает/обновляет доверенного подписанта кампании.
    function setCampaignSigner(
        uint256 campaignId,
        address newSigner
    ) external;

    /// @notice Обновляет метаданные/параметры кампании (ABI-кодированные).
    function setCampaignParameters(
        uint256 campaignId,
        bytes calldata paramsCID,
        uint64 snapshotId
    ) external;

    // ---------------------------------------------------------------------
    //                       Утилиты / предикаты режима
    // ---------------------------------------------------------------------

    /// @notice Истина, если реализация поддерживает Merkle-проверку.
    function isMerkleModeSupported() external view returns (bool);

    /// @notice Истина, если реализация поддерживает подписи подписанта.
    function isSignatureModeSupported() external view returns (bool);

    /// @notice Код вычисления листа для Merkle (индикативный идентификатор хеша/кодека).
    /// @dev Например, keccak256(abi.encode(account,tier,score,snapshotId)) -> keccak256/abi.encode.
    function merkleLeafSchema() external view returns (bytes32 schemaId);
}

/// @dev Минимальный интерфейс ERC-165, вынесен локально для самодостаточности.
/// @custom:bytes4 0x01ffc9a7
interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
