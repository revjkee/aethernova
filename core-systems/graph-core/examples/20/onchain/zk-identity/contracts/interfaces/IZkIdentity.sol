// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IZkIdentity — интерфейс ZK-идентификатора
/// @dev Поддерживает регистрация, проверку, удаление и использование доказательств

interface IZkIdentity {
    /// @notice Структура публичного входа
    struct IdentityInput {
        uint256 identityCommitment;
        uint256 merkleRoot;
        uint256 nullifierHash;
        uint256 signalHash;
        uint256 externalNullifier;
        uint256 proofHash;
    }

    /// @notice Зарегистрировать новый identity commitment в дереве
    /// @param identityCommitment Коммитмент (в виде Poseidon hash)
    function registerIdentity(uint256 identityCommitment) external;

    /// @notice Удалить identity из хранилища (например, при уходе пользователя)
    /// @param identityCommitment Коммитмент для удаления
    function revokeIdentity(uint256 identityCommitment) external;

    /// @notice Проверка доказательства и авторизация сигнала
    /// @param input Полная структура входа для ZK верификации
    /// @param proof Bytes-сериализованное доказательство
    function verifyAndExecute(IdentityInput calldata input, bytes calldata proof) external returns (bool);

    /// @notice Только проверка, без исполнения
    function isValidProof(IdentityInput calldata input, bytes calldata proof) external view returns (bool);

    /// @notice Получить корень текущего Merkle дерева
    function getCurrentRoot() external view returns (uint256);

    /// @notice Проверка была ли nullifierHash уже использована
    function isNullifierUsed(uint256 nullifierHash) external view returns (bool);

    /// @notice Событие при успешной регистрации
    event IdentityRegistered(uint256 indexed identityCommitment);

    /// @notice Событие при отзыве identity
    event IdentityRevoked(uint256 indexed identityCommitment);

    /// @notice Событие при успешной верификации
    event IdentityVerified(address indexed verifier, uint256 indexed signalHash);
}
