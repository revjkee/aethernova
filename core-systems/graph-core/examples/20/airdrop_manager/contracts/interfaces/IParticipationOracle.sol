// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IParticipationOracle — интерфейс для оценки участия в DAO и offchain/zk-активности
/// @dev Поддерживает ZK-доказательства, hybrid offchain feed, epoch-based audits, обратимую верификацию

interface IParticipationOracle {
    /// @notice Структура метаданных активности
    /// @dev Может быть использована для ZK-подписи и on-chain проверки
    struct ParticipationProof {
        uint256 epoch;
        address user;
        bytes32 merkleRoot;          // Merkle доказательство участия
        bytes32 zkProofHash;         // Хэш zk-SNARK или zk-STARK
        bool verifiedOffchain;       // Признак успешной offchain проверки
        uint256 score;               // Балл участия DAO (0–10000)
    }

    /// @notice Получить участие пользователя в рамках текущей эпохи
    /// @param user адрес пользователя
    /// @return score числовой показатель участия (0–10000)
    function getParticipationScore(address user) external view returns (uint256 score);

    /// @notice Проверка и регистрация активности пользователя
    /// @dev Используется при запросе к MerkleDistributor
    /// @param proof ZK/offchain Merkle-доказательство
    function verifyParticipation(ParticipationProof calldata proof) external;

    /// @notice Проверка участия без записи (например, симуляция)
    /// @param user адрес участника
    /// @return isEligible прошёл ли пользователь минимальный порог
    function isEligible(address user) external view returns (bool isEligible);

    /// @notice Получение текущей эпохи DAO (например, раунда голосования)
    /// @return epoch номер текущей эпохи
    function currentEpoch() external view returns (uint256 epoch);

    /// @notice Получить все данные участия пользователя
    /// @param user адрес
    /// @return proof полные метаданные по участию
    function getParticipationProof(address user) external view returns (ParticipationProof memory proof);
}
