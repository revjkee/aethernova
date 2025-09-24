// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IVerifier — zk-SNARK/zk-STARK Verifier Interface для DAO, Airdrop, Identity и пр.
/// @notice Используется любыми контрактами, которым требуется проверка доказательств участия без раскрытия данных.
/// @custom:standard TeslaAI zkInterface v2.1

interface IVerifier {
    /// @notice Верифицирует zk-доказательство и возвращает true/false
    /// @param proof zk-доказательство (Groth16, Plonk, Starkware и т.д.)
    /// @param publicInputs массив публичных входов (например, Merkle root, signal hash)
    /// @return valid true если доказательство валидно
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool valid);

    /// @notice Возвращает имя используемой схемы верификации (например, Groth16)
    function verifierType() external pure returns (string memory);

    /// @notice Версия схемы или билд идентификатор
    function version() external pure returns (string memory);
}
