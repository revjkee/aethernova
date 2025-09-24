// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IVerifier — универсальный интерфейс ZK-вейрификатора
/// @dev Совместим с Groth16, PLONK и поддерживает future-proof сигнатуры

interface IVerifier {
    /// @notice Проверка доказательства
    /// @param proof сериализованное доказательство
    /// @param publicInputs массив публичных входов (nullifier, root, signal и т.д.)
    /// @return true если proof валиден
    function verifyProof(bytes calldata proof, uint256[] calldata publicInputs) external view returns (bool);

    /// @notice Тип используемого доказательства
    /// @dev Может быть 'groth16', 'plonk', 'halo2', и т.д.
    /// @return bytes32 хеш названия схемы
    function verifierType() external pure returns (bytes32);

    /// @notice Поддерживает ли верификатор заданное количество входов
    /// @param inputLength длина publicInputs
    /// @return true если поддерживает
    function supportsInputLength(uint256 inputLength) external pure returns (bool);

    /// @notice Проверка уникального сигнатурного идентификатора схемы
    /// @dev Для модульной совместимости (cross-verifier architectures)
    function signature() external pure returns (bytes4);
}
