// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ZkIdentity — ZK-компатибильный контракт для идентичностей с использованием Merkle + nullifiers
/// @notice Совместим с Semaphore-подобными системами голосования и приватной аутентификацией

import "./ZkIdentityStorage.sol";
import "./interfaces/IVerifier.sol";

contract ZkIdentity is ZkIdentityStorage {
    IVerifier public immutable verifier;

    /// @notice Событие регистрации новой идентичности
    event IdentityRegistered(uint256 indexed commitment, uint32 leafIndex);

    /// @notice Событие успешной верификации доказательства
    event ProofVerified(uint256 indexed signalHash, uint256 nullifierHash);

    /// @param _verifier адрес контракта Groth16/Plonk верификатора
    /// @param _treeLevels глубина Merkle-дерева
    constructor(IVerifier _verifier, uint8 _treeLevels) {
        verifier = _verifier;
        _initializeMerkleTree(_treeLevels);
    }

    /// @notice Регистрация нового коммита идентичности
    /// @param identityCommitment хеш-коммитмента (Poseidon hash)
    function register(uint256 identityCommitment) external {
        require(identityCommitment != 0, "ZkIdentity: zero commitment");

        uint32 index = _insert(identityCommitment);
        emit IdentityRegistered(identityCommitment, index);
    }

    /// @notice Верификация доказательства владения идентичностью без раскрытия личности
    /// @param root корень дерева, сгенерированный off-chain
    /// @param nullifierHash хеш nullifier'а, предотвращающий повторную валидацию
    /// @param signalHash хеш сигнала/действия
    /// @param externalNullifier external scope для защиты от re-use
    /// @param proof доказательство Groth16/Plonk
    function verifyProof(
        uint256 root,
        uint256 nullifierHash,
        uint256 signalHash,
        uint256 externalNullifier,
        uint256[8] calldata proof
    ) external {
        require(!isNullifierUsed(nullifierHash), "ZkIdentity: nullifier already used");
        require(isKnownRoot(root), "ZkIdentity: unknown Merkle root");

        bool valid = verifier.verifyProof(
            [signalHash, root, nullifierHash, externalNullifier],
            proof
        );

        require(valid, "ZkIdentity: invalid ZK proof");

        _markNullifierUsed(nullifierHash);
        emit ProofVerified(signalHash, nullifierHash);
    }

    /// @notice Проверка использованного nullifier
    /// @param nullifierHash nullifier
    /// @return true если nullifier уже использован
    function isNullifierUsed(uint256 nullifierHash) public view returns (bool) {
        return usedNullifiers[nullifierHash];
    }

    /// @notice Пометка nullifier как использованного
    /// @param nullifierHash nullifier
    function _markNullifierUsed(uint256 nullifierHash) internal {
        usedNullifiers[nullifierHash] = true;
    }
}
