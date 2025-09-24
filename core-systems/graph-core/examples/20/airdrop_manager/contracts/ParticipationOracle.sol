// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ParticipationOracle — DAO-оценка активности с поддержкой zk и offchain-подписей
/// @author TeslaAI Genesis
/// @notice Используется для валидации участия в миссиях/вызовах/голосованиях DAO перед airdrop
/// @custom:zk-snark zk-proof (опционально), offchain signer, revocable attestations

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract ParticipationOracle is Ownable {
    using ECDSA for bytes32;

    event Verified(address indexed user, string label, uint256 timestamp);
    event Revoked(address indexed user, string label, uint256 revokedAt);
    event SignerUpdated(address oldSigner, address newSigner);
    event ZkProofVerified(address indexed user, bytes32 signal, bytes32 proofHash);

    mapping(address => mapping(string => bool)) public verified;
    mapping(address => mapping(string => bool)) public revoked;
    address public trustedSigner;

    modifier notRevoked(address user, string memory label) {
        require(!revoked[user][label], "ParticipationOracle: revoked");
        _;
    }

    constructor(address _signer) {
        require(_signer != address(0), "Invalid signer");
        trustedSigner = _signer;
    }

    function updateSigner(address newSigner) external onlyOwner {
        require(newSigner != address(0), "Zero address");
        emit SignerUpdated(trustedSigner, newSigner);
        trustedSigner = newSigner;
    }

    function verifyOffchain(
        address user,
        string memory label,
        uint256 timestamp,
        bytes memory signature
    ) external notRevoked(user, label) {
        require(!verified[user][label], "Already verified");

        bytes32 message = keccak256(abi.encodePacked(user, label, timestamp)).toEthSignedMessageHash();
        address recovered = message.recover(signature);
        require(recovered == trustedSigner, "Invalid signer");

        verified[user][label] = true;
        emit Verified(user, label, timestamp);
    }

    function verifyZkProof(
        address user,
        bytes32 signal,
        bytes32 proofHash,
        bytes calldata proof
    ) external notRevoked(user, "zk") {
        // zk-proof verification simulated (off-chain prevalidation required)
        require(_simulateZkCheck(signal, proofHash, proof), "Invalid zk-proof");

        verified[user]["zk"] = true;
        emit ZkProofVerified(user, signal, proofHash);
    }

    function revoke(address user, string memory label) external onlyOwner {
        require(!revoked[user][label], "Already revoked");
        revoked[user][label] = true;
        emit Revoked(user, label, block.timestamp);
    }

    function isVerified(address user, string memory label) external view returns (bool) {
        return verified[user][label] && !revoked[user][label];
    }

    // В боевой версии этот метод заменяется zkSNARK / Groth16 интерфейсом
    function _simulateZkCheck(
        bytes32 signal,
        bytes32 proofHash,
        bytes memory proof
    ) internal pure returns (bool) {
        // Примерная валидация
        return signal != bytes32(0) && proofHash != bytes32(0) && proof.length > 0;
    }
}
