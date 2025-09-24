// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ParticipationOracle
 * @notice Industrial-grade oracle for airdrop participation verification.
 *         Supports two proof mechanisms:
 *           1) Off-chain attestations signed per EIP-712 by authorized SIGNERs.
 *           2) Off-chain allowlists via Merkle roots per campaign.
 *
 *         Security hardening:
 *           - EIP-712 domain separation (chainId + verifyingContract).
 *           - Nonce-based replay protection per participant+campaign.
 *           - Deadlines on signatures.
 *           - Role-based access control (ADMIN/MANAGER/PAUSER/SIGNER).
 *           - Pausable emergency stop; Reentrancy guard on state-mutating paths.
 *           - Custom errors for gas efficiency.
 *
 * Sources (specs & libraries used):
 *   - EIP-712 typed structured data: https://eips.ethereum.org/EIPS/eip-712
 *   - OpenZeppelin 5.x cryptography (EIP712, SignatureChecker, MerkleProof): https://docs.openzeppelin.com/contracts/5.x/api/utils/cryptography
 *   - OpenZeppelin 5.x AccessControl: https://docs.openzeppelin.com/contracts/5.x/api/access
 *   - OpenZeppelin 5.x ReentrancyGuard: https://docs.openzeppelin.com/contracts/5.x/api/utils
 *   - OpenZeppelin 5.x Pausable: https://docs.openzeppelin.com/contracts/5.x/api/utils
 *   - OpenZeppelin 5.x EnumerableSet: https://docs.openzeppelin.com/contracts/5.x/api/utils
 *   - IERC5267 (EIP-712 domain info): https://docs.openzeppelin.com/contracts/5.x/api/interfaces
 *   - Solidity 0.8 checked arithmetic: https://docs.soliditylang.org/en/latest/control-structures.html
 */

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract ParticipationOracle is AccessControl, Pausable, ReentrancyGuard, EIP712 {
    using EnumerableSet for EnumerableSet.AddressSet;

    // ========= Roles =========
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant PAUSER_ROLE  = keccak256("PAUSER_ROLE");
    // SIGNERs are oracle accounts (EOA or ERC-1271 smart wallets) that co-sign EIP-712 attestations
    bytes32 public constant SIGNER_ROLE  = keccak256("SIGNER_ROLE");

    // ========= Errors (gas efficient) =========
    error ErrUnauthorized();
    error ErrInvalidSignature();
    error ErrSignatureExpired(uint64 expiresAt, uint256 nowTs);
    error ErrNonceUsed(address participant, bytes32 campaignId, uint96 nonce);
    error ErrZeroAddress();
    error ErrInvalidProof();
    error ErrNoSignersConfigured();

    // ========= Events =========
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event CampaignMerkleRootUpdated(bytes32 indexed campaignId, bytes32 indexed root);
    event AttestedBySignature(
        address indexed participant,
        bytes32 indexed campaignId,
        uint96 score,
        uint96 nonce,
        uint64 expiresAt,
        address indexed signer
    );
    event AttestedByMerkle(
        address indexed participant,
        bytes32 indexed campaignId,
        uint96 score,
        uint96 nonce
    );

    // ========= Storage =========

    // Authorized signers set (enumerable for SignatureChecker over ERC-1271 signers)
    EnumerableSet.AddressSet private _signers;

    // Merkle roots per campaign (optional alternative verification track)
    mapping(bytes32 => bytes32) public campaignMerkleRoot;

    // Replay protection: participant+campaign+nonce consumed
    mapping(bytes32 => bool) public nonceConsumed;

    // ======== EIP-712 typing ========
    // struct Participation {
    //   address participant;
    //   bytes32 campaignId;
    //   uint96  score;
    //   uint96  nonce;
    //   uint64  expiresAt; // unix timestamp (sec)
    // }
    bytes32 private constant PARTICIPATION_TYPEHASH = keccak256(
        "Participation(address participant,bytes32 campaignId,uint96 score,uint96 nonce,uint64 expiresAt)"
    );

    // ======== Constructor ========
    constructor(address initialAdmin)
        EIP712("ParticipationOracle", "1")
    {
        if (initialAdmin == address(0)) revert ErrZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(MANAGER_ROLE, initialAdmin);
        _grantRole(PAUSER_ROLE, initialAdmin);
    }

    // ========= Admin / Manager controls =========

    function pause() external onlyRole(PAUSER_ROLE) { _pause(); }

    function unpause() external onlyRole(PAUSER_ROLE) { _unpause(); }

    /// @notice Adds a signer (EOA or ERC-1271 capable contract) authorized for EIP-712 attestations.
    function addSigner(address signer) external onlyRole(MANAGER_ROLE) {
        if (signer == address(0)) revert ErrZeroAddress();
        bool added = _signers.add(signer);
        if (added) {
            _grantRole(SIGNER_ROLE, signer);
            emit SignerAdded(signer);
        }
    }

    /// @notice Removes a signer from the authorized set.
    function removeSigner(address signer) external onlyRole(MANAGER_ROLE) {
        bool removed = _signers.remove(signer);
        if (removed) {
            _revokeRole(SIGNER_ROLE, signer);
            emit SignerRemoved(signer);
        }
    }

    /// @notice Returns the list of current authorized signers.
    function getSigners() external view returns (address[] memory) {
        return _signers.values();
    }

    /// @notice Sets/rotates the Merkle root for a campaign (optional verification path).
    function setCampaignMerkleRoot(bytes32 campaignId, bytes32 root) external onlyRole(MANAGER_ROLE) {
        campaignMerkleRoot[campaignId] = root;
        emit CampaignMerkleRootUpdated(campaignId, root);
    }

    // ========= Public verification (signature path) =========

    /// @notice Verifies and records an EIP-712 attestation. Reverts on invalid/expired/used.
    /// @dev Emits AttestedBySignature and burns the nonce on success.
    function attestWithSignature(
        address participant,
        bytes32 campaignId,
        uint96 score,
        uint96 nonce_,
        uint64 expiresAt,
        bytes calldata signature
    )
        external
        whenNotPaused
        nonReentrant
    {
        if (expiresAt < uint64(block.timestamp)) {
            revert ErrSignatureExpired(expiresAt, block.timestamp);
        }

        bytes32 nonceKey = _nonceKey(participant, campaignId, nonce_);
        if (nonceConsumed[nonceKey]) revert ErrNonceUsed(participant, campaignId, nonce_);

        bytes32 structHash = keccak256(
            abi.encode(
                PARTICIPATION_TYPEHASH,
                participant,
                campaignId,
                score,
                nonce_,
                expiresAt
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);

        address resolvedSigner = _resolveValidSigner(digest, signature);
        // Burn the nonce and emit event (state change last)
        nonceConsumed[nonceKey] = true;

        emit AttestedBySignature(participant, campaignId, score, nonce_, expiresAt, resolvedSigner);
    }

    /// @notice View-only check for an EIP-712 attestation (no state changes).
    function isValidSignatureAttestation(
        address participant,
        bytes32 campaignId,
        uint96 score,
        uint96 nonce_,
        uint64 expiresAt,
        bytes calldata signature
    ) external view returns (bool) {
        if (expiresAt < uint64(block.timestamp)) return false;
        if (nonceConsumed[_nonceKey(participant, campaignId, nonce_)]) return false;

        bytes32 structHash = keccak256(
            abi.encode(
                PARTICIPATION_TYPEHASH,
                participant,
                campaignId,
                score,
                nonce_,
                expiresAt
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);

        // If at least one authorized signer validates, it's considered valid
        return _hasAnyValidSigner(digest, signature);
    }

    // ========= Public verification (Merkle path) =========

    /// @notice Verifies and records via Merkle proof (leaf = keccak256(participant,campaignId,score,nonce)).
    function attestWithMerkle(
        address participant,
        bytes32 campaignId,
        uint96 score,
        uint96 nonce_,
        bytes32[] calldata merkleProof
    )
        external
        whenNotPaused
        nonReentrant
    {
        bytes32 root = campaignMerkleRoot[campaignId];
        if (root == bytes32(0)) revert ErrInvalidProof();

        bytes32 leaf = keccak256(abi.encodePacked(participant, campaignId, score, nonce_));

        bool ok = MerkleProof.verify(merkleProof, root, leaf);
        if (!ok) revert ErrInvalidProof();

        bytes32 nonceKey = _nonceKey(participant, campaignId, nonce_);
        if (nonceConsumed[nonceKey]) revert ErrNonceUsed(participant, campaignId, nonce_);

        nonceConsumed[nonceKey] = true;
        emit AttestedByMerkle(participant, campaignId, score, nonce_);
    }

    /// @notice Pure leaf helper to mirror off-chain tree building.
    function computeLeaf(
        address participant,
        bytes32 campaignId,
        uint96 score,
        uint96 nonce_
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(participant, campaignId, score, nonce_));
    }

    // ========= Introspection / EIP-712 helpers =========

    /// @notice Exposes the current domain separator (EIP-712 v4).
    function domainSeparatorV4() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ========= Internal helpers =========

    function _resolveValidSigner(bytes32 digest, bytes calldata signature) internal view returns (address) {
        uint256 len = _signers.length();
        if (len == 0) revert ErrNoSignersConfigured();

        // First try fast-path ECDSA.recover: if recovered has SIGNER_ROLE, accept.
        // This covers EOAs without iterating the set.
        (address rec, ECDSA.RecoverError recErr, ) = ECDSA.tryRecover(digest, signature);
        if (recErr == ECDSA.RecoverError.NoError && hasRole(SIGNER_ROLE, rec)) {
            return rec;
        }

        // Slow-path: support ERC-1271 contract signers via SignatureChecker against each authorized signer
        for (uint256 i = 0; i < len; ) {
            address signer = _signers.at(i);
            if (SignatureChecker.isValidSignatureNow(signer, digest, signature)) {
                return signer;
            }
            unchecked { ++i; }
        }
        revert ErrInvalidSignature();
    }

    function _hasAnyValidSigner(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        uint256 len = _signers.length();
        if (len == 0) return false;

        (address rec, ECDSA.RecoverError recErr, ) = ECDSA.tryRecover(digest, signature);
        if (recErr == ECDSA.RecoverError.NoError && hasRole(SIGNER_ROLE, rec)) {
            return true;
        }
        for (uint256 i = 0; i < len; ) {
            if (SignatureChecker.isValidSignatureNow(_signers.at(i), digest, signature)) {
                return true;
            }
            unchecked { ++i; }
        }
        return false;
    }

    function _nonceKey(address participant, bytes32 campaignId, uint96 nonce_) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(participant, campaignId, nonce_));
    }

    // ========= AccessControl wiring =========

    /// @dev Override supportsInterface due to multiple inheritance.
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
