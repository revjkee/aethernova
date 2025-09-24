// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MerkleDistributor
 * @notice Industrial-grade ERC20 airdrop distributor secured by Merkle root.
 * - Safe transfers via SafeERC20 (handles non-standard ERC20s)
 * - Reentrancy protection
 * - Pausable emergency switch
 * - Two-step ownership handover (Ownable2Step)
 * - Epoched roots to rotate distributions cleanly
 * - Claim window (start/end)
 * - Bitmap anti-double-claim (per-epoch)
 *
 * Leaf format: keccak256(abi.encodePacked(index, account, amount))
 *
 * References:
 * - OpenZeppelin MerkleProof (verification of inclusion in Merkle trees)
 * - OpenZeppelin SafeERC20 (safe ERC20 transfers)
 * - OpenZeppelin ReentrancyGuard (anti-reentrancy)
 * - OpenZeppelin Pausable (emergency stop)
 * - OpenZeppelin Ownable2Step (safer ownership transfer)
 * - Uniswap MerkleDistributor (bitmap pattern for claimed indices)
 */

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/security/Pausable.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";

contract MerkleDistributor is ReentrancyGuard, Pausable, Ownable2Step {
    using SafeERC20 for IERC20;

    // ------------------------------------------------------------
    // Errors (gas-efficient)
    // ------------------------------------------------------------
    error ZeroAddress();
    error InvalidProof();
    error AlreadyClaimed();
    error ClaimWindowClosed();
    error EpochMismatch();
    error NothingToRecover();

    // ------------------------------------------------------------
    // Events
    // ------------------------------------------------------------
    event Claimed(
        uint256 indexed epoch,
        uint256 indexed index,
        address indexed account,
        uint256 amount
    );

    event MerkleRootUpdated(uint256 indexed oldEpoch, bytes32 oldRoot, uint256 indexed newEpoch, bytes32 newRoot);
    event ClaimWindowUpdated(uint64 startTime, uint64 endTime);
    event Recovered(address indexed token, address indexed to, uint256 amount);

    // ------------------------------------------------------------
    // Immutable / Storage
    // ------------------------------------------------------------

    IERC20 public immutable token;        // ERC-20 being distributed
    bytes32 public merkleRoot;            // current epoch's merkle root
    uint256 public epoch;                 // monotonically increasing epoch id

    // Packed bitmap to record claimed indices per epoch: epoch => (wordIndex => bitmapWord)
    mapping(uint256 => mapping(uint256 => uint256)) private _claimedBitMap;

    // Optional claim window
    uint64 public startTime;              // inclusive; 0 means no restriction
    uint64 public endTime;                // inclusive; 0 means no restriction

    // ------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------
    constructor(
        address token_,
        bytes32 merkleRoot_,
        uint256 initialEpoch_,
        uint64 startTime_,
        uint64 endTime_
    ) Ownable(msg.sender) {
        if (token_ == address(0)) revert ZeroAddress();

        token = IERC20(token_);
        merkleRoot = merkleRoot_;
        epoch = initialEpoch_;

        // sanity: if both provided, ensure start <= end
        if (startTime_ != 0 && endTime_ != 0 && startTime_ > endTime_) {
            // normalize by swapping; this avoids a hard revert on deployment mis-order
            (startTime_, endTime_) = (endTime_, startTime_);
        }
        startTime = startTime_;
        endTime = endTime_;
    }

    // ------------------------------------------------------------
    // Views
    // ------------------------------------------------------------

    function isClaimed(uint256 index) public view returns (bool) {
        return isClaimedAt(epoch, index);
    }

    function isClaimedAt(uint256 epoch_, uint256 index) public view returns (bool) {
        uint256 wordIndex = index >> 8;             // /256
        uint256 bitIndex  = index & 0xff;           // %256
        uint256 word = _claimedBitMap[epoch_][wordIndex];
        uint256 mask = (1 << bitIndex);
        return word & mask == mask;
    }

    // ------------------------------------------------------------
    // Admin
    // ------------------------------------------------------------

    /**
     * @notice Update Merkle root by advancing epoch. Only when paused.
     * @param newEpoch must be strictly greater than current `epoch`
     */
    function updateMerkleRoot(bytes32 newRoot, uint256 newEpoch) external onlyOwner whenPaused {
        if (newEpoch <= epoch) revert EpochMismatch();
        bytes32 oldRoot = merkleRoot;
        uint256 oldEpoch = epoch;

        merkleRoot = newRoot;
        epoch = newEpoch;

        emit MerkleRootUpdated(oldEpoch, oldRoot, newEpoch, newRoot);
    }

    /**
     * @notice Set claim window [startTime, endTime], inclusive. 0 disables bound.
     */
    function setClaimWindow(uint64 startTime_, uint64 endTime_) external onlyOwner {
        if (startTime_ != 0 && endTime_ != 0 && startTime_ > endTime_) {
            (startTime_, endTime_) = (endTime_, startTime_);
        }
        startTime = startTime_;
        endTime   = endTime_;
        emit ClaimWindowUpdated(startTime_, endTime_);
    }

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    /**
     * @notice Recover arbitrary ERC20 mistakenly sent to this contract.
     *         Does NOT touch distribution `token`.
     */
    function recoverERC20(address erc20, address to, uint256 amount) external onlyOwner {
        if (erc20 == address(token)) revert NothingToRecover();
        if (to == address(0)) revert ZeroAddress();
        IERC20(erc20).safeTransfer(to, amount);
        emit Recovered(erc20, to, amount);
    }

    // ------------------------------------------------------------
    // Claim logic
    // ------------------------------------------------------------

    /**
     * @notice Claim a single allocation for the current epoch.
     * @dev leaf = keccak256(abi.encodePacked(index, account, amount))
     */
    function claim(
        uint256 index,
        address account,
        uint256 amount,
        bytes32[] calldata merkleProof
    ) external nonReentrant whenNotPaused {
        _checkWindow();

        if (isClaimed(index)) revert AlreadyClaimed();

        // Verify proof
        bytes32 node = keccak256(abi.encodePacked(index, account, amount));
        bool valid = MerkleProof.verify(merkleProof, merkleRoot, node);
        if (!valid) revert InvalidProof();

        // Effects
        _setClaimed(epoch, index);

        // Interactions
        token.safeTransfer(account, amount);

        emit Claimed(epoch, index, account, amount);
    }

    /**
     * @notice Batch claim multiple allocations for the current epoch.
     *         Reverts atomically if any leaf fails or already claimed.
     */
    function claimMany(
        uint256[] calldata indices,
        address[] calldata accounts,
        uint256[] calldata amounts,
        bytes32[][] calldata proofs
    ) external nonReentrant whenNotPaused {
        _checkWindow();
        uint256 len = indices.length;
        if (len != accounts.length || len != amounts.length || len != proofs.length) {
            revert InvalidProof();
        }

        // Effects first: set all bits to avoid partial transfers on later failure
        for (uint256 i = 0; i < len; ) {
            uint256 index = indices[i];
            if (isClaimed(index)) revert AlreadyClaimed();

            bytes32 node = keccak256(abi.encodePacked(index, accounts[i], amounts[i]));
            bool valid = MerkleProof.verify(proofs[i], merkleRoot, node);
            if (!valid) revert InvalidProof();

            _setClaimed(epoch, index);

            unchecked { ++i; }
        }

        // Interactions second
        for (uint256 i = 0; i < len; ) {
            token.safeTransfer(accounts[i], amounts[i]);
            emit Claimed(epoch, indices[i], accounts[i], amounts[i]);
            unchecked { ++i; }
        }
    }

    // ------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------

    function _setClaimed(uint256 epoch_, uint256 index) internal {
        uint256 wordIndex = index >> 8;   // /256
        uint256 bitIndex  = index & 0xff; // %256
        _claimedBitMap[epoch_][wordIndex] |= (1 << bitIndex);
    }

    function _checkWindow() internal view {
        if (startTime != 0 && block.timestamp < startTime) revert ClaimWindowClosed();
        if (endTime != 0 && block.timestamp > endTime) revert ClaimWindowClosed();
    }
}
