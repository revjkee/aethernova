// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MerkleDistributor for secure airdrop verification and claiming
/// @author TeslaAI Genesis
/// @notice Implements merkle-root-based airdrop logic with anti-replay, audit, and modularization
/// @custom:security-contact security@teslaai.gen

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/structs/BitMaps.sol";
import "./interfaces/IAirdropToken.sol";

contract MerkleDistributor is Ownable, ReentrancyGuard {
    using MerkleProof for bytes32[];
    using BitMaps for BitMaps.BitMap;

    event Claimed(uint256 indexed index, address indexed account, uint256 amount, uint256 timestamp);
    event MerkleRootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot, uint256 updatedAt);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    bytes32 public merkleRoot;
    address public immutable token;
    bool public paused;

    BitMaps.BitMap private claimedBitMap;

    modifier whenNotPaused() {
        require(!paused, "MerkleDistributor: paused");
        _;
    }

    modifier onlyEOA() {
        require(tx.origin == msg.sender, "MerkleDistributor: only EOA");
        _;
    }

    constructor(address _token, bytes32 _merkleRoot) {
        require(_token != address(0), "Invalid token address");
        token = _token;
        merkleRoot = _merkleRoot;
    }

    function isClaimed(uint256 index) public view returns (bool) {
        return claimedBitMap.get(index);
    }

    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata merkleProof)
        external
        whenNotPaused
        nonReentrant
        onlyEOA
    {
        require(!isClaimed(index), "Already claimed");

        bytes32 node = keccak256(abi.encodePacked(index, account, amount));
        require(merkleProof.verify(merkleRoot, node), "Invalid proof");

        claimedBitMap.set(index);
        require(IAirdropToken(token).transfer(account, amount), "Transfer failed");

        emit Claimed(index, account, amount, block.timestamp);
    }

    function updateMerkleRoot(bytes32 newRoot) external onlyOwner {
        require(newRoot != merkleRoot, "Same root");
        emit MerkleRootUpdated(merkleRoot, newRoot, block.timestamp);
        merkleRoot = newRoot;
    }

    function pause() external onlyOwner {
        require(!paused, "Already paused");
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        require(paused, "Already unpaused");
        paused = false;
        emit Unpaused(msg.sender);
    }

    function rescueTokens(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "Invalid address");
        require(IAirdropToken(token).transfer(to, amount), "Rescue failed");
    }

    function sweepUnclaimed(uint256[] calldata indexes, address receiver) external onlyOwner {
        require(receiver != address(0), "Invalid receiver");
        uint256 total;
        for (uint256 i = 0; i < indexes.length; i++) {
            if (!isClaimed(indexes[i])) {
                claimedBitMap.set(indexes[i]);
                // In production: resolve amount via oracle or offchain claim record
                uint256 amount = 0;
                require(IAirdropToken(token).transfer(receiver, amount), "Sweep failed");
                emit Claimed(indexes[i], receiver, amount, block.timestamp);
                total += amount;
            }
        }
    }
}
