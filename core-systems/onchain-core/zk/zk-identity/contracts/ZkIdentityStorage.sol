// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ZkIdentityStorage — безопасное хранилище коммитов и Merkle-корней
/// @notice Предоставляет вставку в Merkle-дерево, проверку корней и отслеживание nullifiers

import "./interfaces/IZkIdentity.sol";
import "./libraries/PoseidonT3.sol";
import "./libraries/MerkleTree.sol";

abstract contract ZkIdentityStorage is IZkIdentity {
    using MerkleTree for MerkleTree.Tree;

    MerkleTree.Tree private tree;

    mapping(uint256 => bool) public usedNullifiers;
    mapping(uint256 => bool) public historicalRoots;

    /// @notice Инициализация Merkle-дерева
    /// @param _levels глубина дерева (например, 20 → 2^20 листов)
    function _initializeMerkleTree(uint8 _levels) internal {
        require(tree.levels == 0, "ZkIdentityStorage: already initialized");
        require(_levels > 0 && _levels <= 32, "ZkIdentityStorage: invalid level");
        tree.init(_levels);
    }

    /// @notice Вставка коммитмента в дерево
    /// @param _leaf коммит (identityCommitment)
    /// @return leafIndex индекс вставленного листа
    function _insert(uint256 _leaf) internal returns (uint32 leafIndex) {
        leafIndex = tree.insert(_leaf);
        uint256 newRoot = tree.root();

        historicalRoots[newRoot] = true;
    }

    /// @notice Проверка валидности корня
    /// @param _root корень дерева
    function isKnownRoot(uint256 _root) public view returns (bool) {
        return historicalRoots[_root];
    }

    /// @notice Текущий корень дерева
    function currentRoot() external view returns (uint256) {
        return tree.root();
    }

    /// @notice Получение листа по индексу
    /// @param _index индекс
    function leafAt(uint32 _index) external view returns (uint256) {
        return tree.leaf(_index);
    }

    /// @notice Получение количества вставленных листов
    function leafCount() external view returns (uint32) {
        return tree.nextIndex;
    }
}
