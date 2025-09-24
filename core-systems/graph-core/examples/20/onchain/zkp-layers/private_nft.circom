// private_nft.circom
// zk-SNARK схема для приватной проверки владения NFT по токен-идентификатору и владельцу
// Автор: Влад

pragma circom 2.0.0;

template PrivateNFVOwnerProof() {
    signal input tokenId;       // Секретный идентификатор NFT
    signal input ownerPrivKey;  // Секретный ключ владельца (хэш или прямая форма)
    signal input publicRoot;    // Публичный корень дерева владения (напр. Merkle root)
    signal input proofPath[32]; // Путь доказательства в Merkle дереве
    signal input proofIndices[32]; // Индексы пути (0 или 1)

    signal computedRoot;

    // Здесь реализуем проверку Merkle proof для tokenId и ownerPrivKey
    // Для простоты: hash(tokenId, ownerPrivKey) формирует лист
    // Затем последовательно вычисляем корень по proofPath и proofIndices

    signal leafHash;
    leafHash <== Poseidon([tokenId, ownerPrivKey]);

    component merkleVerifier = MerkleTreeVerifier(32);
    merkleVerifier.leaf <== leafHash;
    merkleVerifier.path <== proofPath;
    merkleVerifier.pathIndices <== proofIndices;

    computedRoot <== merkleVerifier.root;

    // Проверяем, что вычисленный корень равен публичному корню дерева владения
    computedRoot === publicRoot;

    signal output isValid;
    isValid <== 1;
}

// Вспомогательный компонент MerkleTreeVerifier реализует проверку Merkle proof
template MerkleTreeVerifier(depth) {
    signal input leaf;
    signal input path[depth];
    signal input pathIndices[depth]; // 0 или 1

    signal output root;

    signal currentHash;
    currentHash <== leaf;

    for (var i = 0; i < depth; i++) {
        signal left;
        signal right;

        left <== (pathIndices[i] == 0) ? currentHash : path[i];
        right <== (pathIndices[i] == 0) ? path[i] : currentHash;

        currentHash <== Poseidon([left, right]);
    }

    root <== currentHash;
}

component main = PrivateNFVOwnerProof();
