pragma circom 2.0.0;

include "circomlib/merkle.circom";

template Membership(depth) {
    // Входные сигналы
    signal input leaf;                   // Хэш участника (публичный ключ или ID)
    signal input root;                   // Корень дерева Меркла DAO
    signal input pathElements[depth];   // Элементы пути Меркла
    signal input pathIndices[depth];    // Индексы (0 или 1) для пути

    component merkleProof = MerkleProof(depth);

    // Подключение входных данных в MerkleProof
    for (var i = 0; i < depth; i++) {
        merkleProof.pathElements[i] <== pathElements[i];
        merkleProof.pathIndices[i] <== pathIndices[i];
    }
    merkleProof.leaf <== leaf;

    // Проверка валидности членства — корень совпадает с заданным
    signal output valid;
    valid <== (merkleProof.root === root) ? 1 : 0;
}

component main = Membership(20);
