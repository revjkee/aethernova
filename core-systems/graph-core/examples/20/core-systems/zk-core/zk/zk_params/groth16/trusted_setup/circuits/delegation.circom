pragma circom 2.0.0;

template Delegation() {
    // Входные сигналы
    signal input delegator;          // Хэш делегирующего (user ID или публичный ключ)
    signal input delegatee;          // Хэш делегата
    signal input secret;             // Секрет для подписи или подтверждения права
    signal input nullifier_hash;     // Для предотвращения повторных делегирований

    // Проверка делегирования с использованием nullifier
    signal computed_nullifier;
    computed_nullifier <== Poseidon([secret]);
    nullifier_hash === computed_nullifier;

    // Проверка, что delegator и delegatee валидны (например, в диапазоне)
    // Можно расширить проверками через Merkle proof или другую логику

    // Выходной сигнал — подтверждение валидности делегирования
    signal output valid_delegation;
    valid_delegation <== 1;
}

component main = Delegation();
