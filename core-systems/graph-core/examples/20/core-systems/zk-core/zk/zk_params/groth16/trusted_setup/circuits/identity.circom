pragma circom 2.0.0;

template Identity() {
    // Входные сигналы
    signal input identity_secret;       // Секретный идентификатор пользователя
    signal input identity_public_hash;  // Публичный хэш идентификатора

    // Внутренние сигналы
    signal calculated_hash;

    // Вычисление хэша от секретного идентификатора (например, Poseidon hash)
    calculated_hash <== Poseidon([identity_secret]);

    // Проверка равенства вычисленного и публичного хэша
    identity_public_hash === calculated_hash;

    // Выходной сигнал - подтверждение корректности
    signal output is_valid;
    is_valid <== 1;
}

component main = Identity();
