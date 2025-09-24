pragma circom 2.0.0;

template Vote(n) {
    // Входные сигналы
    signal input vote_choice;           // Голос пользователя (число от 0 до n-1)
    signal input valid_choices_hash;    // Хэш множества допустимых вариантов
    signal input secret;                // Секрет для подтверждения права голоса
    signal input nullifier_hash;        // Хэш для предотвращения повторного голосования

    // Внутренние сигналы
    signal is_valid_choice;
    signal computed_nullifier;

    // Проверка, что голос входит в диапазон [0, n-1]
    is_valid_choice <== vote_choice < n ? 1 : 0;
    is_valid_choice === 1;

    // Проверка уникальности nullifier (например, с помощью Poseidon)
    computed_nullifier <== Poseidon([secret]);
    nullifier_hash === computed_nullifier;

    // Дополнительная логика проверки допустимых вариантов
    // Можно добавить Merkle proof или другое подтверждение принадлежности голосующего к списку

    // Выходной сигнал подтверждения валидности голоса
    signal output valid_vote;
    valid_vote <== is_valid_choice;
}

component main = Vote(3); // Пример: 3 варианта голосования
