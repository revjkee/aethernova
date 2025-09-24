// kyber_demo.c
// Демонстрация базового обмена ключами на основе Kyber (постквантовый алгоритм)

// Включаем необходимые заголовки
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kyber.h"  // Заголовок с API Kyber (ключи, шифрование, дешифрование)

// Функция для печати массива байт в hex формате
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main() {
    // Буферы для ключей и секретов
    unsigned char pk[KYBER_PUBLICKEYBYTES];
    unsigned char sk[KYBER_SECRETKEYBYTES];
    unsigned char ct[KYBER_CIPHERTEXTBYTES];
    unsigned char ss1[KYBER_SSBYTES];
    unsigned char ss2[KYBER_SSBYTES];

    // Генерация ключевой пары (ключ публичный и секретный)
    if (kyber_keypair(pk, sk) != 0) {
        fprintf(stderr, "Ошибка генерации ключей\n");
        return 1;
    }
    printf("Публичный ключ: ");
    print_hex(pk, KYBER_PUBLICKEYBYTES);

    // Симуляция партнёра, который шифрует и создаёт общий секрет
    if (kyber_enc(ct, ss1, pk) != 0) {
        fprintf(stderr, "Ошибка шифрования\n");
        return 1;
    }
    printf("Зашифрованный ключ (ciphertext): ");
    print_hex(ct, KYBER_CIPHERTEXTBYTES);

    // Дешифрование и вычисление общего секрета
    if (kyber_dec(ss2, ct, sk) != 0) {
        fprintf(stderr, "Ошибка дешифрования\n");
        return 1;
    }

    // Проверка совпадения секретов
    if (memcmp(ss1, ss2, KYBER_SSBYTES) == 0) {
        printf("Общий секрет успешно установлен и совпадает.\n");
        printf("Общий секрет: ");
        print_hex(ss1, KYBER_SSBYTES);
    } else {
        printf("Ошибка: общий секрет не совпадает!\n");
        return 1;
    }

    return 0;
}
