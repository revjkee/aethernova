// signature_check.c
// Проверка цифровой подписи на основе постквантового алгоритма (например, Dilithium)

// Необходимые заголовки
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dilithium.h"  // API для постквантовой подписи Dilithium

// Функция вывода массива байт в hex для отладки
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main() {
    // Ключи, сообщение, подпись
    unsigned char pk[DILITHIUM_PUBLICKEYBYTES];
    unsigned char sk[DILITHIUM_SECRETKEYBYTES];
    unsigned char message[] = "Тестовое сообщение для подписи";
    size_t message_len = sizeof(message) - 1;
    unsigned char signature[DILITHIUM_SIGNATUREBYTES];
    size_t signature_len;

    // Генерация пары ключей
    if (dilithium_keypair(pk, sk) != 0) {
        fprintf(stderr, "Ошибка генерации ключей\n");
        return 1;
    }
    printf("Публичный ключ: ");
    print_hex(pk, DILITHIUM_PUBLICKEYBYTES);

    // Подписываем сообщение
    if (dilithium_sign(signature, &signature_len, message, message_len, sk) != 0) {
        fprintf(stderr, "Ошибка создания подписи\n");
        return 1;
    }
    printf("Подпись (%zu байт): ", signature_len);
    print_hex(signature, signature_len);

    // Проверяем подпись
    int verify_result = dilithium_verify(signature, signature_len, message, message_len, pk);
    if (verify_result == 0) {
        printf("Подпись успешно проверена.\n");
    } else {
        printf("Ошибка проверки подписи!\n");
        return 1;
    }

    return 0;
}
