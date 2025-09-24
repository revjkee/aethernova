# Шаги воспроизводимости trusted setup

Этот документ описывает точные шаги, необходимые для воспроизведения trusted setup для схемы Groth16.

## Предпосылки

- Установлены все зависимости:
  - `snarkjs` версии 0.5.1 или выше
  - `powersoftau` toolkit
  - `circom` компилятор схем
- Имеется исходный код схемы и все исходные параметры

## Шаги

1. **Фаза 1: Универсальный trusted setup**

   - Запустить генерацию параметров `powers_of_tau_15.ptau` для 2^15 constraints:
     ```
     snarkjs powersoftau new bn128 15 pot15_0000.ptau -v
     snarkjs powersoftau contribute pot15_0000.ptau pot15_0001.ptau --name="First contribution" -v
     ```
   - Проверить целостность и валидность файла:
     ```
     snarkjs powersoftau verify pot15_0001.ptau
     ```

2. **Фаза 2: Создание параметров схемы**

   - Компилировать схему:
     ```
     circom circuit.circom --r1cs --wasm --sym
     ```
   - Запустить trusted setup с использованием универсальных параметров:
     ```
     snarkjs groth16 setup circuit.r1cs pot15_0001.ptau circuit_final.zkey
     ```

3. **Фаза 3: Ceremony (вклад участников)**

   - Каждый участник вносит случайный вклад:
     ```
     snarkjs zkey contribute circuit_final.zkey circuit_final_1.zkey --name="Contributor name" -v
     ```
   - Проверить валидность:
     ```
     snarkjs zkey verify circuit.r1cs pot15_0001.ptau circuit_final_1.zkey
     ```

4. **Фаза 4: Beacon (отказ от доверия)**

   - Добавить beacon-фазу:
     ```
     snarkjs zkey beacon circuit_final_1.zkey circuit_final_beacon.zkey 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10
     ```
   - Финальная проверка:
     ```
     snarkjs zkey verify circuit.r1cs pot15_0001.ptau circuit_final_beacon.zkey
     ```

5. **Проверка итогов**

   - Проверка всех файлов на соответствие и хеши с помощью `hash_checksums.txt`.
   - Проверка логов `full_transcript.log` на непрерывность и отсутствие ошибок.

## Примечания

- Все команды должны выполняться в безопасной среде.
- Использование нескольких участников и многократных вкладов снижает риск компрометации.
- Логи и контрольные суммы обязательны для аудита и подтверждения честности.

---

Файл содержит пошаговые команды и описания для воспроизводимости и проверки trusted setup в полном объёме.

Готов предоставить полный файл для загрузки.
