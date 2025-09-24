-- crypto_helpers.nse
--
-- Набор вспомогательных функций для криптографических операций в Nmap NSE.
-- Предоставляет базовые реализации хэширования, HMAC, генерации nonce и шифрования с использованием OpenSSL.

local stdnse = require "stdnse"
local openssl = require "openssl"
local string = require "string"
local math = require "math"

_ENV = stdnse.module("crypto_helpers", stdnse.seeall)

--- Генерация безопасного случайного nonce
-- @param length Длина nonce в байтах
-- @return Строка с nonce
function gen_nonce(length)
  local result = {}
  for i = 1, length do
    result[i] = string.char(math.random(0, 255))
  end
  return table.concat(result)
end

--- Вычисление HMAC
-- @param alg Хэш-алгоритм ("sha1", "sha256", "md5", и т.п.)
-- @param key Секретный ключ
-- @param data Сообщение
-- @return hex-строка HMAC
function hmac(alg, key, data)
  local digest = openssl.hmac(alg, key, data)
  return (digest and openssl.hex(digest)) or nil
end

--- Вычисление хэша
-- @param alg Хэш-алгоритм
-- @param data Сообщение
-- @return hex-строка хэша
function hash(alg, data)
  local ctx = openssl.digest.new(alg)
  ctx:update(data)
  return openssl.hex(ctx:final())
end

--- XOR двух строк
-- @param a Первая строка
-- @param b Вторая строка
-- @return Результат XOR в виде строки
function xor_bytes(a, b)
  local out = {}
  for i = 1, math.min(#a, #b) do
    out[i] = string.char(bit.bxor(a:byte(i), b:byte(i)))
  end
  return table.concat(out)
end

--- Шифрование AES-256-CBC
-- @param plaintext Открытый текст
-- @param key 32-байтный ключ
-- @param iv 16-байтный вектор инициализации
-- @return Шифротекст
function encrypt_aes_cbc(plaintext, key, iv)
  local cipher = openssl.cipher.new("aes-256-cbc")
  cipher:init(true, key, iv)
  local encrypted = cipher:update(plaintext)
  return encrypted .. cipher:final()
end

--- Расшифровка AES-256-CBC
-- @param ciphertext Шифротекст
-- @param key 32-байтный ключ
-- @param iv 16-байтный вектор инициализации
-- @return Открытый текст
function decrypt_aes_cbc(ciphertext, key, iv)
  local cipher = openssl.cipher.new("aes-256-cbc")
  cipher:init(false, key, iv)
  local decrypted = cipher:update(ciphertext)
  return decrypted .. cipher:final()
end

--- Конвертация строки в hex
-- @param s строка
-- @return hex-представление
function tohex(s)
  return (s and openssl.hex(s)) or nil
end

--- Конвертация hex в строку
-- @param hex hex-представление
-- @return строка
function fromhex(hex)
  return openssl.hex(hex, true)
end

return _ENV
