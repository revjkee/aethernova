import unittest
from pqcrypto.kem import kyber512, ntru_hps2048509
from pqcrypto.sign import dilithium2
import secrets

class PostQuantumCryptoTests(unittest.TestCase):
    """
    Набор тестов для проверки базовой работоспособности PQC алгоритмов:
    - Kyber512 (KEM)
    - NTRU-HPS2048509 (KEM)
    - Dilithium2 (подписи)
    """

    def test_kyber512_kem(self):
        # Генерация ключей
        pk, sk = kyber512.generate_keypair()
        self.assertIsNotNone(pk)
        self.assertIsNotNone(sk)

        # Шифрование / Дешифрование
        ciphertext, shared_secret_enc = kyber512.encrypt(pk)
        shared_secret_dec = kyber512.decrypt(ciphertext, sk)
        self.assertEqual(shared_secret_enc, shared_secret_dec)

    def test_ntru_hps_kem(self):
        pk, sk = ntru_hps2048509.generate_keypair()
        self.assertIsNotNone(pk)
        self.assertIsNotNone(sk)

        ciphertext, shared_secret_enc = ntru_hps2048509.encrypt(pk)
        shared_secret_dec = ntru_hps2048509.decrypt(ciphertext, sk)
        self.assertEqual(shared_secret_enc, shared_secret_dec)

    def test_dilithium2_sign_verify(self):
        message = secrets.token_bytes(128)
        pk, sk = dilithium2.generate_keypair()

        signature = dilithium2.sign(message, sk)
        verified_message = dilithium2.verify(signature, pk)
        self.assertEqual(message, verified_message)

if __name__ == "__main__":
    unittest.main()
