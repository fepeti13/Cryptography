import pytest
import os
import sys
from encryption_machine import *

@pytest.fixture(autouse=True)
def setup_block_size():
    global BLOCK_SIZE
    BLOCK_SIZE = 16

class TestAESEncryption:
    
    def test_ecb_aes_roundtrip(self):
        plaintext = bytearray(b'Hello World!!!!!')
        key = b'0123456789ABCDEF'
        
        encrypt_func, decrypt_func = get_cipher_functions("AES")
        
        encrypted = ECB_encrypt(plaintext, key, encrypt_func, "Schneier_Ferguson_padding", 16)
        decrypted = ECB_decrypt(encrypted, key, decrypt_func, "Schneier_Ferguson_padding", 16)
        
        assert bytes(decrypted) == bytes(plaintext)
    
    def test_cbc_aes_roundtrip(self):
        plaintext = bytearray(b'Test message!!!!')
        key = b'0123456789ABCDEF'
        iv = bytearray(b'FEDCBA9876543210')
        
        encrypt_func, decrypt_func = get_cipher_functions("AES")
        
        encrypted = CBC_encrypt(plaintext, key, encrypt_func, iv, "Schneier_Ferguson_padding", 16)
        decrypted = CBC_decrypt(encrypted, key, decrypt_func, iv, "Schneier_Ferguson_padding", 16)
        
        assert bytes(decrypted) == bytes(plaintext)
    
    def test_cfb_aes_roundtrip(self):
        plaintext = bytearray(b'CFB mode test message here!')
        key = b'0123456789ABCDEF'
        iv = bytearray(b'FEDCBA9876543210')
        
        encrypt_func, decrypt_func = get_cipher_functions("AES")
        
        encrypted = CFB_encrypt(plaintext, key, encrypt_func, iv, 16)
        decrypted = CFB_decrypt(encrypted, key, decrypt_func, iv, 16)
        
        assert bytes(decrypted) == bytes(plaintext)
    
    def test_ofb_aes_roundtrip(self):
        plaintext = bytearray(b'OFB mode test!')
        key = b'0123456789ABCDEF'
        iv = bytearray(b'FEDCBA9876543210')
        
        encrypt_func, decrypt_func = get_cipher_functions("AES")
        
        encrypted = OFB_encrypt(plaintext, key, encrypt_func, iv, 16)
        decrypted = OFB_decrypt(encrypted, key, decrypt_func, iv, 16)
        
        assert bytes(decrypted) == bytes(plaintext)
    
    def test_ctr_aes_roundtrip(self):
        plaintext = bytearray(b'CTR mode test message!')
        key = b'0123456789ABCDEF'
        nonce = bytearray(b'12345678')
        
        encrypt_func, decrypt_func = get_cipher_functions("AES")
        
        encrypted = CTR_encrypt(plaintext, key, encrypt_func, nonce, 16)
        decrypted = CTR_decrypt(encrypted, key, decrypt_func, nonce, 16)
        
        assert bytes(decrypted) == bytes(plaintext)


class TestDESEncryption:
    
    def test_ecb_des_roundtrip(self):
        plaintext = bytearray(b'Hello!!!')
        key = b'12345678'
        
        encrypt_func, decrypt_func = get_cipher_functions("DES")
        
        encrypted = ECB_encrypt(plaintext, key, encrypt_func, "Schneier_Ferguson_padding", 8)
        decrypted = ECB_decrypt(encrypted, key, decrypt_func, "Schneier_Ferguson_padding", 8)
        
        assert bytes(decrypted) == bytes(plaintext)
    
    def test_cbc_des_roundtrip(self):
        plaintext = bytearray(b'TestMsg!')
        key = b'12345678'
        iv = bytearray(b'87654321')
        
        encrypt_func, decrypt_func = get_cipher_functions("DES")
        
        encrypted = CBC_encrypt(plaintext, key, encrypt_func, iv, "Schneier_Ferguson_padding", 8)
        decrypted = CBC_decrypt(encrypted, key, decrypt_func, iv, "Schneier_Ferguson_padding", 8)
        
        assert bytes(decrypted) == bytes(plaintext)
    
    def test_cfb_des_roundtrip(self):
        plaintext = bytearray(b'CFB DES test!')
        key = b'12345678'
        iv = bytearray(b'87654321')
        
        encrypt_func, decrypt_func = get_cipher_functions("DES")
        
        encrypted = CFB_encrypt(plaintext, key, encrypt_func, iv, 8)
        decrypted = CFB_decrypt(encrypted, key, decrypt_func, iv, 8)
        
        assert bytes(decrypted) == bytes(plaintext)
    
    def test_ofb_des_roundtrip(self):
        plaintext = bytearray(b'OFB test')
        key = b'12345678'
        iv = bytearray(b'87654321')
        
        encrypt_func, decrypt_func = get_cipher_functions("DES")
        
        encrypted = OFB_encrypt(plaintext, key, encrypt_func, iv, 8)
        decrypted = OFB_decrypt(encrypted, key, decrypt_func, iv, 8)
        
        assert bytes(decrypted) == bytes(plaintext)
    
    def test_ctr_des_roundtrip(self):
        plaintext = bytearray(b'CTR DES!')
        key = b'12345678'
        nonce = bytearray(b'1234')
        
        encrypt_func, decrypt_func = get_cipher_functions("DES")
        
        encrypted = CTR_encrypt(plaintext, key, encrypt_func, nonce, 8)
        decrypted = CTR_decrypt(encrypted, key, decrypt_func, nonce, 8)
        
        assert bytes(decrypted) == bytes(plaintext)


class TestCustomEncryption:
    
    def test_ecb_custom_roundtrip(self):
        plaintext = bytearray(b'Hello World!!!!!')
        key = b'mysecretkey12345'
        
        encrypt_func, decrypt_func = get_cipher_functions("CUSTOM")
        
        encrypted = ECB_encrypt(plaintext, key, encrypt_func, "Schneier_Ferguson_padding", 16)
        decrypted = ECB_decrypt(encrypted, key, decrypt_func, "Schneier_Ferguson_padding", 16)
        
        assert bytes(decrypted) == bytes(plaintext)
    
    def test_cbc_custom_roundtrip(self):
        plaintext = bytearray(b'Test message!!!!')
        key = b'mysecretkey12345'
        iv = bytearray(b'initialvector123')
        
        encrypt_func, decrypt_func = get_cipher_functions("CUSTOM")
        
        encrypted = CBC_encrypt(plaintext, key, encrypt_func, iv, "Schneier_Ferguson_padding", 16)
        decrypted = CBC_decrypt(encrypted, key, decrypt_func, iv, "Schneier_Ferguson_padding", 16)
        
        assert bytes(decrypted) == bytes(plaintext)


class TestPaddingModes:
    
    def test_zero_padding(self):
        text = bytearray(b'Hello')
        padded = zero_padding(text.copy(), 16)
        assert len(padded) == 16
        
        unpadded = zero_unpadding(padded.copy(), 16)
        assert bytes(unpadded) == b'Hello'
    
    def test_des_padding(self):
        text = bytearray(b'Test')
        padded = DES_padding(text.copy(), 16)
        assert len(padded) == 16
        assert padded[4] == 0x80
        
        unpadded = DES_unpadding(padded.copy(), 16)
        assert bytes(unpadded) == b'Test'
    
    def test_schneier_ferguson_padding(self):
        text = bytearray(b'Message')
        padded = Schneier_Ferguson_padding(text.copy(), 16)
        assert len(padded) == 16
        assert padded[-1] == 9
        
        unpadded = Schneier_Ferguson_unpadding(padded.copy(), 16)
        assert bytes(unpadded) == b'Message'


class TestLargeData:
    
    def test_large_file_aes_cbc(self):
        plaintext = bytearray(os.urandom(1024 * 100))
        key = b'0123456789ABCDEF'
        iv = bytearray(b'FEDCBA9876543210')
        
        encrypt_func, decrypt_func = get_cipher_functions("AES")
        
        encrypted = CBC_encrypt(plaintext, key, encrypt_func, iv, "Schneier_Ferguson_padding", 16)
        decrypted = CBC_decrypt(encrypted, key, decrypt_func, iv, "Schneier_Ferguson_padding", 16)
        
        assert bytes(decrypted) == bytes(plaintext)


class TestConfigValidation:
    
    def test_missing_required_field(self):
        config = {
            "mode": "encrypt",
            "method": "ECB"
        }
        
        with pytest.raises(ValueError, match="Missing required field"):
            validate_config(config)
    
    def test_invalid_mode(self):
        config = {
            "input_file": "test.txt",
            "output_file": "out.bin",
            "mode": "invalid_mode",
            "method": "ECB",
            "key": "testkey",
            "encryption_function": "AES"
        }
        
        with pytest.raises(ValueError, match="Invalid mode"):
            validate_config(config)
    
    def test_invalid_block_size(self):
        config = {
            "block_size": 129,
            "input_file": "test.txt",
            "output_file": "out.bin",
            "mode": "encrypt",
            "method": "ECB",
            "key": "0123456789ABCDEF",
            "encryption_function": "AES",
            "padding_mode": "zero-padding"
        }
        
        with pytest.raises(ValueError, match="block_size must be divisible by 8"):
            validate_config(config)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])