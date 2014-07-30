import scrypt
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def xor_keys(key1, key2):
    """Returns key1 ^ key2."""
    assert None not in (key1, key2), 'parameters can not be None'
    assert len(key1) == len(key2), 'keys must be the same size'
    b_key1, b_key2 = bytearray(key1), bytearray(key2)
    return str(bytearray(x ^ y for x , y in zip(b_key1, b_key2)))


def generate_hash(data, length=32):
    """Generates SHA256 hash."""
    assert data is not None
    assert length and length > 0
    return SHA256.new(data).digest()


def generate_salt(length=32):
    """Generates random salt."""
    assert length and length >= 0
    return Random.get_random_bytes(length)


def generate_key(password, salt, length=32):
    """Generates key from password using scrypt."""
    assert None not in (password, salt, length), 'parameters can not be None'
    return scrypt.hash(str(password), str(salt), 1 << 14, 8, 1, length)


def AES_encrypt(key, data):
    """Encrypts data with key and random IV using AES."""
    assert None not in (key, data), 'parameters can not be None'
    assert len(key) in AES.key_size, 'key size must be 16, 24, or 32 bytes'
    nonce = generate_salt(16)
    length = 16 - (len(data) % 16)
    data += chr(length) * length
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce, mac_len=16)
    ciphertext, tag = cipher.encrypt_and_digest(bytes(data))
    return ''.join([nonce, tag, ciphertext])


def AES_decrypt(key, data):
    """Decrypts iv + data with key using AES."""
    assert None not in (key, data), 'parameters can not be None'
    assert len(key) in AES.key_size, 'key size must be 16, 24, or 32 bytes'
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext[:-ord(plaintext[-1])]


