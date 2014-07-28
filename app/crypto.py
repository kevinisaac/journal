import scrypt
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def generate_hash(data, length=32):
    return SHA256.new(data).digest()

def generate_salt(length=32):
    return Random.get_random_bytes(length)

def generate_key(password, salt, length=32):
    return scrypt.hash(str(password), str(salt), 1 << 14, 8, 1, length)

def AES_encrypt(key, data):
    iv = generate_salt(16)
    length = 16 - (len(data) % 16)
    data += chr(length) * length
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    return iv + encryptor.encrypt(bytes(data))

def AES_decrypt(key, data):
    iv, data = data[:16], data[16:]
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    plaintext = decryptor.decrypt(data)
    return plaintext[:-ord(plaintext[-1])]