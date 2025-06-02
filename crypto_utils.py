import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def encrypt_file(input_path: str, password: str, output_path: str):
    salt = os.urandom(16)
    iv = os.urandom(16)
    with open(input_path, "rb") as f:
        plaintext = f.read()
    
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    pad_len = 16 - len(plaintext) % 16
    padded = plaintext + bytes([pad_len] * pad_len)

    ciphertext = encryptor.update(padded) + encryptor.finalize()
    hash_plaintext = sha256_hash(plaintext).encode()

    with open(output_path, "wb") as f:
        f.write(salt)             
        f.write(iv)               
        f.write(hash_plaintext)   
        f.write(ciphertext)

def decrypt_file(input_path: str, password: str, output_path: str):
    with open(input_path, "rb") as f:
        salt = f.read(16)
        iv = f.read(16)
        stored_hash = f.read(64)
        ciphertext = f.read()

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    pad_len = padded_plaintext[-1]
    plaintext = padded_plaintext[:-pad_len]

    with open(output_path, "wb") as f:
        f.write(plaintext)

    computed_hash = sha256_hash(plaintext).encode()
    if computed_hash == stored_hash:
        print("El archivo se descifró correctamente y la integridad fue verificada.")
    else:
        print("El archivo fue descifrado pero la integridad NO se verificó.")
