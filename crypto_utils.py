"""
Módulo de utilidades criptográficas para cifrado y descifrado de archivos.

Este módulo proporciona funciones para cifrar y descifrar archivos utilizando
el algoritmo AES-256 en modo CBC con verificación de integridad SHA-256.

Características de seguridad:
- Cifrado AES-256-CBC (Advanced Encryption Standard de 256 bits)
- Derivación de claves PBKDF2 con 100,000 iteraciones
- Salt aleatorio único para cada cifrado (16 bytes)
- Vector de inicialización (IV) aleatorio único (16 bytes)
- Verificación de integridad con hash SHA-256
- Padding PKCS7 para bloques AES

"""

import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_key(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """
    Deriva una clave criptográfica segura a partir de una contraseña usando PBKDF2.
    
    PBKDF2 (Password-Based Key Derivation Function 2) es un algoritmo estándar 
    para derivar claves criptográficas a partir de contraseñas. Utiliza múltiples
    iteraciones para hacer que los ataques de fuerza bruta sean computacionalmente costosos.
    
    Args:
        password (str): La contraseña del usuario en texto plano
        salt (bytes): Salt aleatorio de 16 bytes para prevenir ataques de rainbow table
        iterations (int, opcional): Número de iteraciones PBKDF2 (por defecto: 100,000)
                                   Más iteraciones = mayor seguridad pero más lento
    
    Returns:
        bytes: Clave derivada de 32 bytes (256 bits) lista para usar con AES-256

    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def sha256_hash(data: bytes) -> str:
    """
    Calcula el hash SHA-256 de los datos proporcionados.
    
    SHA-256 es una función hash criptográfica que produce un hash de 256 bits (32 bytes).
    Se utiliza para verificar la integridad de los datos después del descifrado.
    
    Args:
        data (bytes): Los datos de los cuales calcular el hash
        
    Returns:
        str: El hash SHA-256 en formato hexadecimal (64 caracteres)
        
    """
    return hashlib.sha256(data).hexdigest()

def encrypt_file(input_path: str, password: str, output_path: str):
    """
    Cifra un archivo utilizando AES-256-CBC con verificación de integridad.
    
    Este función implementa un esquema de cifrado seguro que incluye:
    - Generación de salt e IV aleatorios únicos
    - Derivación segura de claves con PBKDF2
    - Cifrado AES-256 en modo CBC
    - Padding PKCS7 para completar bloques
    - Hash SHA-256 para verificación de integridad
    
    Args:
        input_path (str): Ruta del archivo original a cifrar
        password (str): Contraseña para el cifrado
        output_path (str): Ruta donde guardar el archivo cifrado (.enc)
        
    Raises:
        FileNotFoundError: Si el archivo de entrada no existe
        PermissionError: Si no hay permisos para leer/escribir archivos
        IOError: Si hay problemas de entrada/salida
        
    Estructura del archivo cifrado resultante:
        Bytes 0-15:   Salt aleatorio (16 bytes)
        Bytes 16-31:  IV aleatorio (16 bytes) 
        Bytes 32-95:  Hash SHA-256 del archivo original (64 bytes en hex)
        Bytes 96+:    Datos cifrados con padding PKCS7
        
    """
 
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
    """
    Descifra un archivo cifrado con verificación de contraseña e integridad.
    
    Esta función implementa el proceso inverso de encrypt_file con validaciones
    de seguridad robustas para detectar contraseñas incorrectas o archivos corruptos.
    
    Args:
        input_path (str): Ruta del archivo cifrado (.enc)
        password (str): Contraseña utilizada para el cifrado
        output_path (str): Ruta donde guardar el archivo descifrado
        
    Raises:
        ValueError: Si la contraseña es incorrecta, el archivo está corrupto,
                   o falla la verificación de integridad
        FileNotFoundError: Si el archivo cifrado no existe
        PermissionError: Si no hay permisos para leer/escribir archivos
        
    Proceso de descifrado y validación:
        1. Lee la estructura del archivo cifrado (salt, IV, hash, datos)
        2. Deriva la clave usando la contraseña y el salt
        3. Descifra los datos usando AES-256-CBC
        4. Valida el padding PKCS7
        5. Calcula el hash SHA-256 de los datos descifrados
        6. Compara con el hash almacenado para verificar integridad
        7. Solo guarda el archivo si todas las validaciones pasan

    """
    try:
        with open(input_path, "rb") as f:
            salt = f.read(16)
            iv = f.read(16)
            stored_hash = f.read(64)
            ciphertext = f.read()

        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        if len(padded_plaintext) == 0:
            raise ValueError("Contraseña incorrecta: No se pudo descifrar el archivo")

        pad_len = padded_plaintext[-1]
        
        if pad_len > 16 or pad_len == 0:
            raise ValueError("Contraseña incorrecta: Padding inválido")

        for i in range(pad_len):
            if padded_plaintext[-(i+1)] != pad_len:
                raise ValueError("Contraseña incorrecta: Padding corrupto")

        plaintext = padded_plaintext[:-pad_len]

        computed_hash = sha256_hash(plaintext).encode()
        if computed_hash != stored_hash:
            raise ValueError("Contraseña incorrecta: La verificación de integridad falló")

        with open(output_path, "wb") as f:
            f.write(plaintext)

        print("El archivo se descifró correctamente y la integridad fue verificada.")
        
    except Exception as e:
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except:
                pass
        
        if "Contraseña incorrecta" in str(e):
            raise e
        else:
            raise ValueError("Error al descifrar el archivo: Contraseña incorrecta o archivo corrupto")

def manual_derive_key(password: str, length: int) -> bytes:
    """Deriva una clave simple usando SHA-256 repetido (solo para XOR manual)."""
    key = hashlib.sha256(password.encode()).digest()
    while len(key) < length:
        key += hashlib.sha256(key).digest()
    return key[:length]

def manual_encrypt_file(input_path: str, password: str, output_path: str):
    """Cifra un archivo usando XOR simple (NO SEGURO, solo educativo)."""
    with open(input_path, "rb") as f:
        plaintext = f.read()
    key = manual_derive_key(password, len(plaintext))
    ciphertext = bytes([b ^ k for b, k in zip(plaintext, key)])
    hash_plaintext = sha256_hash(plaintext).encode()
    with open(output_path, "wb") as f:
        f.write(hash_plaintext)
        f.write(ciphertext)

def manual_decrypt_file(input_path: str, password: str, output_path: str):
    """Descifra un archivo cifrado con XOR simple y verifica integridad."""
    with open(input_path, "rb") as f:
        stored_hash = f.read(64)
        ciphertext = f.read()
    key = manual_derive_key(password, len(ciphertext))
    plaintext = bytes([c ^ k for c, k in zip(ciphertext, key)])
    computed_hash = sha256_hash(plaintext).encode()
    if computed_hash != stored_hash:
        raise ValueError("Contraseña incorrecta o archivo corrupto")
    with open(output_path, "wb") as f:
        f.write(plaintext)
