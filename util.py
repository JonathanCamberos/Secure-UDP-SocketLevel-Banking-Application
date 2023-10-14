from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_hmac(message, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    return h.finalize()

def encrypt_message(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(message) + encryptor.finalize()

def decrypt_message(encrypted_message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_message) + decryptor.finalize()


def generate_shared_secret_key(shared_key_recipe):
    shared_key = HKDF(
         algorithm=hashes.SHA256(),
         length=32,
         salt=None,
         info=b'handshake data',
     ).derive(shared_key_recipe)
    return shared_key


def generate_shared_iv(shared_key_recipe):
    iv = HKDF(
         algorithm=hashes.SHA256(),
         length=16,
         salt=None,
         info=b'initialization_vector_string',
     ).derive(shared_key_recipe)
    return iv


def prepare_message(message, shared_key, iv):

    # Encrypt the message
    encrypted_message = encrypt_message(message, shared_key, iv)

    # Generate HMAC for the encrypted message
    hmac_value = generate_hmac(encrypted_message, shared_key)
    
    # Package Message Together
    packaged_message = b"".join([encrypted_message, hmac_value])


    print(f"Message len: {len(message)}")
    print(f"Message: {message}" )
    
    print(f"Encrypted Message len: {len(encrypted_message)}")
    print(f"Encrypted Message: {encrypted_message}")

    print(f"HMAC len: {len(hmac_value)}")
    print(f"HMAC: {hmac_value}")

    print(f"Packaged Message len: {len(packaged_message)}")
    print(f"Packaged Message: {packaged_message}")

    return packaged_message