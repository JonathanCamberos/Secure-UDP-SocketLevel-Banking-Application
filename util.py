import struct

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


def package_message(message, shared_key, iv):

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


def unpackage_message(packaged_message, shared_key, iv):

    HMAC_len = 32
    package_len = len(packaged_message)
    print(f"Encrypted + HMAC len: {package_len}")

    encrypted_len = package_len - HMAC_len

    encrypted_message, hmac = struct.unpack(f"{encrypted_len}s32s", packaged_message)

    message = decrypt_message(encrypted_message, shared_key, iv)
    
    print(f"Message len: {len(message)}")
    print(f"Message: {message}")

    print(f"Encrypted Message len: {len(encrypted_message)}")
    print(f"Encrypted Message: {encrypted_message}")

    print(f"HMAC len: {len(hmac)}")
    print(f"HMAC: {hmac}")

    print(f"Package len: {len(packaged_message)}")
    print(f"Package: {packaged_message}")

    return message


def recieve_package(peer_sock):

    # Prepend the length of the message
    package_len = peer_sock.recv(2) 

    # Message Length
    package_len = int.from_bytes(package_len, "big")
    print(f"Encrypted / HMAC Length: {package_len}")

    # Recv as many bytes as message length
    recv_encrypted_handshake_message = peer_sock.recv(package_len)
    return recv_encrypted_handshake_message

