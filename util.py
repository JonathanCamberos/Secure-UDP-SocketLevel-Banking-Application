import struct

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_hmac(message, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    return h.finalize()

def validate_hmac(message, key, package_hmac):
    test_hmac = generate_hmac(message, key)

    if package_hmac == test_hmac:
        return True
    else:
        return False

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

    return packaged_message


def unpackage_message(package, shared_key, iv):

    print(f"Package: {package}\n")

    HMAC_len = 32
    package_len = len(package)
    encrypted_len = package_len - HMAC_len
    encrypted_message, hmac = struct.unpack(f"{encrypted_len}s32s", package)
    decrypted_message = decrypt_message(encrypted_message, shared_key, iv)
    
    if validate_hmac(encrypted_message, shared_key, hmac):
        print(f"Valid Package, acepted!")
    else:
        print(f"Invalid Package, rejected!")
    return decrypted_message


def send_package(peer_sock, packaged_message):
    expected_package_length = len(packaged_message).to_bytes(2, "big")

    result = peer_sock.sendall(expected_package_length + packaged_message)
    
    if result == None:
        print(f"Sent: {len(packaged_message)}")
        print("Entire Package Sent: Success!")
        print(f"Package: {packaged_message}\n")
    else:
        print("\nPartial Package Sent: Error!\n")
    
    return


def recieve_package(peer_sock):

    # Prepend the length of the message
    package_len = peer_sock.recv(2) 

    # Message Length
    package_len = int.from_bytes(package_len, "big")
    
    # Recv as many bytes as message length
    recv_encrypted_handshake_message = peer_sock.recv(package_len)

    if package_len == len(recv_encrypted_handshake_message):
        print(f"Expected Len: {package_len}, Recv: {len(recv_encrypted_handshake_message)}")
        print("Entire Package Recieved: Success!")
    else:
        print("Partial Package Recieved: Error!")

    return recv_encrypted_handshake_message



# remember this is the diffie-helman step
# so neither will be encrypted
def send_public_key(peer_sock, public_key):


    expected_public_key_len = len(public_key).to_bytes(2, "big")

    result = peer_sock.sendall(expected_public_key_len + public_key)
    
    if result == None:
        print(f"Sent Public Key Len: {len(public_key)}")
        print("Entire Public Key Sent: Success!")
    else:
        print("\nPartial Public Key Sent: Error!\n")
    
    return

# remember this is the diffie-helman step
# so neither will be encrypted
def recieve_public_key(peer_sock):

    # Prepend the length of the message
    public_key_len = peer_sock.recv(2) 

    # Message Length
    public_key_len = int.from_bytes(public_key_len, "big")
    
    # Recv as many bytes as message length
    recv_public_key = peer_sock.recv(public_key_len)

    if public_key_len == len(recv_public_key):
        print(f"Expected Recv Public Key Len: {public_key_len}, Recv: {len(recv_public_key)}")
        print("Entire Public Key Recieved: Success!")
    else:
        print("Partial Public KEy Recieved: Error!")

    return recv_public_key







def print_package_encrypted_testing(packaged_message, shared_key, iv):
    
    print(f"Sending Packaged Message: \n{package_message}\n")

    HMAC_len = 32
    package_len = len(packaged_message)

    encrypted_len = package_len - HMAC_len

    encrypted_message, hmac = struct.unpack(f"{encrypted_len}s32s", packaged_message)

    decrypted_message = decrypt_message(encrypted_message, shared_key, iv)
    
    print(f"Message len: {len(decrypted_message)}")
    print(f"Message: {decrypted_message}")

    print(f"Encrypted Message len: {len(encrypted_message)}")
    print(f"Encrypted Message: {encrypted_message}")

    print(f"HMAC len: {len(hmac)}")
    print(f"HMAC: {hmac}")

    print(f"Package len: {len(packaged_message)}")
    print(f"Package: {packaged_message}")

    test_hmac = generate_hmac(encrypt_message, shared_key)

    print(f"\nPackage Hmac: {hmac}")
    print(f"Test Hmac: {test_hmac}")
    return

def print_unpackage_encrypted_packaged_testing(packaged_message, shared_key, iv ):

    print(f"Recv/Unpackaging Package:\n {package_message}\n")

    HMAC_len = 32
    package_len = len(packaged_message)

    encrypted_len = package_len - HMAC_len

    encrypted_message, hmac = struct.unpack(f"{encrypted_len}s32s", packaged_message)

    decrypted_message = decrypt_message(encrypted_message, shared_key, iv)
    
    print(f"Message len: {len(decrypted_message)}")
    print(f"Message: {decrypted_message}")

    print(f"Encrypted Message len: {len(encrypted_message)}")
    print(f"Encrypted Message: {encrypted_message}")

    print(f"HMAC len: {len(hmac)}")
    print(f"HMAC: {hmac}")

    print(f"Package len: {len(packaged_message)}")
    print(f"Package: {packaged_message}")

    test_hmac = generate_hmac(encrypt_message, shared_key)

    print(f"\nPackage Hmac: {hmac}")
    print(f"Test Hmac: {test_hmac}")

    return 