import socket
import select
import sys
import argparse
import struct
import time
import pickle


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from Peer import Peer
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


client_state_list = []


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


def send_recv_handshake(server_socket: socket, client_private_key, client_public_key):
    """
    Sends and receives bittorrent handshake needed to initiate a connection
    with a client
    """

    # $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
    print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    # Recv Server Pub key
    length = server_socket.recv(2) # Prepend the length of the message
    server_public_key = server_socket.recv(int.from_bytes(length, "big"))

    server_public_key = load_der_public_key(server_public_key, default_backend())

    print("RECIEVED PUBLIC KEY FORM SERVER $$$$$$$$$$$$$$$$")
    # print(f"Got Server Public Key with Length of : --------------> {len(server_public_key)}")
    # print("Got server public key: " + str(server_public_key))
    # $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


    # ########################################################
    print("########################################################")
    #generating parameters in Main
    
    print(f"Sending to Server")
    server_socket.send(len(client_public_key).to_bytes(2, "big") + client_public_key)
    print(f"Finished sending to client")
    # ########################################################


    # # @@@@@@@@@@@@@@@@@@@@@@@@@@
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    
    shared_key = client_private_key.exchange(server_public_key)
    # Perform key derivation.


    derived_key = HKDF(
         algorithm=hashes.SHA256(),
         length=32,
         salt=None,
         info=b'handshake data',
     ).derive(shared_key)

    print(f"Derived Key: {derived_key}")

    iv = HKDF(
         algorithm=hashes.SHA256(),
         length=16,
         salt=None,
         info=b'initialization_vector_string',
     ).derive(shared_key)

    print(f"IV: {iv}")
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    # @@@@@@@@@@@@@@@@@@@@@@@@@


    pstrlen = b"\x13"
    pstr = b"Bank protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # peer_id = peer_id.encode("utf-8")

    handshake_message = b"".join([pstrlen, pstr, reserved])


    # Encrypt the message
    encrypted_message = encrypt_message(handshake_message, derived_key, iv)

    # Generate HMAC for the encrypted message
    hmac_value = generate_hmac(encrypted_message, derived_key)


    print(f"HandShakeMessage: {handshake_message}" )
    
    print(f"Message 0 Len: {len(handshake_message)}")
    print(f"Message 0: {handshake_message}")

    print(f"Message 1 Len: {len(encrypted_message)}")
    print(f"Message 1: {encrypted_message}")

    print(f"Message 2: {len(hmac_value)}")
    print(f"Message 2: {hmac_value}")

    fullhandshake_message = b"".join([encrypted_message, hmac_value])

    fullhand_length = len(fullhandshake_message)
    print(f"fullhandshake message: {fullhand_length}")
    server_socket.send(len(fullhandshake_message).to_bytes(2, "big") + fullhandshake_message)


    response_handshake = server_socket.recv(22)
    if len(response_handshake) == 0:
        # print("Couldn't complete the handshake")
        return False
 
    print("Bytes recieved from response to our initial handshake --->", len(response_handshake))
    pstrlen, pstr, reserved = struct.unpack("!c13s8s", response_handshake)
    
    pstrlen = int.from_bytes(pstrlen, "big")
    pstr = pstr.decode("utf-8")

    # response_peer_id = response_peer_id.decode("utf-8")
    print(pstrlen)
    print(pstr)
    print(reserved)
    # print(info_hash)
    # TODO: validate response peer id
    # print("Received Peer ID:", response_peer_id)
    # print("My Peer ID:", peer_id)
    return True



def initialize_client_state_list(client_private_key, client_public_key):
    global p, socket_error

    print("Inside initliaze client state")

    for p in peers:


        try:
            print(f"Trying to connect to {p.peer_ip_addr}:{p.peer_port}")
            server_socket = socket.create_connection((p.peer_ip_addr, p.peer_port), timeout=1)
            server_socket.settimeout(None)
            
            print(f"Connection Success!! Attempting Handshake")
            
            # if send_recv_handshake(server_socket, peer_id, tracker):
            if send_recv_handshake(server_socket, client_private_key, client_public_key):
                print(f"! Connected to {p.peer_ip_addr}:{p.peer_port}")
                p.set_sock(server_socket)
                client_state_list.append(p)
                rlist.append(server_socket)
        except socket.error as e:
            # print("could not connect: ", e)
            socket_error = True



# Hello! This is the main code for the Client
# This section of the Banking Application will be in charge of:
#   - Starting communications to the Bank Server
#       - Diffie-Hellman exchange --> Shared_secret
#       - IV Generator            --> For Modes Encryption/Decryption

#   - Providing a Client UI
#       - Request CRUD (Create, Read, Update, Delete) to Backend Database
#       - 

#   - Verifying with Certificate Server (TO-DO)
#       - 
if __name__ == '__main__':

    # Generate some parameters. These can be reused.
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2

    print("Generating Parameters *******************************************************")

    params_numbers = dh.DHParameterNumbers(p,g)
    parameters = params_numbers.parameters(default_backend())

    # Generate a private key for use in the exchange.
    client_private_key = parameters.generate_private_key()
    client_public_key    = client_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    print(f"Client Private Key: {client_private_key}")
    print(f"Length of Client Public Key: --------------> {len(client_public_key)}")
    # print(f"Client Public Key: {client_public_key}")
    print("testing generate 3333")

    print("Success Parameters ********")
          

    if len(sys.argv) < 1:
        print("Usage: python3 client.py [--ip_port IP_PORT] ")
        exit(1)
    else:

        parser = argparse.ArgumentParser()
        parser.add_argument('--ip_port',type=int,required=False,help='The port that the BitTorrent clienct connects to')

        print("Correct number of arguments")

        args = parser.parse_args()


        print(f'Running BitTorrent client with arguments: {args.ip_port}')

    #0.0 Create a Socket and Bind to It
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


    if args.ip_port is not None:
        client_socket.bind(("0.0.0.0", args.ip_port))
    else:
        client_socket.bind(("0.0.0.0", 7500))
    
    print("CLIENT 1111111111111111111111111")
    hostname=socket.gethostname()
    IPAddr=socket.gethostbyname(hostname)
    print("My Computer Name is:"+hostname)
    print("My Computer IP Address is:"+IPAddr)


    ########printing stuff
    print("Testing info --------------")

    ### we will now attempt to connect to test client_2 on port 6969
    print("Connecting to port: 6969")

    peers = []
    peers.append(Peer("Unknown", "0.0.0.0", 6969, -1))

    if len(peers) == 0:
        print("No peers found! Exiting...")
        exit(1)

    print("Got the following peers:")
    for p in peers:
        print(p)


    # Create empty file descriptors lists needed for select call below
    rlist, wlist, xlist = [], [], []
    socket_error = False

    #we have our list of peers, albiet, a single peer
    #now we must inititalize our client --> State list
    initialize_client_state_list(client_private_key, client_public_key)

    print("Have the following Client State List:")
    for c in client_state_list:
        print(c)
        print(f"Socket {c.sock}")

    
    

    print("Closing the Following Client State List:")
    for c in client_state_list:
        print(c)
        print(f"Socket {c.sock}")
        c.sock.close()
    
    print("Closing Our Own Socket")
    client_socket.close()
    


