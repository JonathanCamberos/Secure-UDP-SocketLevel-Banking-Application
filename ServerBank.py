import socket
import select
import sys
import argparse
import time
import struct
import pickle

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from datetime import datetime
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


def recv_handshake_from_initiator(server_socket: socket, server_private_key, server_public_key):
    """
    Sends and receives bittorrent handshake needed to initiate a connection
    with a client
    """
    #accept
    peer_sock, peer_address = server_socket.accept()
    peer_ipaddr, peer_socket = peer_address
    print(f"Connection from {peer_address}")
    
    #create new peer (we do not know there peer 'id')
    new_peer = Peer("Unknown", peer_ipaddr, peer_socket, peer_sock)


    # ########################################################
    #generating parameters in Main
    print("########################################################")
    print(f"Length of Server Public Key: {len(server_public_key)}")
    
    print(f"Sending to client")
    peer_sock.send(len(server_public_key).to_bytes(2, "big") + server_public_key)
    print(f"Finished sending to client")
    # ########################################################

    print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
    # Recv Server Pub key
    #$ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $
    length = peer_sock.recv(2) # Prepend the length of the message
    peer_public_key = peer_sock.recv(int.from_bytes(length, "big"))
    print(f"Got Peer Public Key with Length of : --------------> {len(peer_public_key)}")
    # print("Got peer public key: " + str(peer_public_key))
    peer_public_key = load_der_public_key(peer_public_key, default_backend())
    # $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $ $



    # # @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    
    shared_key = server_private_key.exchange(peer_public_key)
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
    # @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @ @


    # % % % % % % % % % % % % % % % % % % % % % % % % % % % %
    length = peer_sock.recv(2) # Prepend the length of the message
    length_int = int.from_bytes(length, "big")
    print(f"Encrypted / HMAC Length: {length_int}")
    recv_encrypted_handshake_message = peer_sock.recv(int.from_bytes(length, "big"))
    acc_length_int = len(recv_encrypted_handshake_message)
    print(f"Encrypted / HMAC Actual Length: {acc_length_int}")

    x = acc_length_int - 32
    message_1, message_2 = struct.unpack(f"{x}s32s", recv_encrypted_handshake_message)

    message_0 = decrypt_message(message_1, derived_key, iv)
    
    print(f"Message 0 Len: {len(message_0)}")
    print(f"Message 0: {message_0}")

    print(f"Message 1 Len: {len(message_1)}")
    print(f"Message 1: {message_1}")

    print(f"Message 2: {len(message_2)}")
    print(f"Message 2: {message_2}")
    
    # % % % % % % % % % % % % % % % % % % % % % % % % % % % %





    # response_handshake = peer_sock.recv(22)
    # if len(response_handshake) == 0:
    #     # print("Couldn't complete the handshake")
    #     return False
    # print("Bytes recieved from response to our initial handshake --->", len(response_handshake))
    # pstrlen, pstr, reserved = struct.unpack("!c13s8s", response_handshake)
    
    # pstrlen = int.from_bytes(pstrlen, "big")
    # pstr = pstr.decode("utf-8")

    # # response_peer_id = response_peer_id.decode("utf-8")
    # print(pstrlen)
    # print(pstr)
    # print(reserved)
    # # print(info_hash)
    # # TODO: validate response peer id
    # # print("Received Peer ID:", response_peer_id)
    # # print("My Peer ID:", peer_id)

    # pstrlen = b"\x13"
    # pstr = b"Bank protocol"
    # reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # # peer_id = peer_id.encode("utf-8")

    # #send_test edit
    # client_state_list.append(new_peer)

    # handshake_message = b"".join([pstrlen, pstr, reserved])
    # peer_sock.sendall(handshake_message)

    return True


if __name__ == '__main__':

    # Generate some parameters. These can be reused.
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2

    print("Generating Parameters *******************************************************")

    params_numbers = dh.DHParameterNumbers(p,g)
    parameters = params_numbers.parameters(default_backend())

    # Generate a private key for use in the exchange.
    server_private_key = parameters.generate_private_key()
    server_public_key    = server_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    print(f"Server Private Key: {server_private_key}")
    print(f"Length of Server Public Key: --------------> {len(server_public_key)}")
    # print(f"Server Public Key: {server_public_key}")
    print("testing generate 3333")

    print("Success Parameters ******************************************************* !")

    if len(sys.argv) < 1:
        print("Usage: python3 ServerBank.py [--ip_port IP_PORT] ")
        exit(1)
    else:

        parser = argparse.ArgumentParser()
        parser.add_argument('--ip_port',type=int,required=False,help='The port that the BitTorrent clienct connects to')

        print("Correct number of arguments")

        args = parser.parse_args()


        print(f'Running BitTorrent client with arguments: {args.ip_port}')

    server_ip = '0.0.0.0'  # Use '0.0.0.0' to listen on all available interfaces
    default_port = 6969


    #0.0 Create a Socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    #0.1 Binding to Socket Object
    if args.ip_port is not None:
        server_socket.bind((server_ip, args.ip_port))
    else:
        server_socket.bind((server_ip, default_port))

    #0.2 Listen on that Port (Socket)
    server_socket.listen()

    print("We are a serverrrrr We only LISTENINGGGGGG USING OUR EARSSSSS ***************************")

    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    print("My Computer Name is:"+hostname)
    print("My Computer IP Address is:"+IPAddr)
    if args.ip_port is not None:
        print(f"Server listening on {server_ip}:{args.ip_port}")
    else:
        print(f"Server listening on {server_ip}:{default_port}")

    # ########################################################
    # print("testing generate ######################################################################")

    #  # Generate some parameters. These can be reused.
    # # parameters = dh.generate_parameters(generator=2, key_size=2048)

    # p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    # g = 2

    # params_numbers = dh.DHParameterNumbers(p,g)
    # parameters = params_numbers.parameters(default_backend())

    # print(f"Parameters: {parameters}")
    # print("testing generate 2222")

    # # Generate a private key for use in the exchange.
    # server_private_key = parameters.generate_private_key()
    # server_public_key    = server_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    # print(f"Server Private Key: {server_private_key}")
    # print(f"Length of Server Public Key: {len(server_public_key)}")
    # print(f"Server Public Key: {server_public_key}")
    # print("testing generate 3333")

    # # In a real handshake the peer is a remote client. For this
    # # example we'll generate another local private key though. Note that in
    # # a DH handshake both peers must agree on a common set of parameters.
    # peer_private_key = parameters.generate_private_key()
    # peer_public_key = peer_private_key.public_key()
    
    # print(f"Public Key: {peer_public_key}")
    # print(f"testing generate 4444")
    # shared_key = server_private_key.exchange(peer_private_key.public_key())
    # # Perform key derivation.


    # derived_key = HKDF(
    #      algorithm=hashes.SHA256(),
    #      length=32,
    #      salt=None,
    #      info=b'handshake data',
    #  ).derive(shared_key)
    

    # # And now we can demonstrate that the handshake performed in the
    # # opposite direction gives the same final value
    # same_shared_key = peer_private_key.exchange(
    #      server_private_key.public_key()
    #  )
    # same_derived_key = HKDF(
    #      algorithm=hashes.SHA256(),
    #      length=32,
    #      salt=None,
    #      info=b'handshake data',
    #  ).derive(same_shared_key)
    
    
    # if derived_key == same_derived_key:
    #     print("Success!!")
    # else:
    #     print("Whattt")

    # print("testing generate ######################################################################")
    # ########################################################
    

    # Create empty file descriptors lists needed for select call below
    rlist, wlist, xlist = [], [], []
    socket_error = False

    while True:

        rfds = []
        rlist = []
        # validate_peer_list()
        for c in client_state_list:
            rlist.append(c.sock)
        rlist.append(server_socket)
        time_before_select = datetime.now()
        rfds, wfds, xfds = select.select(rlist, wlist, xlist, 5)

        if rfds != []:
            for r in rfds:
                if (r.fileno == -1):
                    continue

                if (r == server_socket):
                    print("recv handshake")

                    recv_handshake_from_initiator(server_socket, server_private_key, server_public_key)
                    continue


    # #Now, as the server, we must accept incoming attempts to connect
    # while True:
    #     # Wait for a client to establish a connection
    #     print(f"Listening.")
    #     client_socket, client_address = server_socket.accept()
    #     print(f"Connection from {client_address}")

    #     bank_recv_send_handshake(client_socket)















    # # Get the current time
    # start_time = time.time()
    # duration = 2
    # while True:
    #     # Get the current time in the loop
    #     current_time = time.time()

    #     # Calculate the elapsed time
    #     elapsed_time = current_time - start_time

    #     # Check if the elapsed time has reached the desired duration
    #     if elapsed_time >= duration:
    #         #alive timer, just prints out for sanity :) 
    #         duration = 2
    #         start_time = time.time()
    #         print("server is alive**************************")


    #     # Print the remaining time (optional)
    #     # remaining_time = duration - elapsed_time
    #     # print(f"Time remaining: {round(remaining_time, 2)} seconds")

    #     # Add a small delay to avoid high CPU usage
    #     # time.sleep(0.1)

    # print("Timer complete!")

