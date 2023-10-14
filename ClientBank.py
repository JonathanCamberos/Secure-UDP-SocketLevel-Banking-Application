import socket
import sys
import argparse
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from Peer import Peer
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key
from cryptography.hazmat.primitives import hashes

from util import generate_hmac
from util import encrypt_message
from util import decrypt_message
from util import generate_shared_secret_key
from util import generate_shared_iv
from util import package_message

client_state_list = []


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
    
    shared_key_recipe = client_private_key.exchange(server_public_key)
    # Perform key derivation.


    shared_key = generate_shared_secret_key(shared_key_recipe)

    print(f"Shared Key: {shared_key}")

    iv = generate_shared_iv(shared_key_recipe)

    print(f"IV: {iv}")
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    # @@@@@@@@@@@@@@@@@@@@@@@@@


    pstrlen = b"\x13"
    pstr = b"Bank protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # peer_id = peer_id.encode("utf-8")

    handshake_message = b"".join([pstrlen, pstr, reserved])

    packaged_message = package_message(handshake_message, shared_key, iv)

    # fullhand_length = len(packaged_message)
    print(f"fullhandshake message: {packaged_message}")
    server_socket.send(len(packaged_message).to_bytes(2, "big") + packaged_message)



    return True




def initialize_client_state_list(client_private_key, client_public_key):
    global p, socket_error

    # print("Inside initliaze client state")

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
#       - Option for viewing Bank information, Adding functions, Taking out Funds, sending Funds to Friend

if __name__ == '__main__':

    # 0.0 - Generating Parameters for Diffie–Hellman exchange via
    #        private/public key strategy


    # Generate some parameters. These can be reused.
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2

    #print("Generating Parameters *******************************************************")
    
    params_numbers = dh.DHParameterNumbers(p,g)
    parameters = params_numbers.parameters(default_backend())

    # Generate a private key for use in the exchange.
    client_private_key = parameters.generate_private_key()
    client_public_key    = client_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    print(f"Client Private Key: {client_private_key}")
    #print(f"Length of Client Public Key: --------------> {len(client_public_key)}")
    # print(f"Client Public Key: {client_public_key}")

    #print("Success Parameters ********")
          
    # 0.1 - Argument validation (ignore)
    if len(sys.argv) < 1:
        print("Usage: python3 client.py [--ip_port IP_PORT] ")
        exit(1)
    else:

        parser = argparse.ArgumentParser()
        parser.add_argument('--ip_port',type=int,required=False,help='The port that the BitTorrent clienct connects to')

        #print("Correct number of arguments")
        args = parser.parse_args()

        if args.ip_port is not None:
            print(f'Running Client with arguments: {args.ip_port}')
        else:
            print("Running Client with default port '7500' ")

    
    # 1.1 - Client Information
    client_ip = '0.0.0.0'  # Use '0.0.0.0' to listen on all available interfaces
    default_port = 7500

    # 1.2 - Creating Server Socket 
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    #1.3 Binding to Server Socket Object
    if args.ip_port is not None:
        client_socket.bind((client_ip, args.ip_port))
    else:
        client_socket.bind((client_ip, default_port))
    
    #1.4 - No need for listening because we are not a server


    #1.5 - Optional Sanity Test Printing
    print("CLIENT 1111111111111111111111111")
    hostname=socket.gethostname()
    IPAddr=socket.gethostbyname(hostname)
    print("My Computer Name is:"+hostname)
    print("My Computer IP Address is:"+IPAddr)


    # 2.0 - Adding Bank Server to peer list (connection list)
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


    # 2.1 - Begin Handshake with Server
    #           - Diffie-Hellman Exchange
    #           - Shared_Secret Exchange
    #           - Encrypted Handshake Message
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
    


