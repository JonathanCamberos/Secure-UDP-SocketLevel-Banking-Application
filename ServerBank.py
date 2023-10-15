import socket
import select
import sys
import argparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from datetime import datetime
from Peer import Peer
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key

from util import generate_shared_secret_key
from util import generate_shared_iv
from util import unpackage_message
from util import recieve_package

client_state_list = []


def recv_handshake_from_initiator(server_socket: socket, server_private_key, server_public_key):
    """
    Sends and receives bittorrent handshake needed to initiate a connection
    with a client
    """
    #accept
    peer_sock, peer_address = server_socket.accept()
    peer_ipaddr, peer_socket = peer_address
    
    print(f"Connection Success! Attempting Handshake from: {peer_address}")
    
    #create new peer (we do not know there peer 'id')
    new_peer = Peer("Unknown", peer_ipaddr, peer_socket, peer_sock)

    # Sending Server Public Key to Client
    peer_sock.send(len(server_public_key).to_bytes(2, "big") + server_public_key)

    # Recv Client Pub key
    length = peer_sock.recv(2) # Prepend the length of the message
    client_public_key = peer_sock.recv(int.from_bytes(length, "big"))
   
    client_public_key = load_der_public_key(client_public_key, default_backend())

    # Create Key Recipe
    shared_key_recipe = server_private_key.exchange(client_public_key)

    # Generate Shared_key and IV with Client for encrypted communication
    shared_key = generate_shared_secret_key(shared_key_recipe)
    iv = generate_shared_iv(shared_key_recipe)

    print(f"Shared Key: {shared_key}")
    print(f"IV: {iv}\n")

    # Recv message from client
    recv_encrypted_handshake_message = recieve_package(peer_sock)

    # Unpackage/Decrypt message from client
    unpackaged_message = unpackage_message(recv_encrypted_handshake_message, shared_key, iv)
    
    print("Handshake Success!\n")

    return True


# Hello! This is the main code for the Bank Server
# This section of the Banking Application will be in charge of:
#   - Starting communications from clients/users
#       - Diffie-Hellman exchange --> Shared_secret
#       - IV Generator            --> For Modes Encryption/Decryption

#   - Taking client/users
#       - Request CRUD (Create, Read, Update, Delete) to Backend Database
#       - 

#   - Verifying with Certificate Server (TO-DO)
#       - 
if __name__ == '__main__':

    # 0.0 - Generating Parameters for Diffie–Hellman exchange via
    #        private/public key strategy

    #print("Generating Parameters *******************************************************")
    
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2
    params_numbers = dh.DHParameterNumbers(p,g)
    parameters = params_numbers.parameters(default_backend())

    # Generate a private key for use in the exchange.
    server_private_key = parameters.generate_private_key()
    server_public_key    = server_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    # 0.1 - Argument validation (ignore)
    if len(sys.argv) < 1:
        print("Usage: python3 ServerBank.py [--ip_port IP_PORT] ")
        exit(1)
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('--ip_port',type=int,required=False,help='The port that the BitTorrent clienct connects to')

        args = parser.parse_args()

        #print("Correct number of arguments")
        if args.ip_port is not None:
            print(f'Running Banking Server with arguments: {args.ip_port}')
        else:
            print("\nRunning Banking Server with default port '6969'")


    # 1.1 - Server Information
    server_ip = '0.0.0.0'  # Use '0.0.0.0' to listen on all available interfaces
    default_port = 6969

    # 1.2 - Creating Server Socket 
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    #1.3 Binding to Server Socket Object
    if args.ip_port is not None:
        server_socket.bind((server_ip, args.ip_port))
    else:
        server_socket.bind((server_ip, default_port))

    #1.4 - Listen on that Server Socket (Port)
    server_socket.listen()

    #print("We are a serverrrrr We only LISTENINGGGGGG USING OUR EARSSSSS ***************************")

    #1.5 - Sanity Test Printing
    if args.ip_port is not None:
        print(f"Server listening on {server_ip}:{args.ip_port}\n")
    else:
        print(f"Server listening on {server_ip}:{default_port}\n")


    #2.0 - Creating empty file descriptors lists needed for select call below
    #      Each file description is in charge of 
    #           - Listening if a client has sent a message
    #           - Prepare to send a message to a client  
    rlist, wlist, xlist = [], [], []
    socket_error = False

    #2.1 - Infinite Loop to Keep Server Constantly listening for Client Information
    while True:
        
        #2.2 -
        rfds = []
        rlist = []

        #2.3 - Check Keep Alive Messages For Each Client (TO-DO)
        # validate_peer_list()

        #2.4 - For Each Client
        #           - Add Client's Read Socket to rlist (Read List)
        for c in client_state_list:
            rlist.append(c.sock)

        #2.5 - Add Servers Read Socket to rlist (for new handshakes from client's)
        rlist.append(server_socket)

        #2.6 - Timer (not sure, figure out later)
        time_before_select = datetime.now()

        #2.7 - Select socket function:
        #           - Select function takes three lists of file descriptors as parameters:
        #                   - Read List:  A list of sockets that the program is interested in for reading.
        #                             If data is available for reading on any of these sockets, select will return,
        #                             indicating that I/O is possible on one or more of them.

        #                   - Write List:   A list of sockets that the program is interested in for writing
        #                             If it's possible to write data to any of these sockets without blocking,
        #                             select will return.     

        #                   - Error List:  A list of sockets that the program is interested in for exceptions 
        #                             (e.g., out-of-band data).  If an exceptional condition occurs on any of these sockets, 
        #                             select will return.
        rfds, wfds, xfds = select.select(rlist, wlist, xlist, 5)

        #2.8 - Check Read File Descriptors 
        if rfds != []:
            for r in rfds:
                if (r.fileno == -1):
                    continue

                if (r == server_socket):

                    recv_handshake_from_initiator(server_socket, server_private_key, server_public_key)
                    continue
        


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

