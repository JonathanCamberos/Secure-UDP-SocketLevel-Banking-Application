import socket
import sys
import argparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from Peer import Peer
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key

from util import generate_shared_secret_key
from util import generate_shared_iv
from util import package_message
from util import send_package
from util import send_public_key
from util import recieve_public_key

from ClientMessages import prepare_HandShake_Message

from ClientMessages import send_login_request
from ClientMessages import recv_login_response

from ClientMessages import send_modify_savings_request
from ClientMessages import recv_modify_savings_response

from ClientMessages import send_view_savings_request
from ClientMessages import recv_view_savings_response

from ClientMessages import send_new_user_request
from ClientMessages import recv_new_user_response
import ClientMessages

# p = prime modulus, g = generator. Both are used for the DH-algorithm and known by both parties beforehand
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
server_peer = ''
shared_key = ''
iv = ''


def send_recv_handshake(server_socket: socket, client_private_key, client_public_key):
    """
    Sends and receives banking handshake needed to initiate a connection from the clien
    with the server.
    """
    global shared_key, iv
    # Recv Server Pub key
    server_public_key = recieve_public_key(server_socket)
    # Load the received public key in DER (Distinguished Encoding Rules) format
    # parses the binary data representing the public key and prepares it for cryptographic operations
    server_public_key = load_der_public_key(server_public_key, default_backend())

    # Sending Client Public Key to Server
    send_public_key(server_socket, client_public_key)

    # Perform key derivation.
    shared_key_recipe = client_private_key.exchange(server_public_key)
    
    shared_key = generate_shared_secret_key(shared_key_recipe)
    iv = generate_shared_iv(shared_key_recipe)

    # print(f"\nShared Key: {shared_key}")
    # print(f"IV: {iv}\n")
    
    handshake_message = prepare_HandShake_Message()
    # encrypt message with shared-key and possibly iv
    packaged_message = package_message(handshake_message, shared_key, iv)

    send_package(server_socket, packaged_message)

    print(f"Handshake Success!\n")

    return True


def initialize_server_peer(client_private_key, client_public_key):
    global server_peer
    try:

        print(f"Connecting to Server: {server_peer.peer_ip_addr}:{server_peer.peer_port}\n")
        server_socket = socket.create_connection((server_peer.peer_ip_addr, server_peer.peer_port), timeout=1)
        server_socket.settimeout(None)
        
        print(f"Connection Success! Attempting Handshake")
        
        if send_recv_handshake(server_socket, client_private_key, client_public_key):

            server_peer.set_sock(server_socket)
            rlist.append(server_socket)
            
    except socket.error as e:
        socket_error = True

# Hello! This is the main code for the Client
# This section of the Banking Application will be in charge of:
#   - Starting communications to the Bank Server
#       - Diffie-Hellman exchange --> Shared_secret
#       - IV Generator            --> For Modes Encryption/Decryption

#   - Providing a Client UI
#       - Option for viewing Bank information, Adding functions, Taking out Funds, sending Funds to Friend

if __name__ == '__main__':

    # 0.0 - Generating Parameters for Diffie–Hellman exchange via private/public key strategy 
    params_numbers = dh.DHParameterNumbers(p,g)
    parameters = params_numbers.parameters(default_backend())

    # Generate a random private key and its DH-public key for use in the exchange.
    client_private_key = parameters.generate_private_key()
    client_public_key  = client_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
          
    # 0.1 - Argument validation (ignore)
    if len(sys.argv) < 1:
        print("Usage: python3 client.py [--ip_port IP_PORT] ")
        exit(1)

    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('--ip_port',type=int,required=False,help='The port that the Banking clienct connects to')

        #print("Correct number of arguments")
        args = parser.parse_args()

        if args.ip_port is not None:
            print(f'Running Client with arguments: {args.ip_port}')
        else:
            print("\nRunning Client with default port '7500' ")

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


    #1.5 - Sanity Test Printing


    # 2.0 - Adding Bank Server as peer (Connection list)
    server_peer = Peer("Unknown", "0.0.0.0", 6969, -1)    

    # Create empty file descriptors lists needed for select call below
    rlist, wlist, xlist = [], [], []
    socket_error = False

    # 2.1 - Begin Handshake with Server
    #           - Diffie-Hellman Exchange
    #           - Shared_Secret Exchange
    #           - Encrypted Handshake Message
    # encrypted
    initialize_server_peer(client_private_key, client_public_key)


    # print(f"Have the following Server Peer: {server_peer}")
    # print(f"On Socket: {server_peer.sock}")

    loop = True
    while loop:
        print("\nWhat would you like to do?")
        print("Enter one of the following options:")
        print("1 Create an account")
        print("2 Login to account")
        user_input = input("3 Exit the application\n\nEnter Here: ")


        if user_input == "1":
            # CREATE NEW ACCOUNT

            input_username = input("\nUsername:\nEnter Here: ")
            input_password = input("\nPassword:\nEnter Here:")
            # encrypted
            send_new_user_request(input_username, input_password, server_peer.sock, shared_key, iv)
            recv_new_user_response(server_peer.sock, shared_key, iv)

        elif user_input == "2":
            # LOG IN
            print(" ********** Logging In ************\n")
            
            input_username = input("\nEnter Username Here: ")
            input_password = input("\nEnter Password Here:")
            # encrypted
            send_login_request(input_username, input_password, server_peer.sock, shared_key, iv)
            res = recv_login_response(server_peer.sock, shared_key, iv)

            if res == True:

                
                print("You have logged in!! Welcome:")
                loop2 = True
                while loop2:
                    print("\nWhat would you like to do?")
                    print("Enter one of the following options:")
                    print("1 - Add/Remove funds from your account!")
                    print("2 - View Funds in your account!")
                    user_input2 = input("3 - Log out of the application\n\nEnter Here: ")
            
                    if user_input2 == "1":
                       # encrypted 
                       send_modify_savings_request(server_peer.sock, shared_key, iv) 
                       recv_modify_savings_response(server_peer.sock, shared_key, iv)
                    
                    elif user_input2 == "2":
                        # encrypted
                        send_view_savings_request(input_username, server_peer.sock, shared_key, iv)
                        recv_view_savings_response(server_peer.sock, shared_key, iv)

                    elif user_input2 == "3":
                        
                        loop2 = False

                    else:
                        print("Please input valid option '1', '2', or '3' ")
            
            else: 
                print("Error on Login")
                print("Username or Password Incorrect")
                    
            
        elif user_input == "3":
            # EXIT CLIENT APP
            # encrypted
            ClientMessages.send_close_request(server_peer.sock, shared_key, iv)
            ClientMessages.recv_close_request(server_peer.sock, shared_key, iv)
            loop = False
            
        else:
            user_input = input("Incorrect Input, try again\n")
        
    print(f"\nClosing the Following Server Peer: {server_peer}")
    print(f"Server Peer Socket: {server_peer.sock}")
    server_peer.sock.close()
    print(f"Socket Closed!")
    
    print("Closing Our Own Socket\n")
    client_socket.close()
    
    print("Come back soon! :)")    


