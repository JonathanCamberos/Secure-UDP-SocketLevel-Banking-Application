import socket
import select
import sys
import argparse
import pymongo 
import secrets
import uuid

from pymongo.errors import DuplicateKeyError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from Headers import KEEP_ALIVE
from Headers import DISCONNECT_CLIENT
from Headers import LOGIN_REQUEST_HEADER 

from Headers import MODIFY_SAVINGS_HEADER
from Headers import VIEW_SAVINGS_REQUEST_HEADER

from Headers import NEW_USER_REQUEST_HEADER

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from datetime import datetime
from Peer import Peer
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key

from util import generate_shared_secret_key
from util import generate_shared_iv
from util import unpackage_message
from util import recieve_package
from util import send_public_key
from util import recieve_public_key

from util import print_package_encrypted_testing
from util import print_unpackage_encrypted_packaged_testing
from util import convert_to_integer

from ServerMessages import send_login_success_response
from ServerMessages import send_login_error_response

from ServerMessages import send_modify_savings_success_response
from ServerMessages import send_view_savings_success_response

from ServerMessages import send_user_created_response
from ServerMessages import send_user_mongo_error_response
from ServerMessages import send_user_name_taken_error_response

from BothMessages import get_packet_data

client_state_list = []

conn_str = "mongodb+srv://jcambero:jcambero@cluster0.nkjnjyb.mongodb.net/"
bank_database = ''
user_information_table = ''


###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################

# Database Section
def generate_unique_id():
    return str(uuid.uuid4())


def add_user_to_database(username, password):

    salt = secrets.token_bytes(16)  # Generate a random 16-byte salt
    print(f"Random Salt: {salt}")
    
    hashed_password = hash_password(password, salt)

    print(f"Plaintext Password: {password}")
    print(f"Hashed Password: {hashed_password}")

    starting_savings = 0

    # Generate Unique Id
    unique_id = generate_unique_id()

    # Create a user document
    new_user = {
        '_id': unique_id,
        'username': username,
        'plaintext password': password,
        'hashed password': hashed_password,
        'salt': salt,
        'savings': starting_savings
    }

    # Try - Add user to MongoDB
    try:
        user_information_table.insert_one(new_user)
    except DuplicateKeyError as e:
        print(f"Error: {e}")
        return 2

    return 1


def get_savings(username):
    user_data = user_information_table.find_one({'username': username})
    if user_data:

        raw_user_savings = user_data.get('savings', '')
        int_user_savings = convert_to_integer(raw_user_savings)
        print(f"Grabbed Raw Savings: {raw_user_savings}")
        print(f"translated to Int Savings: {int_user_savings}")
        
        return int_user_savings
    return None

def verify_transaction(username, type, amount):

    if type == 1:
        return True
    elif type == 2:
        current_savings = get_savings(username)
        res = current_savings - amount
        if res >= 0:
            return True
        else:
            False
    else:
        print("bad transaction type")
        return


# Function to update user's savings based on the username
def update_savings(username, new_savings):
    result = user_information_table.update_one({'username': username}, {'$set': {'savings': new_savings}})
    if result.modified_count > 0:
        print(f"Savings for {username} updated to {new_savings}")
    else:
        print(f"User {username} not found.")


def proceed_transation(username, type, transaction_amount):

    current_savings = ''
    new_savings = ''

    if type == 1:
        current_savings = get_savings(username)
        new_savings = current_savings + transaction_amount
        update_savings(username, new_savings)

        return True
    
    elif type == 2:
        current_savings = get_savings(username)
        new_savings = current_savings - transaction_amount
        update_savings(username, new_savings)

        return True
    else:
        print("bad transaction type")
        return


def verified_modification_user(mode, transaction_amount, username, password):
    
    print(f"Welcome: {username}")

    if mode == "1":
       
        # checks if enough funds for transaction
        if verify_transaction(username, 1, transaction_amount):

            print(f"Adding {transaction_amount} is possible")
            print(f"Proceeding!")
            if proceed_transation(username, 1, transaction_amount) == True:
                print("Success in Adding!")
                return True
        
        else:
            print(f"Adding {transaction_amount} is not possible")
            print(f"Have a good day!\n")
    
    elif mode == "2":   
             

        if verify_transaction(username, 2, transaction_amount):
            print(f"Subtracting {transaction_amount} is possible")
            print(f"Proceeding!")
            if proceed_transation(username, 2, transaction_amount) == True:
                print("Success In Adding!")
                return True
        

        else:
            print(f"Subtracting {transaction_amount} is not possible")
            print(f"Have a good day!\n")

    else:
        print("Invalid modifcation mode")
        return False


    return False





# def pull_user_data(username):
def pull_user_data(username):

    # input_username = input("\nUsername:\nEnter Here: ")
    
    # Query the database for all users with the given username
    user_documents = user_information_table.find({'username': username}, {'_id': 0})

    for user_document in user_documents:
            print("User Information:", user_document)
    return 



# def hash_password(password, salt):
def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,  # Choose an appropriate number of iterations
        length=32  # Length of the derived key
    )
    hashed_password = kdf.derive(password.encode('utf-8'))
    return hashed_password

def get_hashed_password(username):
    user_data = user_information_table.find_one({'username': username})
    if user_data:
        return user_data.get('hashed password', '')
    return None

def get_salt(username):
    user_data = user_information_table.find_one({'username': username})
    if user_data:
        return user_data.get('salt', '')
    return None

def verify_password(username, entered_password, salt):
    # Hash the entered password with the stored salt
    stored_hashed_password = get_hashed_password(username)
    entered_password_hashed = hash_password(entered_password, salt)


    print(f"Stored Hashed Password: {stored_hashed_password}\n")
    print(f"Input password: {entered_password}")
    print(f"Calculated Hashed Password: {entered_password_hashed}")

    # Compare the entered password hash with the stored hash
    return entered_password_hashed == stored_hashed_password

def check_user_exists(username):

    # Query the database to check if the user exists
    user = user_information_table.find_one({"username": username})

    return user is not None


def login_verification(username, password):
    
    if check_user_exists(username) != True:
        print("User does not exist")
        return False


    user_salt = get_salt(username)

    print(f"\nUser {username} has salt: {user_salt}\n")

    # input_password = input("\nPassword:\nEnter Here:")

    if verify_password(username, password, user_salt) == True:
        print("Successfully Logged In\n")
        return True
    else:
        print("Incorrect Username or Password\n")
        return False
    


# Database Section
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################

def user_logged_in_status(client_we_are_serving):
    
    if client_we_are_serving.client_logged_in == 1:
        return True
    else:
        return False


def validate_peer_list():

    global client_state_list
    new_clientlist = []
    for c in client_state_list:
        check = 1
        curr_time = datetime.now()
        #Check that client has sent a message in the past two minutes and that
        #it has not closed the socket
        # if (curr_time - c.peer_last_message_time).total_seconds() <= 120 (c.sock.fileno != -1):

        if (curr_time - c.peer_last_message_time).total_seconds() > 60:
            print("Ya out of time bucko")
            check = 0

        if c.sock.fileno == -1:
            print("Client forced disconeect")
            check = 0

        if check == 1:
            new_clientlist.append(c)
    
    client_state_list = new_clientlist

    return

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
    # peer_sock.send(len(server_public_key).to_bytes(2, "big") + server_public_key)
    send_public_key(peer_sock, server_public_key)

    # Recv Client Pub key
    client_public_key = recieve_public_key(peer_sock)
   
    client_public_key = load_der_public_key(client_public_key, default_backend())

    # Create Key Recipe
    shared_key_recipe = server_private_key.exchange(client_public_key)

    # Generate Shared_key and IV with Client for encrypted communication
    shared_key = generate_shared_secret_key(shared_key_recipe)
    iv = generate_shared_iv(shared_key_recipe)

    print(f"\nShared Key: {shared_key}")
    print(f"IV: {iv}\n")

    # Recv message from client
    recv_encrypted_handshake_message = recieve_package(peer_sock)

    # Unpackage/Decrypt message from client
    unpackaged_message = unpackage_message(recv_encrypted_handshake_message, shared_key, iv)

    print("Handshake Success!\n")

    #send_test edit
    client_state_list.append(new_peer)

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

    print("Setting Up Database")

    try:
        client = pymongo.MongoClient(conn_str)

    except Exception:
        print("Error: " + Exception)

    bank_database = client["bank_of_america_database"]
    user_information_table = bank_database["user_information"]
 
    print("Mongo python database Setup!")

    # pull_user_data("user")
    pull_user_data("user")

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


    print("Before Entering While loop -")
    print(f"Client State List: {client_state_list}")

    #2.1 - Infinite Loop to Keep Server Constantly listening for Client Information
    while True:
        
        #2.2 -
        rfds = []
        rlist = []

        #2.3 - Check Keep Alive Messages For Each Client (TO-DO)
        validate_peer_list()

        #print Test
        print(f"Client List: {client_state_list}")

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

            print("File descriptors not empty!")

            for r in rfds:
                if (r.fileno == -1):
                    print("Error -1")
                    continue

                if (r == server_socket):
                    print("Handshake one")
                    recv_handshake_from_initiator(server_socket, server_private_key, server_public_key)
                    continue
        
                print("Reiceving on some peer")

                packet_header = r.recv(1)
                print(f"Message: {packet_header}")
                if len(packet_header) == 0:  # end of the file
                    continue
                # if len(packet_header) == 0:  # end of the file
                #     print("Something b r o k e")
                #     continue
                
                # headers work directly with bytes
                # packet_header = struct.unpack("!I", packet_header)
                # packet_header = packet_header[0]
                # print("Length:", packet_header)


                if (packet_header == KEEP_ALIVE): #Keep Alive Message
                    print("Keep Alive Message")
                    serving_peer_host, serving_peer_port = r.getpeername()
                    for k in client_state_list:
                        if k.peer_ip_addr == serving_peer_host and k.peer_port == serving_peer_port:
                            k.peer_last_message_time = datetime.now()

                else:
                    print("Non Keep Alive Message")
                    serving_peer_host, serving_peer_port = r.getpeername()
                    print(f"Serving Peer: {serving_peer_host}")
                    print(f"Serving Port: {serving_peer_port}")

                    print(f"Client State List: {client_state_list}")

                    for k in client_state_list:
                        print(f"Client: {k.peer_ip_addr} and {k.peer_port}")
                        # if k.peer_ip_addr == serving_peer_host and k.peer_port == serving_peer_port:
                        #     client_we_are_serving = k
                        if k.peer_port == serving_peer_port:
                             client_we_are_serving = k

                    print(f"Client we are serving: {client_we_are_serving}")
                    client_we_are_serving.peer_last_message_time = datetime.now()

                    if packet_header == KEEP_ALIVE:

                        print("Recieved Packet KEEP ALIVE")
                        
                        # Call Get Packet Data for as many parameters the header requires
                        info_one = get_packet_data(r)

                    elif packet_header == LOGIN_REQUEST_HEADER:

                        print("Recieved Packet Type LOGIN")
                        # Call Get Packet Data for as many parameters the header requires
                        username = get_packet_data(r)
                        password = get_packet_data(r)

                        print(f"Username: {username}")
                        print(f"Password: {password}")

                        username = username.decode('utf-8')
                        password = password.decode('utf-8')

                        print(f"Decoded Username: {username}")
                        print(f"Decoded Password: {password}")

                        if login_verification(username, password) == True:
                            print("Logged In!!")

                            client_we_are_serving.client_logged_in = 1
                            client_we_are_serving.holder_username = username
                            client_we_are_serving.holder_password = password

                            print(f"Client Status username {client_we_are_serving.holder_username}")
                            print(f"Client Status password {client_we_are_serving.holder_password}")

                            send_login_success_response(r)
                            

                        else:
                            print("Ya fucked up kid")
                            send_login_error_response(r)

                    elif packet_header == MODIFY_SAVINGS_HEADER:

                        print("Recieved Packet Type MODIFY")
                        # Call Get Packet Data for as many parameters the header requires
                        add_sub = get_packet_data(r)
                        amount = get_packet_data(r)

                        add_sub = add_sub.decode('utf-8')

                        if user_logged_in_status(client_we_are_serving):
                            print("User is logged in, proceed!")
                        else:
                            print("NOT LOGGED IN ")
                            continue

                        print(f"Add or Sub: {add_sub}")
                        print(f"Amount: {amount}")
                        print(f"Username: {client_we_are_serving.holder_username}")
                        print(f"Password: {client_we_are_serving.holder_password}")

                        amount = convert_to_integer(amount)

                        print(f"type of amount {amount} is {type(amount)}")
                        print(f"type of amount {amount} is {type(amount)}")

                        res2= verified_modification_user(add_sub, amount, client_we_are_serving.holder_username, client_we_are_serving.holder_password)

                        if res2 == True:
                            send_modify_savings_success_response(r)

                    elif packet_header == VIEW_SAVINGS_REQUEST_HEADER:
                        
                        print("Recieved Packet Type VIEW SAVINGS")
                        # Call Get Packet Data for as many parameters the header requires
                        
                        username = client_we_are_serving.holder_username
                        print(f"View User {username}")

                        savings = str(get_savings(username))

                        send_view_savings_success_response(savings, r)


                    elif packet_header ==  NEW_USER_REQUEST_HEADER:

                        print("Recieved Packet Type NEW USER")

                        # Call Get Packet Data for as many parameters the header requires
                        username = get_packet_data(r)
                        password = get_packet_data(r)

                        print(f"Username: {username}")
                        print(f"Password: {password}")

                        username = username.decode('utf-8')
                        password = password.decode('utf-8')

                        print(f"Decoded Username: {username}")
                        print(f"Decoded Password: {password}")

                        if check_user_exists(username) == True:
                            print("User already Exists not exist")
                            send_user_name_taken_error_response(r)

                        res3 = add_user_to_database(username, password)

                        if res3 == 1:
                            send_user_created_response(r)
                        else:
                            send_user_mongo_error_response(r)

                    elif packet_header == DISCONNECT_CLIENT:
                        print("Disconnected")
                        
                    else:
                        print("none packet header")






