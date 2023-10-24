
from Headers import LOGIN_REQUEST_HEADER 
from Headers import DISCONNECT_CLIENT

from Headers import MODIFY_SAVINGS_HEADER
from Headers import MODIFY_SAVINGS_SUCCESS_HEADER
from Headers import MODIFY_SAVINGS_ERROR_HEADER

from Headers import VIEW_SAVINGS_REQUEST_HEADER
from Headers import VIEW_SAVINGS_SUCCESS_RESPONSE

from Headers import LOGIN_SUCCESS_HEADER
from Headers import LOGIN_ERROR_HEADER

from Headers import NEW_USER_REQUEST_HEADER
from Headers import NEW_USER_SUCCESS_RESPONSE
from Headers import NEW_USER_NAME_TAKEN_ERROR_RESPONSE

from BothMessages import send_package
from BothMessages import package_single_data
from BothMessages import get_packet_data
from BothMessages import encrypt_and_send

from util import package_message


def prepare_HandShake_Message():
    pstrlen = b"\x13"
    pstr = b"Bank protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # peer_id = peer_id.encode("utf-8")

    handshake_message = b"".join([pstrlen, pstr, reserved])

    return handshake_message

def send_new_user_request(username, password, server_sock):

    header = NEW_USER_REQUEST_HEADER

    username_package = package_single_data(username)
    password_package = package_single_data(password)

    message = b"".join([header, username_package, password_package])

    send_package(message, server_sock)

    return

def recv_new_user_response(server_sock):

    header = server_sock.recv(1)

    if header == NEW_USER_SUCCESS_RESPONSE:
        print("New User Created!")
        return True

    elif header == NEW_USER_NAME_TAKEN_ERROR_RESPONSE:
        print("Username Already Taken")
        return False
    else:
        print("Invalid repsonse")
        return False


def send_login_request(username, password, server_sock, shared_key, iv):

    header = LOGIN_REQUEST_HEADER

    username_package = package_single_data(username)
    password_package = package_single_data(password)
    
    message = b"".join([header, username_package, password_package])
    encrypt_and_send(message, server_sock, shared_key, iv)
    return

def recv_login_response(server_sock):

    header = server_sock.recv(1)

    if header == LOGIN_SUCCESS_HEADER:
        print("LOGGED IN!")
        return True

    elif header == LOGIN_ERROR_HEADER:
        print("Err on login")
        return False
    else:
        print("Invalid repsonse")
        return False


def send_modify_savings_request(server_sock, shared_key, iv):
    
    print("1 - Add")
    print("2 - Subtract")
    add_sub = input("\nEnter Here: ")
    amount = input("\Amount:\nEnter Here:")

    header = MODIFY_SAVINGS_HEADER

    add_sub_package = package_single_data(add_sub)
    amount_package = package_single_data(amount)

    message = b"".join([header, add_sub_package, amount_package])
    encrypt_and_send(message, server_sock, shared_key, iv)

    return

def recv_modify_savings_response(server_sock):

    header = server_sock.recv(1)

    if header == MODIFY_SAVINGS_SUCCESS_HEADER:
        print("Savings Successfully Updated!")
        return True

    elif header == MODIFY_SAVINGS_ERROR_HEADER:
        print("Unable to Updated Savings")
        return False
    else:
        print("Invalid repsonse")
        return False


def send_view_savings_request(username, server_sock, shared_key, iv):
    
    header = VIEW_SAVINGS_REQUEST_HEADER

    message = b"".join([header])
    encrypt_and_send(message, server_sock, shared_key, iv)

    return

def recv_view_savings_response(server_sock):

    header = server_sock.recv(1)

    if header == VIEW_SAVINGS_SUCCESS_RESPONSE:
        print("Savings Viewed!")
        amount = get_packet_data(server_sock).decode('utf-8')

        print(f"Current Savings: {amount}")

    return

def send_close_request(server_sock, shared_key, iv):
    header = DISCONNECT_CLIENT

    message = b"".join([header])
    encrypt_and_send(message, server_sock, shared_key, iv)

    return

def recv_close_request(server_sock):
    header = server_sock.recv(1)
    if header == DISCONNECT_CLIENT:
        print("Succesfully exited the banking app!")
        print("Goodbye!")
    return
