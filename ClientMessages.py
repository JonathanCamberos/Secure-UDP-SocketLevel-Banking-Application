# little test for commit with this fork bs

import Headers 

import BothMessages

import util


def prepare_HandShake_Message():
    pstrlen = b"\x13"
    pstr = b"Bank protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # peer_id = peer_id.encode("utf-8")

    handshake_message = b"".join([pstrlen, pstr, reserved])

    return handshake_message

def send_new_user_request(username, password, server_sock, shared_key, iv):

    header = Headers.NEW_USER_REQUEST_HEADER

    username_package = BothMessages.package_single_data(username)
    password_package = BothMessages.package_single_data(password)

    message = b"".join([header, username_package, password_package])

    BothMessages.encrypt_and_send(message, server_sock, shared_key, iv)

    return

def recv_new_user_response(server_sock, shared_key, iv):

    header, _ = recv_encrypted_response(server_sock, shared_key, iv)

    if header == Headers.NEW_USER_SUCCESS_RESPONSE:
        print("New User Created!")
        return True

    elif header == Headers.NEW_USER_NAME_TAKEN_ERROR_RESPONSE:
        print("Username Already Taken")
        return False
    else:
        print("Invalid repsonse")
        return False


def send_login_request(username, password, server_sock, shared_key, iv):

    header = Headers.LOGIN_REQUEST_HEADER

    username_package = BothMessages.package_single_data(username)
    password_package = BothMessages.package_single_data(password)
    
    message = b"".join([header, username_package, password_package])
    BothMessages.encrypt_and_send(message, server_sock, shared_key, iv)
    return

def recv_login_response(server_sock, shared_key, iv):

    header, _ = recv_encrypted_response(server_sock, shared_key, iv)

    if header == Headers.LOGIN_SUCCESS_HEADER:
        print("LOGGED IN!")
        return True

    elif header == Headers.LOGIN_ERROR_HEADER:
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

    header = Headers.MODIFY_SAVINGS_HEADER

    add_sub_package = BothMessages.package_single_data(add_sub)
    amount_package = BothMessages.package_single_data(amount)

    message = b"".join([header, add_sub_package, amount_package])
    BothMessages.encrypt_and_send(message, server_sock, shared_key, iv)

    return

def recv_modify_savings_response(server_sock, shared_key, iv):

    header, message = recv_encrypted_response(server_sock, shared_key, iv)

    if header == Headers.MODIFY_SAVINGS_SUCCESS_HEADER:
        print("Savings Successfully Updated!")
        return True

    elif header == Headers.MODIFY_SAVINGS_ERROR_HEADER:
        print("Unable to Updated Savings")
        return False
    else:
        print("Invalid repsonse")
        return False


def send_view_savings_request(username, server_sock, shared_key, iv):
    
    header = Headers.VIEW_SAVINGS_REQUEST_HEADER

    message = b"".join([header])
    BothMessages.encrypt_and_send(message, server_sock, shared_key, iv)

    return

def recv_view_savings_response(server_sock, shared_key, iv):

    header, message = recv_encrypted_response(server_sock, shared_key, iv)

    if header == Headers.VIEW_SAVINGS_SUCCESS_RESPONSE:
        # print("Savings Viewed!")
        amount = message.decode('utf-8')

        print(f"Current Savings: {amount}")

    return

def send_close_request(server_sock, shared_key, iv):
    header = Headers.DISCONNECT_CLIENT

    message = b"".join([header])
    BothMessages.encrypt_and_send(message, server_sock, shared_key, iv)

    return

def recv_close_request(server_sock, shared_key, iv):
    header = recv_encrypted_response(server_sock, shared_key, iv)
    if header == Headers.DISCONNECT_CLIENT:
        print("Succesfully exited the banking app!")
        # print("Goodbye!")
    return

"""
    Takes the socket of sender, returns decrypted message as:
        header, message
"""
def recv_encrypted_response(server_sock, shared_key, iv):
    message_length_bytes = server_sock.recv(4)
    message_length = int.from_bytes(message_length_bytes, 'big', signed=False)
    encrypted_message = server_sock.recv(message_length)

    decrypted_message = util.unpackage_message(encrypted_message, shared_key, iv)
    return decrypted_message[0].to_bytes(1, "big"), decrypted_message[1:]




    
