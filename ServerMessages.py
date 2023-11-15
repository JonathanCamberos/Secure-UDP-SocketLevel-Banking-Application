

import Headers

import BothMessages


def send_login_success_response(peer_sock, shared_key, iv):

    header = Headers.LOGIN_SUCCESS_HEADER

    message = b"".join([header])

    BothMessages.encrypt_and_send(message, peer_sock, shared_key, iv)

    return

def send_login_error_response(peer_sock, shared_key, iv):

    header = Headers.LOGIN_ERROR_HEADER

    message = b"".join([header])

    BothMessages.encrypt_and_send(message, peer_sock, shared_key, iv)

    return



def send_modify_savings_success_response(peer_sock, shared_key, iv):

    header = Headers.MODIFY_SAVINGS_SUCCESS_HEADER

    message = b"".join([header])

    BothMessages.encrypt_and_send(message, peer_sock, shared_key, iv)
    
    return


def send_modify_savings_error_response(peer_sock, shared_key, iv):

    header = Headers.MODIFY_SAVINGS_ERROR_HEADER

    message = b"".join([header])

    BothMessages.encrypt_and_send(message, peer_sock, shared_key, iv)
    
    return

def send_view_savings_success_response(savings, peer_sock, shared_key, iv):

    header = Headers.VIEW_SAVINGS_SUCCESS_RESPONSE

    savings_package = BothMessages.package_single_data(savings)

    message = b"".join([header, savings_package])

    BothMessages.encrypt_and_send(message, peer_sock, shared_key, iv)
    
    return


def send_user_created_response(peer_sock, shared_key, iv):

    header = Headers.NEW_USER_SUCCESS_RESPONSE

    message = b"".join([header])

    BothMessages.encrypt_and_send(message, peer_sock, shared_key, iv)

    return

def send_user_mongo_error_response(peer_sock, shared_key, iv):

    header = Headers.NEW_USER_MONGO_ERROR_RESPONSE

    message = b"".join([header])

    BothMessages.encrypt_and_send(message, peer_sock, shared_key, iv)

    return

def send_user_name_taken_error_response(peer_sock, shared_key, iv):

    header = Headers.NEW_USER_NAME_TAKEN_ERROR_RESPONSE

    message = b"".join([header])

    BothMessages.encrypt_and_send(message, peer_sock, shared_key, iv)

    return

def send_disconnect_succes_response(peer_sock, shared_key, iv):
    header = Headers.DISCONNECT_CLIENT
    message = b"".join([header])
    BothMessages.encrypt_and_send(message, peer_sock, shared_key, iv)
    return

def get_user_and_pass_from_message(message):

    # print(message[:4])
    username_length = int.from_bytes(message[:4], 'big', signed=False)
    # print(username_length)
    # Slice username from byte 5 to byte 4+length
    username_bytes = message[4:4+username_length]

    # Repeat with password, but starting from the end of username
    remaining_message = message[4+username_length:]
    password_length = int.from_bytes(remaining_message[:4], 'big', signed=False)
    # print(password_length)
    password_bytes = remaining_message[4:4+password_length]
    
    username = username_bytes.decode('utf-8')
    password = password_bytes.decode('utf-8')

    return username, password

def get_amount_to_change(message):
    # Litteraly copy of getUsernameAndPassword, find a better name and combine

    # print(message[:4])
    add_sub_length = int.from_bytes(message[:4], 'big', signed=False)
    # print(add_sub_length)
    # Slice username from byte 5 to byte 4+length
    add_sub_bytes = message[4:4+add_sub_length]

    # Repeat with password, but starting from the end of username
    remaining_message = message[4+add_sub_length:]
    amount_length = int.from_bytes(remaining_message[:4], 'big', signed=False)
    # print(amount_length)
    amount_bytes = remaining_message[4:4+amount_length]
    
    add_sub = add_sub_bytes.decode('utf-8')
    amount = amount_bytes.decode('utf-8')

    return add_sub, amount