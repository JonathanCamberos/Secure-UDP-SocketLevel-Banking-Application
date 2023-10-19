import struct

from Headers import TEST_HEADER


from Headers import LOGIN_REQUEST_HEADER 
from Headers import STATUS_REQUEST_HEADER
from Headers import TRANSFER_REQUEST_HEADER

from Headers import MODIFY_SAVINGS_HEADER
from Headers import MODIFY_SAVINGS_SUCCESS_HEADER
from Headers import MODIFY_SAVINGS_ERROR_HEADER

from Headers import VIEW_SAVINGS_REQUEST_HEADER
from Headers import VIEW_SAVINGS_SUCCESS_RESPONSE

from Headers import LOGIN_SUCCESS_HEADER
from Headers import STATUS_SUCCESS_HEADER 
from Headers import TRANSFER_SUCCESS_HEADER 
from Headers import GENERIC_ERROR_HEADER 
from Headers import LOGIN_ERROR_HEADER
from Headers import TRANSFER_ERROR_NOTARGET_HEADER
from Headers import TRANSFER_ERROR_NOMONEY_HEADER 

from BothMessages import send_package
from BothMessages import package_single_data
from BothMessages import get_packet_data

from util import convert_to_integer



# alternativa de rror
#    pstrlen = ERROR_HEADER
#    pstr = error_message.encode('utf-8')
#    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
#
# se dan los detalles del error en error_message


def prepare_HandShake_Message():
    pstrlen = b"\x13"
    pstr = b"Bank protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # peer_id = peer_id.encode("utf-8")

    handshake_message = b"".join([pstrlen, pstr, reserved])

    return handshake_message


def send_login_request(username, password, server_sock):

    header = LOGIN_REQUEST_HEADER

    username_package = package_single_data(username)
    password_package = package_single_data(password)
    
    message = b"".join([header, username_package, password_package])

    send_package(message, server_sock)
    return

def recv_login_response(server_sock):

    data = server_sock.recv(1)

    if data == LOGIN_SUCCESS_HEADER:
        print("LOGGED IN!")
        return True

    elif data == LOGIN_ERROR_HEADER:
        print("Err on login")
        return False
    else:
        print("Invalid repsonse")
        return False


def send_modify_savings_request(server_sock):
    
    print("1 - Add")
    print("2 - Subtract")
    add_sub = input("\nEnter Here: ")
    amount = input("\Amount:\nEnter Here:")

    header = MODIFY_SAVINGS_HEADER

    add_sub_package = package_single_data(add_sub)
    amount_package = package_single_data(amount)

    message = b"".join([header, add_sub_package, amount_package])

    send_package(message, server_sock)

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


def send_view_savings_request(username, server_sock):
    
    header = VIEW_SAVINGS_REQUEST_HEADER

    message = b"".join([header])

    send_package(message, server_sock)

    return

def recv_view_savings_response(server_sock):

    header = server_sock.recv(1)

    if header == VIEW_SAVINGS_SUCCESS_RESPONSE:
        print("Savings Viewed!")
        amount = get_packet_data(server_sock).decode('utf-8')

        print(f"Current Savings: {amount}")

    return