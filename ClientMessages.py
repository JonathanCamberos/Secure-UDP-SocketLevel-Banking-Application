
from Headers import TEST_HEADER


from Headers import LOGIN_REQUEST_HEADER 
from Headers import STATUS_REQUEST_HEADER
from Headers import TRANSFER_REQUEST_HEADER

from Headers import LOGIN_SUCCESS_HEADER
from Headers import STATUS_SUCCESS_HEADER 
from Headers import TRANSFER_SUCCESS_HEADER 
from Headers import GENERIC_ERROR_HEADER 
from Headers import LOGIN_ERROR_HEADER
from Headers import TRANSFER_ERROR_NOTARGET_HEADER
from Headers import TRANSFER_ERROR_NOMONEY_HEADER 


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

def prepare_Hello_Message():
    pstrlen = b"\x13"
    pstr = b"Bank protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # peer_id = peer_id.encode("utf-8")

    hello_message = b"".join([pstrlen, pstr, reserved])

    return hello_message


def wrap_single_information(info):
    info_len = (len(info))
    return b"".join([info_len, info])


def prepare_Login_Message(user, usrpwd):

    print("#######################################################")

    header = LOGIN_REQUEST_HEADER
    firstr = user.encode('utf-8')
    firstrlen = len(firstr).to_bytes(2, 'big')
    secstr = usrpwd.encode('utf-8')
    secstrlen = len(secstr).to_bytes(2, 'big')
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # peer_id = peer_id.encode("utf-8")

    transfer_message = b"".join([header, firstrlen, firstr, secstrlen, secstr, reserved])

    return transfer_message


def prepare_Transfer_Message(transfer_target, transfer_amount):
    header = TRANSFER_REQUEST_HEADER
    firstr = transfer_target.encode('utf-8')
    firstrlen = len(firstr)
    secstr = transfer_amount.encode('utf-8')
    secstrlen = len(secstr)
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # peer_id = peer_id.encode("utf-8")

    transfer_message = b"".join([header, firstrlen, firstr, secstrlen, secstr, reserved])

    return transfer_message


# Pedir una actualización de los datos.
def prepare_Status_Message():
    header = STATUS_REQUEST_HEADER
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # peer_id = peer_id.encode("utf-8")

    status_message = b"".join([header, reserved])

    return status_message


def send_hello_message(server_sock):
    
    header = TEST_HEADER

    word = b"hello"

    length = len(word).to_bytes(4, "big")
    
    message = b"".join([header, length, word])

    print(f"Sending: {message}")

    res = server_sock.sendall(message)

    if res == None:
        print(f"Sent: {len(message)}")
        print("Entire Package Sent: Success!")
        print(f"Package: {message}\n")
    else:
        print("\nPartial Package Sent: Error!\n")
    
    return

def package_single_data(data):

    data = data.encode('utf-8')

    length = len(data).to_bytes(4, "big")
    message = b"".join([length, data])       

    return message

def send_package(package, server_sock):

    res = server_sock.sendall(package)

    if res == None:
        print(f"Sent: {len(package)}")
        print("Entire Package Sent: Success!")
        print(f"Package: {package}\n")
    else:
        print("\nPartial Package Sent: Error!\n")
    
    return

def send_login_request(username, password, server_sock):

    header = LOGIN_REQUEST_HEADER

    username_package = package_single_data(username)
    password_package = package_single_data(password)
    
    message = b"".join([header, username_package, password_package])

    send_package(message, server_sock)
    return


