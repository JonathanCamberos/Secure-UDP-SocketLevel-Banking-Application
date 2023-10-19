from Headers import TEST_HEADER
from Headers import KEEP_ALIVE

from Headers import DISCONNECT_CLIENT

from Headers import LOGIN_REQUEST_HEADER 
from Headers import STATUS_REQUEST_HEADER
from Headers import TRANSFER_REQUEST_HEADER

from Headers import MODIFY_SAVINGS_SUCCESS_HEADER
from Headers import MODIFY_SAVINGS_ERROR_HEADER

from Headers import LOGIN_SUCCESS_HEADER
from Headers import LOGIN_ERROR_HEADER

from Headers import VIEW_SAVINGS_REQUEST_HEADER
from Headers import VIEW_SAVINGS_SUCCESS_RESPONSE

from Headers import STATUS_SUCCESS_HEADER 
from Headers import TRANSFER_SUCCESS_HEADER 
from Headers import GENERIC_ERROR_HEADER 

from Headers import TRANSFER_ERROR_NOTARGET_HEADER
from Headers import TRANSFER_ERROR_NOMONEY_HEADER 

from BothMessages import send_package
from BothMessages import package_single_data


def send_login_success_response(peer_sock):

    header = LOGIN_SUCCESS_HEADER

    message = b"".join([header])

    send_package(message, peer_sock)

    return

def send_login_error_response(peer_sock):

    header = LOGIN_ERROR_HEADER

    message = b"".join([header])

    send_package(message, peer_sock)

    return



def send_modify_savings_success_response(peer_sock):

    header = MODIFY_SAVINGS_SUCCESS_HEADER

    message = b"".join([header])

    send_package(message, peer_sock)
    
    return


def send_view_savings_success_response(savings, peer_sock):

    header = VIEW_SAVINGS_SUCCESS_RESPONSE

    savings_package = package_single_data(savings)

    message = b"".join([header, savings_package])

    send_package(message, peer_sock)
    
    return


