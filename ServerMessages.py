


from Headers import KEEP_ALIVE
from Headers import DISCONNECT_CLIENT

from Headers import MODIFY_SAVINGS_SUCCESS_HEADER
from Headers import MODIFY_SAVINGS_ERROR_HEADER

from Headers import LOGIN_SUCCESS_HEADER
from Headers import LOGIN_ERROR_HEADER

from Headers import VIEW_SAVINGS_SUCCESS_RESPONSE

from Headers import NEW_USER_SUCCESS_RESPONSE
from Headers import NEW_USER_NAME_TAKEN_ERROR_RESPONSE
from Headers import NEW_USER_MONGO_ERROR_RESPONSE

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


def send_user_created_response(peer_sock):

    header = NEW_USER_SUCCESS_RESPONSE

    message = b"".join([header])

    send_package(message, peer_sock)

    return

def send_user_mongo_error_response(peer_sock):

    header = NEW_USER_MONGO_ERROR_RESPONSE

    message = b"".join([header])

    send_package(message, peer_sock)

    return

def send_user_name_taken_error_response(peer_sock):

    header = NEW_USER_NAME_TAKEN_ERROR_RESPONSE

    message = b"".join([header])

    send_package(message, peer_sock)

    return