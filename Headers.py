


KEEP_ALIVE = b"\x01"
DISCONNECT_CLIENT = b'\x02'

NEW_USER_REQUEST_HEADER = b'\x10'
NEW_USER_SUCCESS_RESPONSE = b'\x11'
NEW_USER_NAME_TAKEN_ERROR_RESPONSE = b'\x12'
NEW_USER_MONGO_ERROR_RESPONSE = b'\x13'

LOGIN_REQUEST_HEADER = b"\x20"
LOGIN_SUCCESS_HEADER = b"\x21"
LOGIN_ERROR_HEADER = b'\x22'

MODIFY_SAVINGS_HEADER = b"\x23"
MODIFY_SAVINGS_SUCCESS_HEADER = b"\x24"
MODIFY_SAVINGS_ERROR_HEADER = b'\x25'

VIEW_SAVINGS_REQUEST_HEADER = b'\x51'
VIEW_SAVINGS_SUCCESS_RESPONSE = b'\x52'

PEER_HANDSHAKE_CERTIFICATE_HEADER = b'\x61'



