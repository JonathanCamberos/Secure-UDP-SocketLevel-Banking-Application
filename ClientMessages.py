

def prepare_HandShake_Message():
    pstrlen = b"\x13"

    test_string = "Bank protocol"
    test_string = test_string.encode('utf-8')

    # pstr = b"Bank protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # peer_id = peer_id.encode("utf-8")

    handshake_message = b"".join([pstrlen, test_string, reserved])

    return handshake_message

def prepare_Hello_Message():

    pstrlen = b"\x13"
    pstr = b"Bank protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # peer_id = peer_id.encode("utf-8")

    hello_message = b"".join([pstrlen, pstr, reserved])

    return hello_message