

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