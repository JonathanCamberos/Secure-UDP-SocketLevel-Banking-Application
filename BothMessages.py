import struct
import util
import Headers
import socket

from cryptography import x509

def package_single_data(data):

    data = data.encode('utf-8')

    length = len(data).to_bytes(4, "big")
    message = b"".join([length, data])

    return message

def package_bytes_data(data_bytes):

    length = len(data_bytes).to_bytes(4, "big")
    message = b"".join([length, data_bytes])
    
    return message

def send_package(package, server_sock):

    print(f"\nSending Message with Length {len(package)}\n")

    is_socket = isinstance(server_sock, socket.socket)
    print(f"Server Socket is socket: {is_socket}")

    res = server_sock.sendall(package)

    if res == None:
        print(f"Sent package of length: {len(package)}")
        # print("Entire Package Sent: Success!")
        # print(f"Package: {package}\n")
    else:
        print("\nPartial Package Sent: Error!\n")
    
    return


def send_peer_self_cert(self_cert_bytes, peer_sock, shared_key, iv):

    header = Headers.PEER_HANDSHAKE_CERTIFICATE_HEADER

    self_cert_package = package_bytes_data(self_cert_bytes)

    message = b"".join([header, self_cert_package])

    encrypt_and_send(message, peer_sock, shared_key, iv)

    return


def recv_peer_self_cert(peer_sock, shared_key, iv):

    encrypted_message = get_packet_data(peer_sock)
    decrypted_message = util.unpackage_message(encrypted_message, shared_key, iv)

    # Isolate header and chop it off the rest of the message
    packet_header = decrypted_message[0].to_bytes(1,"big")

    if packet_header == Headers.PEER_HANDSHAKE_CERTIFICATE_HEADER:
        print("\nRecieved Self-Signed Certificate")
    else:
        print("Did not Recieve Certificate - Error")
        return

    # Rest of the message (Parameters of the request)
    decrypted_message = decrypted_message[1:]


    # print(message[:4])
    peer_self_cert_len = int.from_bytes(decrypted_message[:4], 'big', signed=False)
    # print(add_sub_length)
    # Slice username from byte 5 to byte 4+length
    peer_self_cert_bytes = decrypted_message[4:4+peer_self_cert_len]

    # print(client_self_cert_bytes)

     # Grabbing certificate bytes and reloading into a certificate
    # print("\nDecoding Bytes to Certificate:\n")
    
    peer_self_cert = x509.load_pem_x509_certificate(peer_self_cert_bytes)


    return peer_self_cert



# Used in the (length + Encrypted_Message) portion of the code
def get_packet_data(r):

    data_length = r.recv(4)
    sum_data_length = 0
    data = b""

    # print(data_len)

    if(data_length == b''):
        return b''


    data_length = struct.unpack("!I", data_length)
    data_length = data_length[0]
    # print(f"Length of Curr Data: {data_length}")

    print(f"\nRecieved Packet of Total length: {data_length}")

    while (sum_data_length < data_length):
        print(f"Have read {sum_data_length} Bytes")

        if (sum_data_length + 1024) > data_length:
            temp_data = r.recv(data_length - sum_data_length)
        else:
            temp_data = r.recv(1024)

        data = b"".join([data, temp_data])
        sum_data_length += len(temp_data)    

    print(f"Finished Reading {len(data)} amount of bytes\n")

    # data = r.recv(data_length)

    # print(f"Data: {data}")

    return data

def encrypt_and_send(message, server_sock, key, iv):
    # Encrypt message using shared key and iv
    encrypted_message = util.package_message(message, key, iv)
    # add 4 bytes containing package length and prepend this to the package
    length = len(encrypted_message).to_bytes(4, "big")
    encr_message_with_length_prefix = b"".join([length, encrypted_message])

    send_package(encr_message_with_length_prefix, server_sock)

    return