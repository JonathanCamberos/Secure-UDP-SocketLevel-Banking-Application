import struct
import util


def package_single_data(data):

    data = data.encode('utf-8')

    length = len(data).to_bytes(4, "big")
    message = b"".join([length, data])

    return message

def send_package(package, server_sock):

    res = server_sock.sendall(package)

    if res == None:
        print(f"Sent package of length: {len(package)}")
        # print("Entire Package Sent: Success!")
        # print(f"Package: {package}\n")
    else:
        print("\nPartial Package Sent: Error!\n")
    
    return

def get_packet_data(r):

    data_len = r.recv(4)
    # print(data_len)


    if(data_len == b''):
        return b''


    data_len = struct.unpack("!I", data_len)
    data_len = data_len[0]
    # print(f"Length of Curr Data: {data_len}")

    data = r.recv(data_len)

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