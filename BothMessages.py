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