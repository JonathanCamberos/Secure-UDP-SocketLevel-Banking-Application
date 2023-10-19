import struct



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

def get_packet_data(r):

    data_len = r.recv(4)
   
    data_len = struct.unpack("!I", data_len)
    data_len = data_len[0]
    print(f"Length of Curr Data: {data_len}")

    data = r.recv(data_len)

    print(f"Data: {data}")

    return data