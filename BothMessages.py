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
