import socket
import select
import sys
import argparse
import time
import struct

from Peer import Peer



# def bank_recv_send_handshake(sd: socket, peer_id: str):
def bank_recv_send_handshake(sd: socket):
    """
    Sends and receives bittorrent handshake needed to initiate a connection
    with a client
    """

    
    response_handshake = sd.recv(68)
    if len(response_handshake) == 0:
        # print("Couldn't complete the handshake")
        return False
    print("Bytes recieved from response to our initial handshake --->", len(response_handshake))
    # pstrlen, pstr, reserved, info_hash, response_peer_id = struct.unpack("!c19s8s20s20s", response_handshake)
    # pstrlen = int.from_bytes(pstrlen, "big")
    # pstr = pstr.decode("utf-8")

    # response_peer_id = response_peer_id.decode("utf-8")
    # print(pstrlen)
    # print(pstr)
    # print(reserved)
    # print(info_hash)
    # TODO: validate response peer id
    # print("Received Peer ID:", response_peer_id)
    # print("My Peer ID:", peer_id)

    pstrlen = b"\x13"
    pstr = b"Bank protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # peer_id = peer_id.encode("utf-8")

    handshake_message = b"".join([pstrlen, pstr, reserved])
    sd.sendall(handshake_message)

    return True


if __name__ == '__main__':

    if len(sys.argv) < 1:
        print("Usage: python3 ServerBank.py [--ip_port IP_PORT] ")
        exit(1)
    else:

        parser = argparse.ArgumentParser()
        parser.add_argument('--ip_port',type=int,required=False,help='The port that the BitTorrent clienct connects to')

        print("Correct number of arguments")

        args = parser.parse_args()


        print(f'Running BitTorrent client with arguments: {args.ip_port}')

    server_ip = '0.0.0.0'  # Use '0.0.0.0' to listen on all available interfaces
    default_port = 6969


    #0.0 Create a Socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    #0.1 Binding to Socket Object
    if args.ip_port is not None:
        server_socket.bind((server_ip, args.ip_port))
    else:
        server_socket.bind((server_ip, default_port))

    #0.2 Listen on that Port (Socket)
    server_socket.listen()

    print("We are a serverrrrr We only LISTENINGGGGGG USING OUR EARSSSSS ***************************")

    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    print("My Computer Name is:"+hostname)
    print("My Computer IP Address is:"+IPAddr)
    if args.ip_port is not None:
        print(f"Server listening on {server_ip}:{args.ip_port}")
    else:
        print(f"Server listening on {server_ip}:{default_port}")


    #Now, as the server, we must accept incoming attempts to connect
    while True:
        # Wait for a client to establish a connection
        print(f"Listening....")
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")

        bank_recv_send_handshake(client_socket)

    # # Get the current time
    # start_time = time.time()
    # duration = 2
    # while True:
    #     # Get the current time in the loop
    #     current_time = time.time()

    #     # Calculate the elapsed time
    #     elapsed_time = current_time - start_time

    #     # Check if the elapsed time has reached the desired duration
    #     if elapsed_time >= duration:
    #         #alive timer, just prints out for sanity :) 
    #         duration = 2
    #         start_time = time.time()
    #         print("server is alive**************************")


    #     # Print the remaining time (optional)
    #     # remaining_time = duration - elapsed_time
    #     # print(f"Time remaining: {round(remaining_time, 2)} seconds")

    #     # Add a small delay to avoid high CPU usage
    #     # time.sleep(0.1)

    # print("Timer complete!")

