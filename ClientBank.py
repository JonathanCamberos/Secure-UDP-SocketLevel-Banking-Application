import socket
import select
import sys
import argparse
import struct

from Peer import Peer

client_state_list = []


# def send_recv_handshake(sd: socket, peer_id: str):
def send_recv_handshake(sd: socket):
    """
    Sends and receives bittorrent handshake needed to initiate a connection
    with a client
    """
    pstrlen = b"\x13"
    pstr = b"Bank protocol"
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # peer_id = peer_id.encode("utf-8")

    handshake_message = b"".join([pstrlen, pstr, reserved])
    sd.sendall(handshake_message)

    response_handshake = sd.recv(22)
    if len(response_handshake) == 0:
        # print("Couldn't complete the handshake")
        return False
 
    print("Bytes recieved from response to our initial handshake --->", len(response_handshake))
    # pstrlen, pstr, reserved, info_hash, response_peer_id = struct.unpack("!c20s2s20s20s", response_handshake)
    pstrlen, pstr, reserved = struct.unpack("!c18s3s", response_handshake)

    pstrlen = int.from_bytes(pstrlen, "big")
    pstr = pstr.decode("utf-8")
    # response_peer_id = response_peer_id.decode("utf-8")
    # print(pstrlen)
    # print(pstr)
    # print(reserved)
    # print(info_hash)
    # TODO: validate response peer id
    # print("Received Peer ID:", response_peer_id)
    # print("My Peer ID:", peer_id)
    return True



def initialize_client_state_list():
    global p, socket_error

    print("Inside initliaze client state")

    for p in peers:


        try:
            print(f"Trying to connect to {p.peer_ip_addr}:{p.peer_port}")
            sd = socket.create_connection((p.peer_ip_addr, p.peer_port), timeout=1)
            sd.settimeout(None)
            
            print(f"Connection Success!! Attempting Handshake")
            
            # if send_recv_handshake(sd, peer_id, tracker):
            if send_recv_handshake(sd):
                print(f"! Connected to {p.peer_ip_addr}:{p.peer_port}")
                p.set_sock(sd)
                client_state_list.append(p)
                rlist.append(sd)
        except socket.error as e:
            # print("could not connect: ", e)
            socket_error = True




if __name__ == '__main__':

    if len(sys.argv) < 1:
        print("Usage: python3 client.py [--ip_port IP_PORT] ")
        exit(1)
    else:

        parser = argparse.ArgumentParser()
        parser.add_argument('--ip_port',type=int,required=False,help='The port that the BitTorrent clienct connects to')

        print("Correct number of arguments")

        args = parser.parse_args()


        print(f'Running BitTorrent client with arguments: {args.ip_port}')

    #0.0 Create a Socket and Bind to It
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if args.ip_port is not None:
        my_socket.bind(("0.0.0.0", args.ip_port))
    else:
        my_socket.bind(("0.0.0.0", 4200))
    my_socket.listen()

    print("CLIENT 1111111111111111111111111")
    hostname=socket.gethostname()
    IPAddr=socket.gethostbyname(hostname)
    print("My Computer Name is:"+hostname)
    print("My Computer IP Address is:"+IPAddr)


    ########printing stuff
    print("Testing info --------------")

    ### we will now attempt to connect to test client_2 on port 6969
    print("Connecting to port: 6969")

    peers = []
    peers.append(Peer("Unknown", "0.0.0.0", 6969, -1))

    if len(peers) == 0:
        print("No peers found! Exiting...")
        exit(1)

    print("Got the following peers:")
    for p in peers:
        print(p)


    # Create empty file descriptors lists needed for select call below
    rlist, wlist, xlist = [], [], []
    socket_error = False

    #we have our list of peers, albiet, a single peer
    #now we must inititalize our client --> State list
    initialize_client_state_list()





