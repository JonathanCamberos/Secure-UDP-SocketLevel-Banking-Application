import string
import socket
import struct

from math import ceil
from util import *
from datetime import datetime

class Peer:
    def __init__(self, id_number, peer_ip_addr, peer_port, sd):
        self.peer_id = id_number
        self.peer_ip_addr = "0.0.0.0"
        self.peer_port = peer_port
        self.sock = sd
        self.peer_last_message_time = datetime.now()
        self.peer_last_send_time = -1
        self.peer_certificate = 0
        self.handshake_complete = 0

    def __str__(self):
        return "Peer -> ID: " + self.peer_id + ", " + self.peer_ip_addr + ":" + str(self.peer_port + "Socket" + self.sock)

    def __eq__(self, other):
        """Overrides the default implementation"""
        return self.peer_id == other.peer_id and self.peer_ip_addr == other.peer_ip_addr and self.peer_port == other.peer_port

    def __lt__(self, other):  # For sorting lists
        return self.peer_id < other.peer_id
    def set_sock(self, sd):
        self.sock = sd