import socket
import select
import sys
import argparse
import pymongo 
import secrets
import uuid

from pymongo.errors import DuplicateKeyError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from datetime import datetime
from Peer import Peer
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key


conn_str = "mongodb+srv://jcambero:jcambero@cluster0.nkjnjyb.mongodb.net/"
certificate_database = ''
user_certificates_table = ''

print("Setting Up Database")

    try:
        client = pymongo.MongoClient(conn_str)

    except Exception:
        print("Error: " + Exception)

    certificate_database = client["certificate_server_database"]
    user_certificates_table = certificate_database["user_certificates"]
 
    print("Mongo python database Setup!")

    # pull_user_data("user")
    pull_user_data("user")