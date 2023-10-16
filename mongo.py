
import pymongo 
import uuid
import os

from pymongo.errors import DuplicateKeyError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode



conn_str = "mongodb+srv://jcambero:jcambero@cluster0.nkjnjyb.mongodb.net/"
bank_database = ''
user_information_table = ''
salt = ''



def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=urlsafe_b64decode(salt),
        iterations=100000,  # Choose an appropriate number of iterations
        length=32  # Length of the derived key
    )
    hashed_password = kdf.derive(password.encode('utf-8'))
    return hashed_password

def verify_password(username, entered_password, salt):
    # Hash the entered password with the stored salt
    entered_password_hashed = hash_password(entered_password, salt)

    stored_hashed_password = get_stored_hashed_password(username)

    print(f"Stored Hashed Password: {stored_hashed_password}\n")
    print(f"Input password: {entered_password}0")
    print(f"Calculated Hashed Password: {entered_password_hashed}")

    # Compare the entered password hash with the stored hash
    return entered_password_hashed == stored_hashed_password


def generate_unique_id():
    return str(uuid.uuid4())

def user_exists(user_collection, username):
    return user_collection.find_one({'name': username}) is not None

def get_stored_hashed_password(username):

    # Query the database for the user with the given username
    user_document = user_information_table.find_one({'name': username}, {'_id': 0, 'password': 1})

    # Check if the user was found
    if user_document:
        return user_document.get('password')
    else:
        print(f"User with username '{username}' not found.")
        return None

def convert_to_integer(s):
    try:
        return int(s)
    except ValueError:
        print(f"Error: Unable to convert '{s}' to an integer.")
        return None


def add_user_to_database(salt):

    input_username = input("\nSelect a username:\nEnter Here: ")

    input_password = input("\nChoose a password:\nEnter Here: ")
    hashed_input_password = hash_password(input_password, salt)

    print(f"Calculated Hash: {hashed_input_password}")

    input_savings = input("\nAmount of money input\nEnter Here: ")
    input_savings = convert_to_integer(input_savings)

     # Validate - User Already Exists
    if user_exists(user_information_table, input_username):
        print(f"\nUser with username '{input_username}' already exists in the database.")
        return 2

    # Validate - Input Savings is an Int
    if not isinstance(input_savings, int):
        print("Error: 'savings' must be an integer.")
        return 2

    # Generate Unique Id
    unique_id = generate_unique_id()

    # Create a user document
    new_user = {
        '_id': unique_id,
        'name': input_username,
        'plaintext password': input_password,
        'hashed password': hashed_input_password,
        'savings': input_savings
    }

    # Try - Add user to MongoDB
    try:
        user_information_table.insert_one(new_user)
    except DuplicateKeyError as e:
        print(f"Error: {e}")
        return 2

    return 1


def modify_user_savings(salt):

    print("Please Login:\n")
    input_username = input("\nUsername:\nEnter Here: ")
    input_password = input("\nPassword:\nEnter Here:")

    if verify_password(input_username, input_password, salt) == True:
        print("Successfully Logged In\n")
    else:
        print("Incorrect Username or Password\n")
        return 2
    
    input_savings = input("\nAmount of money input\nEnter Here: ")
    input_savings = convert_to_integer(input_savings)

    input_password = input("\nChoose a password:\nEnter Here: ")
    input_password = hash_password(input_password, salt)

     # Validate - User Already Exists
    if user_exists(user_information_table, input_username):
        print(f"\nUser with username '{input_username}' already exists in the database.")
        return 2

    # Validate - Input Savings is an Int
    if not isinstance(input_savings, int):
        print("Error: 'savings' must be an integer.")
        return 2

    # Generate Unique Id
    unique_id = generate_unique_id()

    # Create a user document
    new_user = {
        '_id': unique_id,
        'name': input_username,
        'password': input_password,
        'savings': input_savings
    }

    # Try - Add user to MongoDB
    try:
        user_information_table.insert_one(new_user)
    except DuplicateKeyError as e:
        print(f"Error: {e}")
        return 2

    return 1

def pull_user_data():

    input_username = input("\nUsername:\nEnter Here: ")

    # Query the database for all users with the given username
    user_documents = user_information_table.find({'name': input_username}, {'_id': 0})


    for user_document in user_documents:
            print("User Information:", user_document)
        
    return 



# Hello! This is the main code for the Client
# This section of the Banking Application will be in charge of:
#   - Starting communications to the Bank Server
#       - Diffie-Hellman exchange --> Shared_secret
#       - IV Generator            --> For Modes Encryption/Decryption

#   - Providing a Client UI
#       - Option for viewing Bank information, Adding functions, Taking out Funds, sending Funds to Friend

if __name__ == '__main__':

    print("Setting Up Database")

    try:
        client = pymongo.MongoClient(conn_str)

    except Exception:
        print("Error: " + Exception)

    bank_database = client["bank_of_america_database"]
    user_information_table = bank_database["user_information"]
    salt = urlsafe_b64encode(os.urandom(16))

    print(f"Random Salt: {salt}")

    print("Welcome to the mongo python database tester!")
   
    loop = True
    while loop:
        print("\nWhat would you like to do?")
        print("Enter one of the following options:")
        print("1 - Add a user!")
        print("2 - Add/Remove funds to an account!")
        print("3 - Retrieve all user Data")
        user_input = input("4 Exit the application\n\nEnter Here: ")

        if user_input == "1":
            if add_user_to_database(salt) == 1:
                print("User Added Successfully!")
            else:
                print("Err: User not added!")

        elif user_input == "2":
            modify_user_savings(salt)

        elif user_input == "3":
            pull_user_data()

        elif user_input == "4":
            print("Exiting Mongo Python Tester - Thanks for playing!\n")
            loop = False
            
        else:
            user_input = input("Incorrect Input, try again\n")
    
    print("Thats all folks! :)")    

