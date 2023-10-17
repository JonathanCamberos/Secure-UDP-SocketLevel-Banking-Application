
import pymongo 
import uuid
import os
import secrets

from pymongo.errors import DuplicateKeyError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode


conn_str = "mongodb+srv://jcambero:jcambero@cluster0.nkjnjyb.mongodb.net/"
bank_database = ''
user_information_table = ''


# def hash_password(password, salt):
def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,  # Choose an appropriate number of iterations
        length=32  # Length of the derived key
    )
    hashed_password = kdf.derive(password.encode('utf-8'))
    return hashed_password

def generate_unique_id():
    return str(uuid.uuid4())

def user_exists(username):
    return user_information_table.find_one({'username': username}) is not None

def convert_to_integer(s):
    try:
        return int(s)
    except ValueError:
        print(f"Error: Unable to convert '{s}' to an integer.")
        return None





def add_user_to_database():

    input_username = input("\nSelect a username:\nEnter Here: ")
    input_password = input("\nChoose a password:\nEnter Here: ")
    
    salt = secrets.token_bytes(16)  # Generate a random 16-byte salt
    print(f"Random Salt: {salt}")
    
    hashed_input_password = hash_password(input_password, salt)

    print(f"Plaintext Password: {input_password}")
    print(f"Hashed Password: {hashed_input_password}")

    input_savings = input("\nAmount of Savings\nEnter Here: ")
    input_savings = convert_to_integer(input_savings)

    if input_savings == None:
        print("Error: 'savings' must be an integer.")
        return

    # Validate - User Already Exists
    if user_exists(input_username):
        print(f"\nUser with username '{input_username}' already exists in the database.")
        return 2

    # Generate Unique Id
    unique_id = generate_unique_id()

    # Create a user document
    new_user = {
        '_id': unique_id,
        'username': input_username,
        'plaintext password': input_password,
        'hashed password': hashed_input_password,
        'salt': salt,
        'savings': input_savings
    }

    # Try - Add user to MongoDB
    try:
        user_information_table.insert_one(new_user)
    except DuplicateKeyError as e:
        print(f"Error: {e}")
        return 2

    return 1

def get_salt(username):
    user_data = user_information_table.find_one({'username': username})
    if user_data:
        return user_data.get('salt', '')
    return None

def get_hashed_password(username):
    user_data = user_information_table.find_one({'username': username})
    if user_data:
        return user_data.get('hashed password', '')
    return None

def get_savings(username):
    user_data = user_information_table.find_one({'username': username})
    if user_data:
        return user_data.get('savings', '')
    return None

# Function to update user's savings based on the username
def update_savings(username, new_savings):
    result = user_information_table.update_one({'username': username}, {'$set': {'savings': new_savings}})
    if result.modified_count > 0:
        print(f"Savings for {username} updated to {new_savings}.")
    else:
        print(f"User {username} not found.")


def verify_password(username, entered_password, salt):
    # Hash the entered password with the stored salt
    stored_hashed_password = get_hashed_password(username)
    entered_password_hashed = hash_password(entered_password, salt)


    print(f"Stored Hashed Password: {stored_hashed_password}\n")
    print(f"Input password: {entered_password}0")
    print(f"Calculated Hashed Password: {entered_password_hashed}")

    # Compare the entered password hash with the stored hash
    return entered_password_hashed == stored_hashed_password

def verify_transaction(username, type, amount):

    if type == 1:
        return True
    elif type == 2:
        current_savings = get_savings(username)
        res = current_savings - amount
        if res > 0:
            return True
        else:
            False
    else:
        print("bad transaction type")
        return

    

def proceed_transation(username, type, transaction_amount):

    current_savings = ''
    new_savings = ''

    if type == 1:
        current_savings = get_savings(username)
        c = current_savings + transaction_amount
        update_savings(username, new_savings)

        return True
    
    elif type == 2:
        
        current_savings = get_savings(username)
        new_savings = current_savings - transaction_amount
        update_savings(username, new_savings)
        return True
    else:
        print("bad transaction type")
        return


def verified_modification_user(username):
    
    print("Logged In Successfully!")
    print(f"Welcome: {username}")

    loop = True
    while loop:
    
        print("\nWhat would you like to do?")
        print("Enter one of the following options:")
        print("1 - Add Funds")
        print("2 - Remove Funds")
        print("3 - Send Money to User")
        user_input = input("Exit - Exit the application\n\nEnter Here: ")

        if user_input == "1":
            transaction_amount = input("Enter Amount to Add to Account\n\nEnter Here: ")            
            

            transaction_amount = convert_to_integer(transaction_amount)

            if transaction_amount == None:
                print("Error: 'savings' must be an integer.")
                return

            
            if verify_transaction(username, 1, transaction_amount):
                print(f"Adding {transaction_amount} is possible")
                print(f"Proceeding!")
                proceed_transation(username, 1, transaction_amount)
            else:
                print(f"Adding {transaction_amount} is not possible")
                print(f"Have a good day!\n")
        elif user_input == "2":
            modify_user_savings()

        elif user_input == "3":
            remove_user()

        elif user_input == "4":
            pull_user_data()

        elif user_input == "Exit":
            print("Exiting Mongo Python Tester - Thanks for playing!\n")
            loop = False
            
        else:
            user_input = input("Incorrect Input, try again\n")

    
    return

def modify_user_savings():

    print("Please Login:\n")
    input_username = input("\nUsername:\nEnter Here: ")
    
    user_salt = get_salt(input_username)

    print(f"\nUser {input_username} has salt: {user_salt}\n")

    
    input_password = input("\nPassword:\nEnter Here:")



    if verify_password(input_username, input_password, user_salt) == True:
        print("Successfully Logged In\n")

        verified_modification_user(input_username)
    else:
        print("Incorrect Username or Password\n")
        return 2
    
    # input_savings = input("\nAmount of money input\nEnter Here: ")
    # input_savings = convert_to_integer(input_savings)

    # input_password = input("\nChoose a password:\nEnter Here: ")
    # input_password = hash_password(input_password, salt)

    #  # Validate - User Already Exists
    # if user_exists(user_information_table, input_username):
    #     print(f"\nUser with username '{input_username}' already exists in the database.")
    #     return 2

    # # Validate - Input Savings is an Int
    # if not isinstance(input_savings, int):
    #     print("Error: 'savings' must be an integer.")
    #     return 2

    # # Generate Unique Id
    # unique_id = generate_unique_id()

    # # Create a user document
    # new_user = {
    #     '_id': unique_id,
    #     'name': input_username,
    #     'password': input_password,
    #     'savings': input_savings
    # }

    # # Try - Add user to MongoDB
    # try:
    #     return_id = user_information_table.insert_one(new_user)
    #     if return_id == unique_id:
    #         print("User added correctly!")
    #     else:
    #         print("User NOT added: errorr")
    # except DuplicateKeyError as e:
    #     print(f"Error: {e}")
    #     return 2

    return 1

# Function to remove a user based on username
def remove_user():

    input_username = input("\nUsername:\nEnter Here: ")

    result = user_information_table.delete_one({'username': input_username})
    if result.deleted_count > 0:
        print(f"User {input_username} successfully removed.")
    else:
        print(f"User {input_username} not found.")

def pull_user_data():

    input_username = input("\nUsername:\nEnter Here: ")

    # Query the database for all users with the given username
    user_documents = user_information_table.find({'username': input_username}, {'_id': 0})


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

    print("Welcome to the mongo python database tester!")
   
    loop = True
    while loop:
        print("\nWhat would you like to do?")
        print("Enter one of the following options:")
        print("1 - Add a user!")
        print("2 - Add/Remove funds to an account!")
        print("3 - Remove User")
        print("4 - Retrieve all user Data")
        user_input = input("Exit - Exit the application\n\nEnter Here: ")

        if user_input == "1":
            if add_user_to_database() == 1:
                print("User Added Successfully!")
            else:
                print("Err: User not added!")

        elif user_input == "2":
            modify_user_savings()

        elif user_input == "3":
            remove_user()

        elif user_input == "4":
            pull_user_data()

        elif user_input == "Exit":
            print("Exiting Mongo Python Tester - Thanks for playing!\n")
            loop = False
            
        else:
            user_input = input("Incorrect Input, try again\n")
    
    print("Thats all folks! :)")    

