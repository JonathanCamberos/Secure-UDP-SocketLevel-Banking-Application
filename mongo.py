
import pymongo 
import uuid
import secrets
import time

from pymongo.errors import DuplicateKeyError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

conn_str = "mongodb+srv://jcambero:jcambero@cluster0.nkjnjyb.mongodb.net/"
bank_database = ''
user_information_table = ''



# HEllooooo
# this is mainly for manual testing of the database
# the actual file we will use will be
# DatabaseBank.py






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

        raw_user_savings = user_data.get('savings', '')
        int_user_savings = convert_to_integer(raw_user_savings)
        print(f"Grabbed Raw Savings: {raw_user_savings}")
        print(f"translated to Int Savings: {int_user_savings}")
        
        return int_user_savings
    return None

# Function to update user's savings based on the username
def update_savings(username, new_savings):
    result = user_information_table.update_one({'username': username}, {'$set': {'savings': new_savings}})
    if result.modified_count > 0:
        print(f"Savings for {username} updated to {new_savings}")
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
        if res >= 0:
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
        new_savings = current_savings + transaction_amount
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
    
    print(f"Welcome: {username}")
    

    loop = True
    while loop:
        current_savings = get_savings(username)
        print(f"\nCurrently you have: {current_savings}\n")

        print("What would you like to do?")
        print("Enter one of the following options:")
        print("1 - Add Funds")
        print("2 - Remove Funds")
        user_input = input("Exit - Exit the application\n\nEnter Here: ")

        if user_input == "1":
            transaction_amount = input("Enter Amount to Add to Account\n\nEnter Here: ")            
            transaction_amount = convert_to_integer(transaction_amount)

            # None is err returned from convert_to_integer function on err
            if transaction_amount == None:
                print("Error: 'savings' must be an integer.")
                return

            # checks if enough funds for transaction
            if verify_transaction(username, 1, transaction_amount):

                print(f"Adding {transaction_amount} is possible")
                print(f"Proceeding!")
                proceed_transation(username, 1, transaction_amount)
            
            else:
                print(f"Adding {transaction_amount} is not possible")
                print(f"Have a good day!\n")
        
        elif user_input == "2":
            transaction_amount = input("Enter Amount to Subtract from Account\n\nEnter Here: ")            
            transaction_amount = convert_to_integer(transaction_amount)

            if transaction_amount == None:
                print("Error: 'savings' must be an integer.")
                return

            if verify_transaction(username, 2, transaction_amount):
                print(f"Subtracting {transaction_amount} is possible")
                print(f"Proceeding!")
                proceed_transation(username, 2, transaction_amount)

            else:
                print(f"Subtracting {transaction_amount} is not possible")
                print(f"Have a good day!\n")

        elif user_input == "Exit":
            print("Exiting Mongo Python Tester - Thanks for playing!\n")
            loop = False
            
        else:
            user_input = input("Incorrect Input, try again\n")

    return

def modify_user_savings():

    print("Please Login:\n")
    input_username = input("\nUsername:\nEnter Here: ")

    if login_verification(input_username) == True:
        verified_modification_user(input_username)
    else:
        return

def login_verification(username):
    
    user_salt = get_salt(username)

    print(f"\nUser {username} has salt: {user_salt}\n")

    input_password = input("\nPassword:\nEnter Here:")

    if verify_password(username, input_password, user_salt) == True:
        print("Successfully Logged In\n")
        return True
    else:
        print("Incorrect Username or Password\n")
        return False
    

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


# simple send money function
def send_money_to_user():
    return

# probably will need to be some sort of json object, with an amount requested and username from
# each user can have a list of reqests and "finished them" in order
def request_money_from_user():
    return


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
        print("5 - Send Funds to another user")
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
        
        elif user_input == "5":
            send_money_to_user()

        elif user_input == "Exit":
            print("Exiting Mongo Python Tester - Thanks for playing!\n")
            loop = False
            
        else:
            user_input = input("Incorrect Input, try again\n")
    
    print("Thats all folks! :)")    

