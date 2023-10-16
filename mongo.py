import pymongo 
from pymongo.errors import DuplicateKeyError


conn_str = "mongodb+srv://jcambero:jcambero@cluster0.nkjnjyb.mongodb.net/"

try:
    client = pymongo.MongoClient(conn_str)

except Exception:
    print("Error: " + Exception)


bank_database = client["bank_of_america_database"]

print(client.list_database_names())

user_information_table = bank_database["user_information"]

user_info = {
    "_id": 1,
    "name": "Steve",
    "message": "This is my will"
}

try:
    user_information_table.insert_one(user_info)
except DuplicateKeyError as e:
    print(f"Error: {e}")

print(client.list_database_names())


def add_user_to_database():

    input_username = input("Select a username:\n\nEnter Here: ")
    return 1


def add_funds_to_user():
    return 1


# Hello! This is the main code for the Client
# This section of the Banking Application will be in charge of:
#   - Starting communications to the Bank Server
#       - Diffie-Hellman exchange --> Shared_secret
#       - IV Generator            --> For Modes Encryption/Decryption

#   - Providing a Client UI
#       - Option for viewing Bank information, Adding functions, Taking out Funds, sending Funds to Friend

if __name__ == '__main__':

    print("Welcome to the mongo python database tester!")
   
    loop = True
    while loop:
        print("\nWhat would you like to do?")
        print("Enter one of the following options:")
        print("1 - Add a user!")
        print("2 - Add funds to an account!")
        user_input = input("3 Exit the application\n\nEnter Here: ")

        if user_input == "1":
            add_user_to_database()

        elif user_input == "2":
            add_funds_to_user()

        elif user_input == "3":
            print("Exiting Mongo Python Tester - Thanks for playing!\n")
            loop = False
            
        else:
            user_input = input("Incorrect Input, try again\n")
    
    print("Thats all folks! :)")    

