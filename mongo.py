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

