import pymongo 

conn_str = "mongodb+srv://jcambero:jcambero@cluster0.nkjnjyb.mongodb.net/"

try:
    client = pymongo.MongoClient(conn_str)

except Exception:
    print("Error: " + Exception)


myDb = client["pymongo_demo"]

print(client.list_database_names())

myCollection = myDb["demo_collection"]

myDoc = {
    "name": "Steve",
    "message": "This is pymongo demo"
}

myCollection.insert_one(myDoc)

print(client.list_database_names())

