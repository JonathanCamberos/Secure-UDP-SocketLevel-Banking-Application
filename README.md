# UDP-Socket-Banking-Application
Kinda like payall :)


To use - Have 2 Ubuntu Terminals Open (or any termial) and run the following in this order:

  1. python3 ServerBank.py
  2. python3 ClientBank.py

The result should be the Client talks to the Server, they exchange a secret key via diffie-hellmen,
and the client sends an ecrypted message using AES and HMAC and the server Decrypts the message and verifies the HMAC
