# UDP-Socket-Banking-Application
Kinda like payall :)


To use - Have 2 Ubuntu Terminals Open (or any terminal) 

You will need to create a Python Virtual Environment
Run the following: 

  1. Install the vritualenv package
     pip install virtualenv

  2. Create a virtual enviornment (venv) directory
      python<version> -m venv <virtual-environment-name>
      for me it was just --> 'python3 -m venv venv'

  3. Activate/Turn On the Virtual Environment
     From the your current directory:
     source venv/bin/activate

To run the Server/Client, run 1. in the first terminal, run 2. in the second terminal      

  1. python3 ServerBank.py
  2. python3 ClientBank.py

The result should be the Client talks to the Server, they exchange a secret key via diffie-hellmen,
and the client sends an ecrypted message using AES and HMAC and the server Decrypts the message and verifies the HMAC
