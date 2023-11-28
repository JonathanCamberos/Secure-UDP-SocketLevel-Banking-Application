# import pymongo 
import datetime
import OpenSSL
from OpenSSL import crypto

from cryptography import x509

from datetime import datetime as dt

from cryptography.x509.oid import NameOID
    
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa




# conn_str = "mongodb+srv://jcambero:jcambero@cluster0.nkjnjyb.mongodb.net/"
# certificate_database = ''
# user_certificates_table = ''


# def user_exists(username):
#     return user_certificates_table.find_one({'username': username}) is not None


# def add_certificate_to_database():

#     input_username = input("\nSelect a username:\nEnter Here: ")

#     # Validate - User Already Exists
#     if user_exists(input_username):
#         print(f"\nUser with username '{input_username}' already exists in the database.")
#         return 2

#     # Create a certificate
#     new_user = {
#         'username': input_username,
#     }

#     # Try - Add user to MongoDB
#     try:
#         user_certificates_table.insert_one(new_user)
#     except DuplicateKeyError as e:
#         print(f"Error: {e}")
#         return 2

#     return 1



if __name__ == '__main__':

    # print("Setting Up Database")

    # try:
    #     client = pymongo.MongoClient(conn_str)

    # except Exception:
    #     print("Error: " + Exception)

    # certificate_database = client["certificate_server_database"]
    # user_certificates_table = certificate_database["user_certificates"]
 
    # print("Mongo python database Setup!")

    # # add_certificate_to_database()

    # # pull_user_data("user")
    # Mongo_util.pull_user_data("user", user_certificates_table)

    # one_day = datetime.timedelta(1, 0, 0)

    # private_key = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048,
    # )
    # public_key = private_key.public_key()

    # print("Public Key:")
    # print(public_key)

    # print("\nPrivate Key")
    # print(private_key)

    # print("Creating Certificate ##############################################################################")

    # builder = x509.CertificateBuilder()
    # builder = builder.subject_name(x509.Name([
    #     x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
    # ]))

    # builder = builder.issuer_name(x509.Name([
    #     x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
    # ]))

    # builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    # builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    # builder = builder.serial_number(x509.random_serial_number())
    # builder = builder.public_key(public_key)
    # builder = builder.add_extension(

    #     x509.SubjectAlternativeName(
    #         [x509.DNSName(u'cryptography.io')]
    #     ),

    #     critical=False
    # )

    # builder = builder.add_extension(
    #     x509.BasicConstraints(ca=False, path_length=None), critical=True,
    # )

    # certificate = builder.sign(
    #     private_key=private_key, algorithm=hashes.SHA256(),
    # )

    # res = isinstance(certificate, x509.Certificate)
    # print("\n")
    # print(res)

    # print("\nCertificate Version")
    # ves = certificate.version
    # print(ves)

    # print("\nPublic Key:")
    # public_key = certificate.public_key()
    # print(public_key)

    # print("\nNot Valid before:")
    # res = certificate.not_valid_before
    # print(res)

    # print("\nNot Valid After:")
    # res2 = certificate.not_valid_after
    # print(res2)

    # print("\nSerial Number:")
    # res3 = certificate.serial_number
    # print(res3)
    

    # print("\nFingerprint:")
    # res4 = certificate.fingerprint(hashes.SHA256())
    # print(res4)

    # print("\nExtensions:")
    # for ext in certificate.extensions:
    #     print(ext)



    # print("Generating a CSR (Certificate Request) ###################################################################")

    # # Generate our key

    # key = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048,
    # )

    # # Write our key to disk for safe keeping
    # # with open("path/to/store/key.pem", "wb") as f:
        
    # #     f.write(key.private_bytes(
    # #         encoding=serialization.Encoding.PEM,
    # #         format=serialization.PrivateFormat.TraditionalOpenSSL,
    # #         encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    # #     ))

    # # Generate a CSR
    # csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    #     # Provide various details about who we are.
    #     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    #     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    #     x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    #     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    #     x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    # ])).add_extension(

    #     x509.SubjectAlternativeName([
    #         # Describe what sites we want this certificate for.
    #         x509.DNSName(u"mysite.com"),
    #         x509.DNSName(u"www.mysite.com"),
    #         x509.DNSName(u"subdomain.mysite.com"),
    #     ]),
    #     critical=False,
    # # Sign the CSR with our private key.
    # ).sign(key, hashes.SHA256())

    # print("\nCSR:")
    # print(csr)

    # # Write our CSR out to disk.

    # # with open("path/to/csr.pem", "wb") as f:

    # #     f.write(csr.public_bytes(serialization.Encoding.PEM))


    print("Generating a Self-Signed Certificate ###################################################################")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Write our key to disk for safe keeping
    # with open("path/to/store/key.pem", "wb") as f:
    #     f.write(key.private_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PrivateFormat.TraditionalOpenSSL,
    #         encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    #     ))

    # Various details about who we are. For a self-signed certificate the

# subject and issuer are always the same.

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])

    self_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    # Sign our certificate with our private key
    ).sign(key, hashes.SHA256())

    # Write our certificate out to disk.
    # with open("path/to/certificate.pem", "wb") as f:
    #     f.write(cert.public_bytes(serialization.Encoding.PEM))



    # Creating a self signed certificate
    print("\nSelf Signed Cert:")
    print(self_cert)


    print("\nCertificate Issuer:")
    print(self_cert.issuer)
    
    print("Certificate Subject:")
    print(self_cert.subject)

    # Validate the certificate chain (for a self-signed certificate, it's its own issuer)
    if self_cert.issuer != self_cert.subject:
        print("Certificate chain validation failed")
    else:
        print("Certificate Passed issue-er test")


    print("\nCertificate Start Time:")
    print(self_cert.not_valid_before)

    print("Certificate End Time")
    print(self_cert.not_valid_after)
    
    print("Time Now")
    print(dt.now())

    # Check the certificate's validity period
    current_time = dt.now()
    if not self_cert.not_valid_before <= current_time <= self_cert.not_valid_after:
        print("Certificate time has expired")
    else:
        print("Ceritifcate Time is still valid")

    print("Certificate is valid.")


  
    
    # Validating Certificate Type
    self_cert_public_key = self_cert.public_key()
    
    print("\nValidate the Certificate ###############")
    res = isinstance(self_cert_public_key, rsa.RSAPublicKey)
    print(res)
    self_cert_serial_number = self_cert.serial_number
    print("Serial Number:")
    print(self_cert_serial_number)


    # turning certificate into bytes so we can transmite over sockets
    print("\nPrinting Original Certificate @@@@@@@@@@")
    print(self_cert)

    #print original bytes
    print("\nCertificate in Bytes")
    bytes_pem = self_cert.public_bytes(encoding=serialization.Encoding.PEM)
    print(bytes_pem)

    print("Length of certificate in bytes: ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
    print(len(bytes_pem))

    

    # printing with decoding
    # print("\nDecoding the certificate\n")
    # decoded = bytes_pem.decode('utf8')
    # print(decoded)


    
    # Grabbing certificate bytes and reloading into a certificate
    print("\nDecoding Bytes to Certificate:\n")
    new_self_cert = x509.load_pem_x509_certificate(bytes_pem)

    # First result
    print("\nNew Certificate Result --------------->")
    print(new_self_cert)

    new_self_cert_public_key = new_self_cert.public_key()

    print("\nThe Beates: Validate New Certificate ###############")
    new_res = isinstance(new_self_cert_public_key, rsa.RSAPublicKey)
    print(new_res)

    new_self_cert_serial_number = new_self_cert.serial_number
    print("Serial Number:")
    print(new_self_cert_serial_number)

    #print original bytes
    print("\nNew Certificate in Bytes")
    new_bytes_pem = new_self_cert.public_bytes(encoding=serialization.Encoding.PEM)
    print(new_bytes_pem)

    print("Length of new certificate in bytes: !!!!!!!!!!!!!!!!")
    print(len(new_bytes_pem))

    # crl_2 = x509.load_pem_x509_crl(pem)
    # pem_2 = crl_2.public_bytes(encoding=serialization.Encoding.PEM) # Check
    
    # #Printing New Certificate Original
    # print("\n Original New Certificate\n")
    # print(pem_2)

    # Printing New Certificate Decoded
    # print("\n New Certificate Decoded \n")
    # print(pem_2.decode('utf8')) 