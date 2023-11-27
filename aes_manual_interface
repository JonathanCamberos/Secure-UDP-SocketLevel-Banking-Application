from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key


if __name__ == '__main__':


    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048, 
    )

    print("Private RSA Key:")
    print(private_key)


    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("\nPublic Key")
    print(public_key)

    print("\nPublic Keys in Bytes")
    print(public_key_bytes)

   
    new_public_key = load_der_public_key(public_key_bytes)

    print("\nNew public key")
    print(new_public_key)