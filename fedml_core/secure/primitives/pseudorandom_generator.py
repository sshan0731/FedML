import secrets
# use "pip install pycryptodomex" to install this package instead of "pip install pycryptodome"
from Cryptodome.Cipher import AES
from base64 import b64encode
import fedml_core.secure.primitives.AES_encryption as fedml_AES


def random_bytes(n=None):
    """Return a random byte string containing *n* bytes.
       default: 16
    """
    return secrets.token_bytes(n)


def aes_random(plaintext_data):
    key = random_bytes(16)
    encrypter, nonce = fedml_AES.create_AES_encrypter(key, AES.MODE_CTR)
    ciphertext = fedml_AES.ctr_mode_encrypt(encrypter, plaintext_data)
    num = b64encode(ciphertext).decode('utf-8')
    return num


if __name__ == '__main__':
    print(random_bytes(16))
    data = b'pseudorandom generator - aes encryption test'
    print(aes_random(data))
