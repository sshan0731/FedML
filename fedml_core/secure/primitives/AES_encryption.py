# use "pip install pycryptodomex" to install this package instead of "pip install pycryptodome"
import secrets
from Cryptodome.Cipher import AES
from binascii import unhexlify


def create_AES_encrypter(key, mode):
    """MODE_ECB:	Electronic Code Book (ECB)
    MODE_CBC:	    Cipher-Block Chaining (CBC)
    MODE_CFB:	    Cipher FeedBack (CFB)
    MODE_OFB:	    Output FeedBack (OFB)
    MODE_CTR:	    CounTer Mode (CTR)
    MODE_OPENPGP:   OpenPGP Mode
    MODE_CCM:	    Counter with CBC-MAC (CCM) Mode
    MODE_EAX:	    EAX Mode
    MODE_GCM:	    Galois Counter Mode (GCM)
    MODE_SIV:	    Syntethic Initialization Vector (SIV)
    MODE_OCB:       Offset Code Book (OCB)"""

    encrypter = AES.new(key, mode)
    return encrypter, encrypter.nonce


def encrypt(encrypter, plaintext):
    return encrypter.encrypt_and_digest(plaintext)  # return cipertext and tag


def ctr_mode_encrypt(encrypter, plaintext):
    return encrypter.encrypt(plaintext)

def create_AES_decrypter(key, mode, nonce):
    decrypter = AES.new(key, mode, nonce=nonce)
    return decrypter


def decrypt(decrypter, ciphertext):
    plaintext = decrypter.decrypt(ciphertext)
    return plaintext


def verify(encrypter, tag):
    encrypter.verify(tag)


if __name__ == '__main__':
    key = secrets.token_bytes(16)  # for AES-GCM with 128 bit keys
    key = unhexlify('d1b85afec2794f9673a08f8965b47e6a3a1ae1218cc803690de5e19f3963c464')
    # encrypt
    mode = AES.MODE_GCM
    encrypter, nonce = create_AES_encrypter(key, mode)
    data = '1 3 199440227064449254913935221915006528141 118437970611692378107116866343157382145'
    ciphertext, tag = encrypt(encrypter, data.encode('utf-8'))
    print(ciphertext)
    decrypter = create_AES_decrypter(key, mode, nonce)
    plaintext = decrypt(decrypter, ciphertext)
    print(plaintext)

    assert plaintext.decode() == data
    try:
        verify(decrypter, tag)
        print("The message is authentic:", plaintext)
    except ValueError:
        print("Key incorrect or message corrupted")
