# import sys
# sys.path.append('./Fed_Secure/FedML')

from fedml_core.secure.primitives.key_agreement import DiffieHellman

def test_pydh_keygen():
    d1 = DiffieHellman()
    d2 = DiffieHellman()
    d1_pubkey = d1.gen_public_key()
    d2_pubkey = d2.gen_public_key()
    d1_sharedkey = d1.gen_shared_key(d2_pubkey)
    d2_sharedkey = d2.gen_shared_key(d1_pubkey)
    assert d1_sharedkey == d2_sharedkey

if __name__ == '__main__':
    test_pydh_keygen()
