#!/usr/bin/python3

from key_store import KeyStore


if __name__ == '__main__':
    # ps = "00000000"
    # key_store = KeyStore()
    # s, p = KeyPair().get_key()
    # sa = binascii.b2a_hex(secrets.token_bytes(32))
    # v = binascii.b2a_hex(secrets.token_bytes(16))
    # argon2id = Argon2Manager().hash(ps.encode(), sa, TIMECOST, MEMORYCOST, PARALLELIS)
    # address = KeystoreUtils().pubkey_to_address(p)
    # aes = AesManager().encrypt_data(binascii.a2b_hex(s), binascii.a2b_hex(argon2id), binascii.a2b_hex(v))
    # mac = binascii.b2a_hex(Sha3Keccack().calculate_hash(argon2id + aes)).decode()
    # key_store.address = address
    # key_store.crypto = Crypto(CIPHER, aes.decode(), v.decode()).__dict__
    # key_store.id = Utils.generate_uuid()
    # key_store.mac = mac
    # key_store.kdf_params = KdfParams(MEMORYCOST, TIMECOST, PARALLELIS, v.decode()).__dict__
    # print('adress:' + address)
    # print(b'argon2id:' + argon2id)
    # print('aes:' + aes.decode())
    # print('mac:' + mac)
    # print(json.dumps(key_store.__dict__))
    print(KeyStore.from_password("00000000").as_dict())
