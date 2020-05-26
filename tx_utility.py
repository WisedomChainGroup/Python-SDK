#!/usr/bin/python3

from utils import Utils
import nacl.signing
import rlp


GAS_TABLE = [0, 50000, 100000, 20000]
FEE = 200000
TYPE_DICT = {
                "TRANSFER": 1,
                "TRANSFER_VOTE": 2,
                "TRANSFER_VOTE_WITH": 13,
                "TRANSFER_MORTGAGE": 14,
                "TRANSFER_MORTGAGE_WITH": 15,
                "TRANSFER_PROVE": 3,
                "DEPLOY_FOR_RULE_ASSET": 7,
                "TRANSFER_CALL_FOR_RULE_ASSET_CHANGE_OWNER": 8,
                "TRANSFER_CALL_FOR_RULE_ASSET_INCREASED": 8,
                "TRANSFER_DEPLOY_FOR_RULE_ASSET": 8,
                "MULTIPLE_FOR_RULE_FIRST": 7,
                "MULTIPLE_FOR_RULE_SPLICE": 7,
                "MULTI_SIGNATURE_FOR_FIRST": 8,
                "HASH_TIME_BLOCK_FOR_DEPLOY": 7,
                "HASH_TIME_BLOCK_GET_FOR_DEPLOY": 8,
                "HASH_TIME_BLOCK_TRANSFER_FOR_DEPLOY": 8,
                "HASH_HEIGHT_BLOCK_FOR_DEPLOY": 7,
                "HASH_HEIGHT_BLOCK_GET_FOR_DEPLOY": 8,
                "HASH_HEIGHT_BLOCK_TRANSFER_FOR_DEPLOY": 8,
            }
TYPE_LIST_ZERO = ["TRANSFER", "TRANSFER_VOTE", "TRANSFER_VOTE_WITH", "TRANSFER_MORTGAGE", "TRANSFER_MORTGAGE_WITH", "TRANSFER_PROVE"]
TYPE_LIST_ONE = ["DEPLOY_FOR_RULE_ASSET", "TRANSFER_CALL_FOR_RULE_ASSET_CHANGE_OWNER"]
TYPE_LIST_TWO = ["TRANSFER_CALL_FOR_RULE_ASSET_INCREASED", "TRANSFER_DEPLOY_FOR_RULE_ASSET", "MULTIPLE_FOR_RULE_FIRST", "MULTIPLE_FOR_RULE_SPLICE"]
TYPE_LIST_THREE = ["HASH_TIME_BLOCK_FOR_DEPLOY"]
TYPE_LIST_FOUR = ["MULTI_SIGNATURE_FOR_FIRST", "HASH_HEIGHT_BLOCK_FOR_DEPLOY"]
TYPE_LIST_FIVE = ["HASH_TIME_BLOCK_TRANSFER_FOR_DEPLOY"]
TYPE_LIST_SIX = ["HASH_TIME_BLOCK_GET_FOR_DEPLOY"]
TYPE_LIST_SEVEN = ["HASH_HEIGHT_BLOCK_TRANSFER_FOR_DEPLOY"]
TYPE_LIST_EIGHT = ["HASH_HEIGHT_BLOCK_GET_FOR_DEPLOY"]
DEFAULT_VERSION = 1


class Multiple:
    def __init__(self, m_asset_hash: bytes = b'', m_max: int = 0, m_min: int = 0, m_pub_list=[],
                 m_signatures=[], m_pubkey_hash_list=[]):
        self.m_asset_hash = m_asset_hash
        self.m_max = m_max
        self.m_min = m_min
        self.m_pub_list = m_pub_list
        self.m_signatures = m_signatures
        self.m_pubkey_hash_list = m_pubkey_hash_list


class MultipleTransfer:
    def __init__(self, mt_origin: int = 0, mt_dest: int = 0, mt_from=[], mt_signatures=[],
                 mt_to: bytes = b'', mt_value: int = 0, mt_pubkey_hash_list=[]):
        self.mt_origin = mt_origin
        self.mt_dest = mt_dest
        self.mt_from = mt_from
        self.mt_signatures = mt_signatures
        self.mt_to = mt_to
        self.mt_value = mt_value
        self.mt_pubkey_hash_list = mt_pubkey_hash_list


class Asset:
    def __init__(self, at_code: str = '', at_offering: int = 0, at_total_amount: int = 0, at_create_user: bytes = b'',
                 at_owner: bytes = b'', at_allow_increase: int = 0, at_info: bytes = b''):
        self.at_code = at_code
        self.at_offering = at_offering
        self.at_total_amount = at_total_amount
        self.at_create_user = at_create_user
        self.at_owner = at_owner
        self.at_allow_increase = at_allow_increase
        self.at_info = at_info

    def _get_list(self) -> []:
        at_code_encode = self.at_code.encode()
        at_offering_encode = Utils.encode_u8(self.at_offering)
        at_total_amount_encode = Utils.encode_u8(self.at_total_amount)
        at_allow_increase_encode = Utils.encode_u8(self.at_allow_increase)
        ret = [at_code_encode, at_offering_encode, at_total_amount_encode, self.at_create_user, self.at_owner, at_allow_increase_encode, self.at_info]
        return ret

    @classmethod
    def _from_list(cls, d: []):
        ret = cls()
        ret.at_code = d[0].decode()
        ret.at_offering = Utils.decode_u32(d[1])
        ret.at_total_amount = Utils.decode_u32(d[2])
        ret.at_create_user = d[3].decode()
        ret.at_owner = d[4].decode()
        ret.at_allow_increase = Utils.decode_u32(d[5])
        ret.at_info = d[6].decode()
        return ret

    def rlp_encode(self) -> bytes:
        return rlp.encode(self._get_list())

    def rlp_decode(self, b: bytes):
        data = rlp.decode(b)
        ret = self._from_list(data)
        return ret


class Transaction:
    def __init__(self, tx_from: bytes = b'', gas_price: int = 0, version: int = DEFAULT_VERSION, tx_type: str = "",
                 tx_nonce: int = 0, tx_amount: int = 0, payload: bytes = b'', tx_to: bytes = b'', sig: bytes = b''):
        self.version = version
        self.tx_type = tx_type
        self.tx_nonce = tx_nonce
        self.tx_from = tx_from
        self.gas_price = gas_price
        self.version = version
        self.tx_amount = tx_amount
        self.payload = payload
        self.tx_to = tx_to
        self.sig = sig

    def _get_raw(self, null_sig: bool) -> bytes:
        sig = bytes(64)
        if not null_sig:
            sig = self.sig
        ret = Utils.encode_u8(self.version)
        ret += Utils.encode_u8(TYPE_DICT[self.tx_type])
        ret += Utils.encode_u64(self.tx_nonce)
        ret += self.tx_from
        ret += Utils.encode_u64(self.gas_price)
        ret += Utils.encode_u64(self.tx_amount)
        ret += sig
        ret += self.tx_to
        if self.tx_type not in TYPE_LIST_ZERO:
            ret += Utils.encode_u32(len(self.payload)+1)
        else:
            ret += Utils.encode_u32(len(self.payload))
        if self.tx_type in TYPE_LIST_ONE:
            ret += bytes(1)
        elif self.tx_type in TYPE_LIST_TWO:
            ret += Utils.encode_u8(1)
        elif self.tx_type in TYPE_LIST_THREE:
            ret += Utils.encode_u8(2)
        elif self.tx_type in TYPE_LIST_FOUR:
            ret += Utils.encode_u8(3)
        elif self.tx_type in TYPE_LIST_FIVE:
            ret += Utils.encode_u8(4)
        elif self.tx_type in TYPE_LIST_SIX:
            ret += Utils.encode_u8(5)
        elif self.tx_type in TYPE_LIST_SEVEN:
            ret += Utils.encode_u8(6)
        elif self.tx_type in TYPE_LIST_EIGHT:
            ret += Utils.encode_u8(7)
        ret += self.payload
        return ret

    def get_raw_for_sign(self) -> bytes:
        return self._get_raw(True)

    def get_raw_for_hash(self) -> bytes:
        return self._get_raw(False)

    def get_hash(self) -> bytes:
        return Utils.keccak256(self.get_raw_for_hash())


class TxUtility:

    @staticmethod
    def sign_transaction(tx: Transaction, sk: bytes):
        tx.sig = nacl.signing.SigningKey(sk).sign(tx.get_raw_for_sign())[0:-len(tx.get_raw_for_sign())]

    @staticmethod
    def create_transfer_tx(tx_from: bytes, tx_to: bytes, tx_amount: int, tx_nonce: int) -> Transaction:
        """
            构造交易事务
            :param tx_from: bytes
            :param tx_to: bytes
            :param tx_amount: bytes
            :param tx_nonce: bytes
            :return: Transaction
        """
        tx = Transaction(
            tx_type="TRANSFER",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_amount=tx_amount
        )
        tx.gas_price = round(FEE / GAS_TABLE[1])
        return tx

    @staticmethod
    def create_transfer_vote_tx(tx_from: bytes, tx_to: bytes, tx_amount: int, tx_nonce: int) -> Transaction:
        """
            构造投票事务
            :param tx_from: bytes
            :param tx_to: bytes
            :param tx_amount: int
            :param tx_nonce: int
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="TRANSFER_VOTE",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_amount=tx_amount
        )
        tx.gas_price = round(FEE / GAS_TABLE[3])
        return tx

    @staticmethod
    def create_transfer_vote_with_tx(tx_from: bytes, tx_to: bytes, tx_amount: int, tx_nonce: int, tx_id: bytes) -> Transaction:
        """
            构造投票撤回事务
            :param tx_from: bytes
            :param tx_to: bytes
            :param tx_amount: int
            :param tx_nonce: int
            :param tx_id: bytes
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="TRANSFER_VOTE_WITH",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_amount=tx_amount,
            payload=tx_id,
        )
        tx.gas_price = round(FEE / GAS_TABLE[3])
        return tx

    @staticmethod
    def create_transfer_mortgage_tx(tx_from: bytes, tx_to: bytes, tx_amount: int, tx_nonce: int) -> Transaction:
        """
            构造抵押事务
            :param tx_from: bytes
            :param tx_to: bytes
            :param tx_amount: int
            :param tx_nonce: int
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="TRANSFER_MORTGAGE",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_amount=tx_amount,
        )
        tx.gas_price = round(FEE / GAS_TABLE[3])
        return tx

    @staticmethod
    def create_transfer_mortgage_with_tx(tx_from: bytes, tx_to: bytes, tx_amount: int, tx_nonce: int, tx_id: bytes) -> Transaction:
        """
            构造抵押撤回事务
            :param tx_from: bytes
            :param tx_to: bytes
            :param tx_amount: int
            :param tx_nonce: int
            :param tx_id: bytes
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="TRANSFER_MORTGAGE_WITH",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_amount=tx_amount,
            payload=tx_id,
        )
        tx.gas_price = round(FEE / GAS_TABLE[3])
        return tx

    @staticmethod
    def create_transfer_prove_tx(tx_from: bytes, tx_payload: bytes, tx_nonce: int) -> Transaction:
        """
            构造存证事务
            :param tx_from: bytes
            :param tx_payload: bytes
            :param tx_nonce: int
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="TRANSFER_PROVE",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
        )
        tx.tx_to = bytes(20)
        tx.payload = tx_payload
        tx.gas_price = round(FEE / GAS_TABLE[2])
        return tx

    @staticmethod
    def create_deploy_for_rule_asset_tx(tx_from: bytes, tx_nonce: int, tx_code: str, tx_offering: int, tx_total_amount: int, tx_create_user: bytes, tx_owner: bytes, tx_allow_increase: int, tx_info: bytes) -> Transaction:
        """
            部署资产定义事务
            :param tx_from: bytes
            :param tx_nonce: int
            :param tx_code: str
            :param tx_offering: int
            :param tx_total_amount: int
            :param tx_create_user: bytes
            :param tx_owner: bytes
            :param tx_allow_increase: int
            :param tx_info: bytes
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="DEPLOY_FOR_RULE_ASSET",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_amount=0
        )
        tx.tx_to = bytes(20)
        at = Asset(
            at_code=tx_code,
            at_offering=tx_offering,
            at_total_amount=tx_total_amount,
            at_create_user=tx_create_user,
            at_owner=tx_owner,
            at_allow_increase=tx_allow_increase,
            at_info=tx_info
        )
        tx.payload = at.rlp_encode()
        tx.gas_price = round(FEE / GAS_TABLE[2])
        return tx

    @staticmethod
    def create_transfer_call_for_rule_asset_change_owner_tx(tx_from: bytes, tx_hash: bytes, tx_nonce: int, tx_new_owner: bytes) -> Transaction:
        """
            构造资产定义的更换所有者事务
            :param tx_from: bytes
            :param tx_hash: bytes
            :param tx_nonce: int
            :param tx_new_owner: bytes
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="TRANSFER_CALL_FOR_RULE_ASSET_CHANGE_OWNER",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_amount=0
        )
        tx.tx_to = Utils.ripmed160(tx_hash)
        tx.payload = rlp.encode(tx_new_owner)
        tx.gas_price = round(FEE / GAS_TABLE[2])
        return tx

    @staticmethod
    def create_transfer_call_for_rule_asset_increased_tx(tx_from: bytes, tx_hash: bytes, tx_nonce: int, tx_amount: int) -> Transaction:
        """
            构造资产定义的增发事务
            :param tx_from: bytes
            :param tx_hash: bytes
            :param tx_nonce: int
            :param tx_amount: int
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="TRANSFER_CALL_FOR_RULE_ASSET_INCREASED",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_amount=0
        )
        tx.tx_to = Utils.ripmed160(tx_hash)
        tx_amount_encode = Utils.encode_u8(tx_amount)
        tx.payload = rlp.encode(tx_amount_encode)
        tx.gas_price = round(FEE / GAS_TABLE[2])
        return tx

    @staticmethod
    def create_transfer_deploy_for_rule_asset_tx(tx_from: bytes, tx_hash: bytes, tx_nonce: int, tx_from_asset: bytes, tx_to_asset: bytes, tx_amount: int) -> Transaction:
        """
            构造资产定义的转账事务
            :param tx_from: bytes
            :param tx_hash: bytes
            :param tx_nonce: int
            :param tx_from_asset: bytes
            :param tx_to_asset: bytes
            :param tx_amount: int
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="TRANSFER_DEPLOY_FOR_RULE_ASSET",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_amount=0
        )
        tx.tx_to = Utils.ripmed160(tx_hash)
        tx_amount_encode = Utils.encode_u8(tx_amount)
        tx_rlp = [tx_from_asset, tx_to_asset, tx_amount_encode]
        tx.payload = rlp.encode(tx_rlp)
        tx.gas_price = round(FEE / GAS_TABLE[2])
        return tx

    @staticmethod
    def create_multiple_for_rule_first_tx(tx_from: bytes, tx_nonce: int, tx_asset_hash: bytes, tx_max: int, tx_min: int, tx_pub_list: [], tx_signatures: [], tx_public_key_hash_list: []) -> Transaction:
        """
            构造签名的多重规则部署（发布者签名）
            :param tx_from: bytes
            :param tx_nonce: int
            :param tx_asset_hash: bytes
            :param tx_max: int
            :param tx_min: int
            :param tx_pub_list: []
            :param tx_signatures: []
            :param tx_public_key_hash_list: []
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="MULTIPLE_FOR_RULE_FIRST",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_amount=0
        )
        tx.tx_to = bytes(20)
        tx_max_encode = Utils.encode_u8(tx_max)
        tx_min_encode = Utils.encode_u8(tx_min)
        tx_rlp = [tx_asset_hash, tx_max_encode, tx_min_encode, tx_pub_list, tx_signatures, tx_public_key_hash_list]
        tx.payload = rlp.encode(tx_rlp)
        tx.gas_price = round(FEE / GAS_TABLE[2])
        return tx

    @staticmethod
    def create_multiple_for_rule_splice_tx(tx_from: bytes, tx_nonce: int, tx_asset_hash: bytes, tx_max: int, tx_min: int, tx_pub_list: [], tx_signatures: [], tx_public_key_hash_list: []) -> Transaction:
        """
            构造多重签名部署（拼接事务）
            :param tx_from: bytes
            :param tx_nonce: int
            :param tx_asset_hash: bytes
            :param tx_max: int
            :param tx_min: int
            :param tx_pub_list: []
            :param tx_signatures: []
            :param tx_public_key_hash_list: []
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="MULTIPLE_FOR_RULE_SPLICE",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_amount=0
        )
        tx.tx_to = bytes(20)
        tx_max_encode = Utils.encode_u8(tx_max)
        tx_min_encode = Utils.encode_u8(tx_min)
        tx_rlp = [tx_asset_hash, tx_max_encode, tx_min_encode, tx_pub_list, tx_signatures, tx_public_key_hash_list]
        tx.payload = rlp.encode(tx_rlp)
        tx.gas_price = round(FEE / GAS_TABLE[2])
        return tx

    @staticmethod
    def create_transfer_multi_signature_for_first_tx(tx_from: bytes, tx_hash: bytes, tx_nonce: int, tx_origin: int, tx_dest: int, tx_from_list: [], tx_signatures: [], tx_to_list: [], tx_amount: int, tx_public_key_hash_list: []) -> Transaction:
        """
            构造多重签名转账（发布者签名）
            :param tx_from: bytes
            :param tx_hash: bytes
            :param tx_nonce: int
            :param tx_origin: int
            :param tx_dest: int
            :param tx_from_list: []
            :param tx_signatures: []
            :param tx_to_list: []
            :param tx_amount: int
            :param tx_public_key_hash_list: []
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="MULTI_SIGNATURE_FOR_FIRST",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_amount=0
        )
        tx.tx_to = Utils.ripmed160(tx_hash)
        tx_origin_encode = Utils.encode_u8(tx_origin)
        tx_dest_encode = Utils.encode_u8(tx_dest)
        tx_amount_encode = Utils.encode_u8(tx_amount)
        tx_rlp = [tx_origin_encode, tx_dest_encode, tx_from_list, tx_signatures, tx_to_list, tx_amount_encode, tx_public_key_hash_list]
        tx.payload = rlp.encode(tx_rlp)
        tx.gas_price = round(FEE / GAS_TABLE[2])
        return tx

    @staticmethod
    def create_hash_time_block_for_deploy_tx(tx_from: bytes, tx_nonce: int,  tx_asset_hash: bytes, tx_public_hash: bytes) -> Transaction:
        """
            构造时间锁定的事务
            :param tx_from: bytes
            :param tx_nonce: int
            :param tx_asset_hash: bytes
            :param tx_public_hash: bytes
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="HASH_TIME_BLOCK_FOR_DEPLOY",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_amount=0
        )
        tx.gas_price = round(FEE / GAS_TABLE[2])
        tx.tx_to = bytes(20)
        tx_rlp = [tx_asset_hash, tx_public_hash]
        tx.payload = rlp.encode(tx_rlp)
        return tx

    @staticmethod
    def create_hash_time_block_get_for_deploy_tx(tx_from: bytes, tx_hash: bytes, tx_nonce: int, tx_transfer_hash: bytes, tx_origin_text: bytes) -> Transaction:
        """
            构造获得锁定资产事务
            :param tx_from: bytes
            :param tx_hash: bytes
            :param tx_nonce: int
            :param tx_transfer_hash: bytes
            :param tx_origin_text: bytes
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="HASH_TIME_BLOCK_GET_FOR_DEPLOY",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_amount=0
        )
        tx.gas_price = round(FEE / GAS_TABLE[2])
        tx.tx_to = Utils.ripmed160(tx_hash)
        tx_rlp = [tx_transfer_hash, tx_origin_text]
        tx.payload = rlp.encode(tx_rlp)
        return tx

    @staticmethod
    def create_hash_time_block_transfer_for_deploy_tx(tx_from: bytes, tx_hash: bytes, tx_nonce: int, tx_amount: int, tx_hash_result: bytes, tx_time_stamp: int) -> Transaction:
        """
            构造时间锁定的转发资产事务
            :param tx_from: bytes
            :param tx_hash: bytes
            :param tx_nonce: int
            :param tx_amount: int
            :param tx_hash_result: bytes
            :param tx_time_stamp: int
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="HASH_TIME_BLOCK_TRANSFER_FOR_DEPLOY",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_amount=0
        )
        tx.gas_price = round(FEE / GAS_TABLE[2])
        tx.tx_to = Utils.ripmed160(tx_hash)
        tx_amount_encode = Utils.encode_u8(tx_amount)
        tx_time_stamp_encode = Utils.encode_u8(tx_time_stamp)
        tx_rlp = [tx_amount_encode, tx_hash_result, tx_time_stamp_encode]
        tx.payload = rlp.encode(tx_rlp)
        return tx

    @staticmethod
    def create_hash_height_block_for_deploy_tx(tx_from: bytes, tx_nonce: int, tx_asset_hash: bytes, tx_pubkey_hash: bytes) -> Transaction:
        """
            构造区块高度锁定支付的事务
            :param tx_from: bytes
            :param tx_nonce: int
            :param tx_asset_hash: bytes
            :param tx_pubkey_hash: bytes
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="HASH_HEIGHT_BLOCK_FOR_DEPLOY",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_amount=0
        )
        tx.gas_price = round(FEE / GAS_TABLE[2])
        tx.tx_to = bytes(40)
        tx_rlp = [tx_asset_hash, tx_pubkey_hash]
        tx.payload = rlp.encode(tx_rlp)
        return tx

    @staticmethod
    def create_hash_height_block_get_for_deploy_tx(tx_from: bytes, tx_hash: bytes, tx_nonce: int, tx_transfer_hash: bytes, tx_origin_text: bytes) -> Transaction:
        """
            构造区块高度锁定的获得锁定资产事务
            :param tx_from: bytes
            :param tx_hash: bytes
            :param tx_nonce: int
            :param tx_transfer_hash: bytes
            :param tx_origin_text: bytes
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="HASH_HEIGHT_BLOCK_GET_FOR_DEPLOY",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_amount=0
        )
        tx.gas_price = round(FEE / GAS_TABLE[2])
        tx.tx_to = Utils.ripmed160(tx_hash)
        tx_rlp = [tx_transfer_hash, tx_origin_text]
        tx.payload = rlp.encode(tx_rlp)
        return tx

    @staticmethod
    def create_hash_height_block_transfer_for_deploy_tx(tx_from: bytes, tx_hash: bytes, tx_nonce: int, tx_amount: int, tx_hash_result: bytes, tx_block_height: int) -> Transaction:
        """
            构造区块高度锁定的转发资产事务
            :param tx_from: bytes
            :param tx_hash: bytes
            :param tx_nonce: int
            :param tx_amount: int
            :param tx_hash_result: bytes
            :param tx_block_height: int
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type="HASH_HEIGHT_BLOCK_TRANSFER_FOR_DEPLOY",
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_amount=0
        )
        tx.gas_price = round(FEE / GAS_TABLE[2])
        tx.tx_to = Utils.ripmed160(tx_hash)
        tx_amount_encode = Utils.encode_u8(tx_amount)
        tx_block_height_encode = Utils.encode_u8(tx_block_height)
        tx_rlp = [tx_amount_encode, tx_hash_result, tx_block_height_encode]
        tx.payload = rlp.encode(tx_rlp)
        return tx


if __name__ == '__main__':
    # fromPubkey = bytes.fromhex('7a94e5c3c8bf9bbf23df6d195ff3a76322088a94886f5bfee70ac574d11bd52a')
    # toPubkeyHash = bytes.fromhex('fbdacd374729b74c594cf955dc207fbb1d203a10')
    # amount = 10 * 100000000
    # prikey = bytes.fromhex('f0d55ae8a79186e8595514fe23dec8716a191d2bb525998298371693dc69a926')
    fromPubkey = bytes.fromhex('fce8ec82c17bbd763e2edfbbd9ae9cb24bfa2181e166c4c8590435c6383a4465')
    toPubkeyHash = bytes.fromhex('a8dab9a3828d750174c25f09ab619f55d7533346')
    amount = 10 * 100000000
    prikey = bytes.fromhex('a4643462e43c642418f638d5cb0ba7bf79d3887e7df0e146a0a7a1738eef0107')
    nonce = 1
    a = TxUtility()
    b = a.create_transfer_tx(fromPubkey, toPubkeyHash, amount, nonce)
    print('b.sig: ' + b.sig.hex())
    print('b.get_raw_for_sign: ' + b.get_raw_for_sign().hex())
    a.sign_transaction(b, prikey)
    print('b.sig: ' + b.sig.hex())
    print('b.get_hash: ' + b.get_hash().hex())
    print('b.get_raw_for_hash: ' + b.get_raw_for_hash().hex())
