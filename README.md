# Python-SDK文档
## 1.0 PYTHON-SDK文档
* 1.1 生成keystore文件
```python
from key_store import KeyStore

pwd = str("00000000")

key_store = KeyStore.create_key_store(pwd)
key_store_json_str = key_store.as_dict()
# 参数：
#  1）、密码（str)
# 返回类型：KeyStore json str
# 返回值：keystore

```

* 1.2 地址校验
```python
from utils import Utils

address = str("address")

pubkey_hash = Utils().address_to_pubkey_hash(address)
# 参数：
#  1）、地址字符串（str)
# 返回类型：bytes
# 返回值：
#  pubkey_hash(公钥哈希) -> 地址正确
#  抛异常 -> 地址错误
```

* 1.3 通过地址获得公钥哈希
```python
from utils import Utils

address = str("address")

pubkey_hash = Utils().address_to_pubkey_hash(address)
# 参数：
#  1）、地址字符串（str)
# 返回类型：bytes
# 返回值：pubkey_hash(公钥哈希)
```

* 1.4 通过公钥哈希获得地址
```python
from utils import Utils

pubkey_hash = b"pubkey_hash"

address = Utils().pubkey_hash_to_address(pubkey_hash)
# 参数：
#  1）、公钥哈希（bytes)
# 返回类型：str
# 返回值：address(地址)
```

* 1.5 通过keystore获得地址
```python
from key_store import KeyStore

key_store = str("key store json str")

store = KeyStore.from_json(key_store).as_dict()
# 获得地址
address = store["address"]
# 参数：
#  1）、KeyStore json str
# 返回类型：str
# 返回值：地址
```

* 1.6 通过地址获得公钥哈希
```python
from utils import Utils

address = str("address")
# 获得公钥哈希
pubkey_hash = Utils.address_to_pubkey_hash(address)
# 参数：
#  1）、address str
# 返回类型：bytes
# 返回值：公钥哈希
```

* 1.7 通过keystore获得私钥
```python
from key_store import KeyStore

keystore_json_str = str("keystore json str")
keystore = KeyStore.from_json(keystore_json_str)
    
# 获得私钥
sk = keystore.parse("00000000")
# 参数：
#  1）、keystore json str
# 返回类型：bytes
# 返回值：私钥
```

* 1.8 通过私钥获得公钥
```python
from utils import Utils

sk = b"private_key"

# 获得公钥
pk = Utils.ed25519_keypair(sk)
# 参数：
#  1）、sk(私钥)
# 返回类型：bytes
# 返回值：公钥
```

* 1.9 修改KeyStore密码方法
```python
from key_store import KeyStore

pwd = str("new password")
sk = b"private_key"

# 获得公钥
pk = KeyStore.create_key_store(pwd, sk)
# 参数：
#  1）、sk(私钥)
# 返回类型：bytes
# 返回值：公钥
```

* 1.10 SHA3-256哈希方法
```python
from utils import Utils

hash_text = b"hash_text"

# 获得哈希值
hash_plain = Utils.keccak256(hash_text)
# 参数：
#  1）、哈希原文（字节数组)
# 返回类型：十六进制bytes
# 返回值：哈希值
```

* 1.11 Ripemd-160哈希方法
```python
from utils import Utils

hash_text = b"hash_text"

# 获得哈希值
hash_plain = Utils.ripmed160(hash_text)
# 参数：
#  1）、哈希原文（字节数组)
# 返回类型：十六进制bytes
# 返回值：哈希值
```

* 1.12 base58编码方法
```python
from utils import Utils

text_bytes = b"text_bytes"

# 获得哈希值
text_encode = Utils.b58encode(text_bytes)
# 参数：
#  1）、哈希原文（字节数组)
# 返回类型：str
# 返回值：哈希值
```

* 1.13 创建原生转账事务
```python
from tx_utility import TxUtility

from_pubkey = b'from_pubkey'
to_pubkey_hash = b'to_pubkey_hash'
amount = 10 * 100000000
nonce = 0 + 1

# 创建原生转账事务
tx_utility = TxUtility()
transaction = tx_utility.create_transfer_tx(from_pubkey, to_pubkey_hash, amount, nonce)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、接收者公钥哈希（bytes)
#  3）、转账金额(int)
#  4）、nonce(int)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 1.14 签名事务
```python
from tx_utility import TxUtility

from_pubkey = b'from_pubkey'
to_pubkey_hash = b'to_pubkey_hash'
amount = 10 * 100000000
nonce = 0 + 1
private_key = b"private_key"

# 创建原生转账事务
tx_utility = TxUtility()
transaction = tx_utility.create_transfer_tx(from_pubkey, to_pubkey_hash, amount, nonce)

# 签名事务
sign = tx_utility.sign_transaction(transaction, private_key)

# 参数：
#  1）、事务(transaction)
#  2）、私钥(bytes)
# 返回类型：十六进制字符(bytes)
# 返回值：签名哈希
```

* 1.15 构造存证事务
```python
from tx_utility import TxUtility

from_pubkey = b'from_pubkey'
tx_payload = b'tx_payload'
amount = 10 * 100000000
nonce = 0 + 1

# 创建原生存证事务
tx_utility = TxUtility()
transaction = tx_utility.create_transfer_prove_tx(from_pubkey, tx_payload, nonce)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、存证内容（bytes)
#  3）、Nonce(int)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 1.16 构造投票事务
```python
from tx_utility import TxUtility

from_pubkey = b'from_pubkey'
to_pubkey_hash = b'to_pubkey_hash'
amount = 10 * 100000000
nonce = 0 + 1

# 创建原生投票事务
tx_utility = TxUtility()
transaction = tx_utility.create_transfer_vote_tx(from_pubkey, to_pubkey_hash, amount, nonce)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、接收者公钥哈希（bytes)
#  3）、票数(int)
#  4）、nonce(int)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 1.17 构造投票撤回事务
```python
from tx_utility import TxUtility

from_pubkey = b'from_pubkey'
to_pubkey_hash = b'to_pubkey_hash'
amount = 10 * 100000000
nonce = 0 + 1
tx_id = b'tx_id'

# 创建原生投票撤回事务
tx_utility = TxUtility()
transaction = tx_utility.create_transfer_vote_with_tx(from_pubkey, to_pubkey_hash, amount, nonce, tx_id)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、接收者公钥哈希（bytes)
#  3）、票数(int)
#  4）、nonce(int)
#  5）、投票事务哈希(bytes)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 1.18 构造抵押事务
```python
from tx_utility import TxUtility

from_pubkey = b'from_pubkey'
to_pubkey_hash = b'to_pubkey_hash'
amount = 10 * 100000000
nonce = 0 + 1

# 创建原生抵押事务
tx_utility = TxUtility()
transaction = tx_utility.create_transfer_mortgage_tx(from_pubkey, to_pubkey_hash, amount, nonce)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、接收者公钥哈希（bytes)
#  3）、金额(int)
#  4）、nonce(int)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 1.19 构造抵押撤回事务
```python
from tx_utility import TxUtility

from_pubkey = b'from_pubkey'
to_pubkey_hash = b'to_pubkey_hash'
amount = 10 * 100000000
nonce = 0 + 1
tx_id = b'tx_id'

# 创建原生抵押撤回事务
tx_utility = TxUtility()
transaction = tx_utility.create_transfer_mortgage_with_tx(from_pubkey, to_pubkey_hash, amount, nonce, tx_id)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、接收者公钥哈希（bytes)
#  3）、金额(int)
#  4）、nonce(int)
#  5）、抵押事务哈希(bytes)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 1.20 部署资产定义事务
```python
from tx_utility import TxUtility

tx_from = b'tx_from'
tx_nonce = 0 + 1
tx_code = str("tx_code")
tx_offering = 10 * 100000000
tx_total_amount = 10 * 100000000
tx_create_user = b'tx_create_user'
tx_owner = b'tx_owner'
tx_allow_increase = 1
tx_info = b'tx_info'

# 部署资产定义事务
tx_utility = TxUtility()
transaction = tx_utility.create_deploy_for_rule_asset_tx(tx_from, tx_nonce, tx_code, tx_offering, tx_total_amount, tx_create_user, tx_owner, tx_allow_increase, tx_info)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、nonce(int)
#  3）、code(str，资产代码)
#  4）、offering（int，期初发行额度)
#  5）、create_user(bytes，规则创建者的公钥)
#  6）、owner（bytes，规则所有者的公钥哈希)
#  7）、allow_increase(int 是否允许增发 1表示允许，0表示不允许)
#  8）、info(string 说明)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 1.21 构造资产定义的更换所有者事务
```python
from tx_utility import TxUtility

tx_from = b'tx_from'
tx_hash = b'tx_hash'
tx_nonce = 0 + 1
tx_new_owner = b'tx_new_owner'

# 构造资产定义的更换所有者事务
tx_utility = TxUtility()
transaction = tx_utility.create_transfer_call_for_rule_asset_change_owner_tx(tx_from, tx_hash, tx_nonce, tx_new_owner)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、事务哈希(bytes)
#  3）、nonce(int)
#  4）、new_owner(bytes，新的目标用户公钥哈希)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 1.22 构造资产定义的增发事务
```python
from tx_utility import TxUtility

tx_from = b'tx_from'
tx_hash = b'tx_hash'
tx_nonce = 0 + 1
tx_amount = 10 * 100000000

# 构造资产定义的增发事务
tx_utility = TxUtility()
transaction = tx_utility.create_transfer_call_for_rule_asset_increased_tx(tx_from, tx_hash, tx_nonce, tx_amount)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、事务哈希(bytes)
#  3）、nonce(int)
#  4）、amount(bytes，增发的金额)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 1.23 构造资产定义的转账事务
```python
from tx_utility import TxUtility

tx_from = b'tx_from'
tx_hash = b'tx_from'
tx_nonce = 0 + 1
tx_from_asset = b'tx_from_asset'
tx_to_asset = b'tx_to_asset'
tx_amount = 10 * 100000000

# 构造资产定义的转账事务
tx_utility = TxUtility()
transaction = tx_utility.create_transfer_deploy_for_rule_asset_tx(tx_from, tx_hash, tx_nonce, tx_from_asset, tx_to_asset, tx_amount)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、事务哈希(bytes)
#  3）、nonce(int)
#  4）、from(bytes，公钥)
#  5）、to(bytes，目标地址的公钥哈希)
#  6）、value(int，转发金额，必须大于0，整数)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 1.24 构造签名的多重规则部署（发布者签名）
```python
from tx_utility import TxUtility

tx_from = b'tx_from'
tx_nonce = 0 + 1
tx_asset_hash = b'tx_asset_hash'
tx_max = 10
tx_min = 1
tx_pub_list = [b'tx', b'pub', b'list']
tx_signatures = [b'tx', b'signatures']
tx_public_key_hash_list = [b'tx', b'public', b'key', b'hash', b'list']

# 构造签名的多重规则部署（发布者签名）
tx_utility = TxUtility()
transaction = tx_utility.create_multiple_for_rule_first_tx(tx_from, tx_nonce, tx_asset_hash, tx_max, tx_min, tx_pub_list, tx_signatures, tx_public_key_hash_list)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、nonce(int，发布人的当前nonce)
#  3）、asset_hash(bytes  资产的哈希值)
#  4）、max(int   总计可以具备的签名数)
#  5）、min(int   最少需要达到的签名数)
#  6）、public_key_hash_list(bytes的集合  公钥数组)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 2.25 构造时间锁定的事务
```python
from tx_utility import TxUtility

tx_from = b'tx_from'
tx_nonce = 0 + 1
tx_asset_hash = b'tx_asset_hash'
tx_public_hash = b'tx_public_hash'
# 构造时间锁定的事务
tx_utility = TxUtility()
transaction = tx_utility.create_hash_time_block_for_deploy_tx(tx_from, tx_nonce, tx_asset_hash, tx_public_hash)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、nonce（int)
#  3）、asset_hash(bytes 资产哈希)
#  4）、public_hash(bytes 公钥哈希)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 2.26 构造获得锁定资产事务
```python
from tx_utility import TxUtility

tx_from = b'tx_from'
tx_hash = b'tx_hash'
tx_nonce = 0 + 1
tx_transfer_hash = b'tx_transfer_hash'
tx_origin_text = 'tx_origin_text'
# 构造获得锁定资产事务
tx_utility = TxUtility()
transaction = tx_utility.create_hash_time_block_get_for_deploy_tx(tx_from, tx_hash, tx_nonce, tx_transfer_hash, tx_origin_text)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、事务哈希（bytes)
#  3）、nonce（int)
#  4）、transfer_hash(bytes 签发事务的哈希)
#  5）、origin_text(str 原文)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 2.27 构造时间锁定的转发资产事务
```python
from tx_utility import TxUtility

tx_from = b'tx_from'
tx_hash = b'tx_hash'
tx_nonce = 0 + 1
tx_amount = 10 * 100000000
tx_hash_result = b'tx_hash_result'
tx_time_stamp = 10000
# 构造时间锁定的转发资产事务
tx_utility = TxUtility()
transaction = tx_utility.create_hash_time_block_transfer_for_deploy_tx(tx_from, tx_hash, tx_nonce, tx_amount, tx_hash_result, tx_time_stamp)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、事务哈希（bytes)
#  3）、nonce（int)
#  4）、amount(int 金额)
#  5）、hash_result(bytes 原文)
#  6）、time_stamp(时间戳)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 2.28 构造区块高度锁定支付的事务
```python
from tx_utility import TxUtility

tx_from = b'tx_from'
tx_nonce = 0 + 1
tx_asset_hash = b'tx_asset_hash'
tx_pubkey_hash = b'tx_pubkey_hash'
# 构造区块高度锁定支付的事务
tx_utility = TxUtility()
transaction = tx_utility.create_hash_height_block_for_deploy_tx(tx_from, tx_nonce, tx_asset_hash, tx_pubkey_hash)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、nonce（int)
#  3）、asset_hash（bytes 资产哈希)
#  4）、pubkey_hash(bytes 公钥哈希)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 2.29 构造区块高度锁定的获得锁定资产事务
```python
from tx_utility import TxUtility

tx_from = b'tx_from'
tx_hash = b'tx_hash'
tx_nonce = 0 + 1
tx_transfer_hash = b'tx_transfer_hash'
tx_origin_text = 'tx_origin_text'
# 构造区块高度锁定的获得锁定资产事务
tx_utility = TxUtility()
transaction = tx_utility.create_hash_height_block_get_for_deploy_tx(tx_from, tx_hash, tx_nonce, tx_transfer_hash, tx_origin_text)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、事务哈希(bytes)
#  3）、nonce（int)
#  4）、transfer_hash（bytes 转账事务的哈希)
#  5）、origin_text(str 原文)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```

* 2.30 构造区块高度锁定的转发资产事务
```python
from tx_utility import TxUtility

tx_from = b'tx_from'
tx_hash = b'tx_hash'
tx_nonce = 0 + 1
tx_amount = 10 * 100000000
tx_hash_result = b'tx_hash_result'
tx_block_height = 10
# 构造区块高度锁定的转发资产事务
tx_utility = TxUtility()
transaction = tx_utility.create_hash_height_block_transfer_for_deploy_tx(tx_from, tx_hash, tx_nonce, tx_amount, tx_hash_result, tx_block_height)

# 参数：
#  1）、发送者公钥(bytes)
#  2）、事务哈希(bytes)
#  3）、nonce（int)
#  4）、amount（int 金额)
#  5）、hash_result（bytes 原文)
#  6）、block_height(int)
# 返回类型：Transaction(bytes)
# 返回值：未签名的事务
```