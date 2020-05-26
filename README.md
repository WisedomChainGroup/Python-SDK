# Python-SDK文档
```
APPSDK是提供给APP调用的方法，主要是提供给实现普通转账事务的构造，签名，发送以及孵化器相关的操作，
对于RPC来说，提供若干的接口，对于客户端来说，需要提供若干的实现方法，如下所示：
```

## 1.0 基本说明

* 1.1 区块确认完成
```
通过事务的哈希值查询确认区块数，并且确认是否已经完成， 我们认为往后确定2区块即可表示已经完成。 
无论什么事务，都要等待至少2个区块确认才算完成。
```

* 1.2 返回格式
```json
{"message":"描述","data":["数据"],"statusCode": 5000}
```

## 2.0 JAVA-SDK文档
* 2.1 生成keystore文件
```python
from key_store import KeyStore

pwd = str("00000000")

key_store = KeyStore.create_key_store(pwd)
print(KeyStore.from_json(key_store).as_dict())
# 参数：
#  1）、密码（str)
# 返回类型：KeyStore json str
# 返回值：keystore

```

* 2.2 地址校验
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

* 2.3 通过地址获得公钥哈希
```python
from utils import Utils

address = str("address")

pubkey_hash = Utils().address_to_pubkey_hash(address)
# 参数：
#  1）、地址字符串（str)
# 返回类型：bytes
# 返回值：pubkey_hash(公钥哈希)
```

* 2.4 通过公钥哈希获得地址
```python
from utils import Utils

pubkey_hash = b"pubkey_hash"

address = Utils().pubkey_hash_to_address(pubkey_hash)
# 参数：
#  1）、公钥哈希（bytes)
# 返回类型：str
# 返回值：address(地址)
```

* 2.5 通过keystore获得地址
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

* 2.6 通过地址获得公钥哈希
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

* 2.7 通过keystore获得私钥
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

* 2.8 通过私钥获得公钥
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

* 2.9 修改KeyStore密码方法
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

* 2.10 SHA3-256哈希方法
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

* 2.11 Ripemd-160哈希方法
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

* 2.12 base58编码方法
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

* 2.13 创建原生转账事务
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

* 2.14 签名事务
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

* 2.15 构造存证事务
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

* 2.16 构造投票事务
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

* 2.17 构造投票撤回事务
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

* 2.18 构造抵押事务
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

* 2.19 构造抵押撤回事务
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