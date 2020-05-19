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
{"message":"描述","data":["数据"],"statusCode":int}
```

## 2.0 JAVA-SDK文档
* 2.1 生成keystore文件
```python
from key_store import KeyStore

pwd = "00000000"

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

address = "address"

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

address = "address"

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

key_store = "key store json str"

store = KeyStore.from_json(key_store).as_dict()
# 获得地址
address = store["address"]
# 参数：
#  1）、KeyStore json str
# 返回类型：str
# 返回值：地址
```