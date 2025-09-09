---
name: Keeping Up With The Credentials (2025)
event: CTF@CIT CTF 2025
category: Web
description: Writeup for Keeping Up With The Credentials (Web) - CTF@CIT CTF (2025) 💜
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

# Keeping Up With The Credentials

[![](https://img.youtube.com/vi/ZBdApaw0r0M/0.jpg)](https://www.youtube.com/watch?v=ZBdApaw0r0M?t=879 "Keeping up with the Credentials (CIT CTF)")

## Description

> "I’m all about strong passwords. If you're not using one, you’re just playing yourself."

> This challenge requires something that can be acquired in any of the other web challenges.

## Solution

Another basic login page. The description mentions we need something from another web challenge and the name hints at reused credentials, remember the DB we dumped in the SQLi challenge?


```bash
+---------+----------+--------------+----------+
| email   | fullname | password     | username |
+---------+----------+--------------+----------+
| <blank> | <blank>  | m1n3r41s     | hank     |
| <blank> | <blank>  | 9f3IC3uj9^zZ | admin    |
| <blank> | <blank>  | M4GN375      | jesse    |
| <blank> | <blank>  | b4byb1u3     | walter   |
+---------+----------+--------------+----------+
```


Try to login with `admin:9f3IC3uj9^zZ` and we successfully login and reach `/debug.php`. It says the page is currently under construction and to try again later.

Couldn't see much to do here, no cookies etc. Tried a few things:

-   Different GET parameters to see if response changed
-   Different HTTP methods
-   Different Content-Type (XML/JSON)

The response remained the same 😕 Try SQLi again, maybe there's a different DB.


```bash
sqlmap -u http://23.179.17.40:58003/index.php --data "username=cat&password=meow&login=Login" --batch
```


Nope, it's the same! Tried to use `gobuster` along with the cookie to see if there are some other PHP files (this is starting to feel guessy lol).


```bash
gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -u http://23.179.17.40:58003/ -x php -c "PHPSESSID=3769e9cc271318ef55b31272d2ea9424"

===============================================================
/index.php            (Status: 200) [Size: 2484]
/admin.php            (Status: 302) [Size: 0] [--> /index.php]
/debug.php            (Status: 200) [Size: 2432]
```


Interesting that there does seem to be an admin page, and we are logged in as the admin user but get redirected to the homepage.

Another challenge I didn't finish before the CTF ended 😞 I didn't see any writeups yet but heard someone mentioning changing the request method to POST. I tried that on the `debug.php` page but apparently I was meant to do it on `index.php` during login. Testing that confirms we are redirected to `admin.php` containing the flag.

Flag: `CIT{7bf610e96ade83db}`
