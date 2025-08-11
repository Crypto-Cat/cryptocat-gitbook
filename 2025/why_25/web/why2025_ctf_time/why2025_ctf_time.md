---
name: WHY2025 CTF TIMES (2025)
event: WHY CTF 2025
category: Web
description: Writeup for WHY2025 CTF TIMES (Web) - WHY CTF (2025) 💜
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

# WHY2025 CTF TIMES

## Description

> Besides creating a CTF, we also created a [newspaper website](https://why2025-ctf-times.ctf.zone). Well we have one article at least. We made sure we followed all the latest trends and laws.

## Recon

When we arrive to the site we have to agree to some cookies.

![](images/0.PNG)

Then we need to enter our date of birth.

![](images/1.PNG)

Then enter our email.

![](images/2.PNG)

We'll arrive at the page, but very quickly all the annoying popups will return. It is a troll challenge!!

![](images/3.PNG)

There's also an interesting chat button in the bottom right.

![](images/4.PNG)

## Solution

There's probably a lot of ways to disable the popups, which seem to be coming from the `paywall.min.js` file.

![](images/5.PNG)

It's heavily obfuscated but we could try to reverse engineer it or step through with the debugger.

I hoped to skip the trouble by simply dropping requests for the file. You can do this manually, or setup a match and replace rule in burp suite. I opted to replace all instances of `paywall.min.js` with `meow`.

![](images/6.PNG)

Remember to reload the page while clearing the cache (`ctrl + f5`). We no longer get most of the annoying popups, but date of birth is still there and is no longer functional. Dead end, so we can remove the rule.

### Debugging

Time for a simpler approach, I use `ctrl + F` on the minified JS file.

![](images/7.PNG)

It looks like our flag is split up across those lines with some obfuscation. We can search for `line4` and setup a breakpoint.

![](images/8.PNG)

When the debugger pauses, we switch to the console and print out the line variables.

![](images/9.PNG)

`line3` holds the flag!

Flag: `flag{2d582cd42552e765d2658a14a0a25755}`
