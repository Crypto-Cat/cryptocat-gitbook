---
name: YAMLwaf (2025)
event: Tsuku CTF 2025
category: Web
description: Writeup for YAMLwaf (Web) - Tsuku CTF (2025) 💜
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

# YAMLwaf

[![](https://img.youtube.com/vi/qGd4d0zmhy8/0.jpg)](https://www.youtube.com/watch?v=qGd4d0zmhy8?t=508 "YAMLwaf (Tsuku CTF)")

## Description

> YAML is awesome!!

## Solution

### Source code

The challenge comes with source code, `server.js` is most relevant.

{% code overflow="wrap" %}
```js
const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const path = require("path");
const yaml = require("js-yaml");
const app = express();
app.use(bodyParser.text());

app.post("/", (req, res) => {
    try {
        if (req.body.includes("flag")) {
            return res.status(403).send("Not allowed!");
        }
        if (req.body.includes("\\") || req.body.includes("/") || req.body.includes("!!") || req.body.includes("<")) {
            return res.status(403).send("Hello, Hacker :)");
        }
        const data = yaml.load(req.body);
        const filePath = data.file;

        if (filePath && fs.existsSync(filePath)) {
            const content = fs.readFileSync(filePath, "utf8");
            return res.send(content);
        } else {
            return res.status(404).send("File not found");
        }
    } catch (err) {
        return res.status(400).send("Invalid request");
    }
});

app.listen(3000, () => {
    console.log("Server listening on port 3000");
});
```
{% endcode %}

### Breaking it down

The app processes POST requests, parses YAML from the request body, and attempts to read a file specified in the YAML content.

WAF checks if:

-   `'flag'` is in the raw request body → 403.
-   `'/'`, `'\\'`, `'!!'`, or `'<'` are present → 403.
    If checks pass, it tries to access `data.file`.

| Filter        | Purpose                     | Bypass Possibility                 |
| ------------- | --------------------------- | ---------------------------------- |
| `'flag'`      | Blocks direct keyword usage | Use Unicode, split string, etc.    |
| `'/'`, `'\\'` | Blocks path traversal       | Use symlinks or local files        |
| `'!!'`, `'<'` | Blocks YAML tag injection   | No known bypass with these blocked |

### YAML Injection

The challenge description already gave a sample curl command.

{% code overflow="wrap" %}
```bash
curl -X POST "http://challs.tsukuctf.org:50001" -H "Content-Type: text/plain" -d "file: flag.txt"

Not allowed!
```
{% endcode %}

Imagine if it gave the flag 😆 It doesn't since "flag" is a blocked keyword.

I tried a lot of suggestions from ChatGPT; unicode chars, splitting the flag into variables, adding newlines etc. Nothing worked and it kept going in circles.

I checked this [guide](https://book.jorianwoltjer.com/languages/yaml#javascript-js-yaml-less-than-4.0) from J0r1an but we can't use the `<` character, and it specifies versions < 4.0, while this challenge uses the latest version of `js-yaml` (`^4.1.0`).

I searched through previous CTF writeups but wasn't getting anywhere. Eventually, I swapped the ChatGPT model from `o4` to `o3` and found a working solution.

{% code overflow="wrap" %}
```bash
curl -X POST "http://challs.tsukuctf.org:50001" -H "Content-Type: text/plain" --data-binary $'%TAG !b! tag:yaml.org,2002:\n---\nfile: !b!binary "ZmxhZy50eHQ="'

TsukuCTF25{YAML_1s_d33p!}
```
{% endcode %}

Here's the logic behind the payload:

| Stage                     | What happens                                                                                                                                                                            | Why the blacklist is bypassed                                                                                    |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| **1. YAML directive**     | `%TAG !b! tag:yaml.org,2002:` declares a **handle** `!b!`. Any tag that starts with `!b!` is expanded to `tag:yaml.org,2002:`.                                                          | Directive text contains none of the blocked substrings.                                                          |
| **2. Binary tag**         | `!b!binary` therefore becomes the official core tag `tag:yaml.org,2002:binary` (`!binary`).                                                                                             | Only a single `!` is used → no `!!`. No `<` or `/`.                                                              |
| **3. Base‑64 value**      | `"ZmxhZy50eHQ="` is base‑64 for the ASCII bytes `flag.txt`.                                                                                                                             | The four ASCII letters **f l a g** never appear in the raw request, so `req.body.includes("flag")` is **false**. |
| **4. `js‑yaml` decoding** | With the **default (safe) schema**, `!binary` is still recognised. `js‑yaml` converts it to a Node `Buffer` containing the bytes `flag.txt`.                                            | No dangerous function tags are involved, so the payload is accepted.                                             |
| **5. File read**          | The application later executes `fs.existsSync(filePath)` and `fs.readFileSync(filePath,'utf8')`. Both `fs` calls accept either a string _or a Buffer_ as the path, so the Buffer works. | From this point onward the blacklist is already satisfied and no further checks occur.                           |
| **6. Response**           | The server reads the real **`flag.txt`** from disk and returns its contents in the HTTP response.                                                                                       | Mission accomplished.                                                                                            |

Flag: `TsukuCTF25{YAML_1s_d33p!}`
