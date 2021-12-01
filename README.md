# Writer 10.10.11.101

Core Concepts:
    SMB Enumeration
    SSH brute forcing
    pspy64
    Python code for sending mail
    Privilege escalation

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