# Writer 10.10.11.101
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
wget https://github.com/digination/dirbuster-ng/blob/master/wordlists/common.txt
gobuster dir -u http://writer.htb -w common.txt -o gobuster.writer.txt
```