# OSCP-CheatSheet

c1inton's OSCP CheatSheet.

  - [Port](#port)
    - [21-FTP](#21-ftp)
    - [22-SSH](#22-ssh)
    - [25-SMTP](#25-smtp)
    - [53-DNS](#53-dns)
    - [80/443-HTTP(S)](#80443-https)
    - [110-POP3](#110-pop3)
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
```powershell
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
ssh $user@~~$ip~~
ssh $user@$ip -i user.key

#Brute force
hydra -v  -L user.txt -P /usr/share/wordlists/rockyou.txt -t 16 $ip ssh
hydra -l gibson -P /tmp/alpha.txt -T 20 $ip ssh

#SSH key file
/home/user/.ssh/id_rsa
/home/user/.ssh/authorized_keys
```
### 25-SMTP

### 53-DNS

### 80/443-HTTP(S)

### 110-POP3

## Linux Privilege Escalation

## Windows Privilege Escalation

## Useful Commands
### File Transfer

### Reverse Shell

### Shell Spawning

## Buffer Overflow


```python
s = "Python syntax highlighting"
print s
```