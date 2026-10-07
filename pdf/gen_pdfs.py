#!/usr/bin/env python3
"""Generate CyTech cybersecurity study PDFs (6 topics) with reportlab."""
import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak

GREEN = HexColor('#0a7a4a'); DARK = HexColor('#111111'); ACC = HexColor('#00553f')
OUT = os.path.dirname(os.path.abspath(__file__))

CONTENT = {
"cybersecurity-foundations": ("Cybersecurity Foundations", [
 ("What is Cybersecurity?", [
  "Cybersecurity is the practice of protecting systems, networks, programs and data from digital attacks. These attacks usually aim to access, change or destroy sensitive information, extort money, or interrupt normal business processes.",
  "The discipline spans people, process and technology: even the strongest encryption fails if a user reuses a weak password. A professional therefore thinks in layers - technical controls, policies, and continuous education."]),
 ("The CIA Triad", [
  "Confidentiality: only authorized parties can read data (encryption, access control, least privilege). Integrity: data is accurate and unmodified except by authorized action (hashing, digital signatures, checksums). Availability: systems and data are accessible when needed (redundancy, backups, DDoS protection).",
  "Every security decision maps to one or more of these three pillars. When you analyze an incident, ask which pillar was broken; when you design a control, ask which pillar it protects."]),
 ("Threat Actors and Attack Types", [
  "Actors range from script kiddies and cybercriminals (ransomware, fraud) to hacktivists, insider threats and nation-state APT groups. Motivations: money, espionage, ideology, disruption, reputation.",
  "Common attacks: phishing and social engineering, malware (viruses, worms, trojans, ransomware, spyware), credential attacks (brute force, stuffing, spraying), MITM, SQL injection, XSS, zero-days and supply-chain compromise."]),
 ("Core Defenses", [
  "Defense in depth: firewalls and network segmentation, EDR/antivirus, patch management, MFA, strong password policy and managers, encrypted transport (TLS) and storage (AES-256), secure configuration baselines, logging and SIEM monitoring, regular backups with tested restore.",
  "Security awareness training is the highest-ROI control: most breaches begin with a human click. Simulate phishing, teach verification habits, and make reporting easy."]),
 ("Careers and Certifications", [
  "Roles: SOC analyst, penetration tester, security engineer, DFIR analyst, GRC analyst, malware reverse engineer, CISO. Entry certs: CompTIA Security+, Google Cybersecurity Certificate. Practical: eJPT, PNPT. Advanced: OSCP, CEH (theory), GCIH, CHFI.",
  "Build a home lab (VirtualBox + Kali + a vulnerable VM like Metasploitable or DVWA), document everything you learn publicly, and practice on legal platforms: TryHackMe, HackTheBox, PicoCTF."])]),
"ethical-hacking": ("Ethical Hacking & Penetration Testing", [
 ("Rules of Engagement", [
  "Ethical hacking is authorized testing. Never touch a system without written permission defining scope, timing and allowed techniques. A signed rules-of-engagement contract protects you legally.",
  "Practice legally on: testphp.vulnweb.com (Acunetix test site), DVWA, Metasploitable 2/3, OWASP Juice Shop, HackTheBox, TryHackMe, VulnHub VMs."]),
 ("Phase 1 - Reconnaissance", [
  "Passive OSINT: WHOIS, DNS records (dig, nslookup), Google dorking (site:, filetype:, inurl:), Shodan, certificate transparency logs (crt.sh), LinkedIn for staff names, theHarvester for emails.",
  "Active: host discovery and port scanning with Nmap. Examples: nmap -sn 192.168.1.0/24 (ping sweep), nmap -sV -sC -O target (services, default scripts, OS), nmap -p- --min-rate 5000 target (all ports)."]),
 ("Phase 2 - Scanning & Enumeration", [
  "Enumerate services: SMB (enum4linux, smbclient), web directories (gobuster, ffuf, dirb), DNS zone transfer (dig axfr), SNMP. Nikto and OWASP ZAP find known web weaknesses automatically.",
  "Map every input: URL parameters, forms, cookies, headers, file uploads. Inputs are where vulnerabilities live."]),
 ("Phase 3 - Exploitation", [
  "SQL injection: test with a single quote; confirm with ' OR '1'='1; automate with sqlmap -u 'URL?id=1' --dbs. XSS: inject <script>alert(1)</script>; stored XSS is most dangerous. Command injection: append ;id or |whoami.",
  "Metasploit workflow: msfconsole; search <cve>; use exploit/...; set RHOSTS/LHOST; run. Always prefer the least-destructive proof of concept that demonstrates impact."]),
 ("Phase 4 - Post-Exploitation & Reporting", [
  "After access: establish persistence conceptually, escalate privileges (linpeas/winpeas, sudo -l, unquoted service paths), pivot, and - most importantly - collect evidence (screenshots, timestamps).",
  "The report is the product: executive summary, findings with CVSS severity, business impact, reproduction steps, and concrete remediation. A great pentester is 50% writer."])]),
"reverse-engineering": ("Reverse Engineering", [
 ("Foundations", [
  "Reverse engineering means understanding a program without its source code. You need: x86/x64 assembly basics (registers EAX/EBX/ECX/EDX, stack, CALL/RET, JMP/JE/JNE), the compilation pipeline (C -> compiler -> assembler -> linker -> PE/ELF binary), and how memory is laid out (stack, heap, .text, .data).",
  "Binaries come in formats: PE (Windows .exe/.dll), ELF (Linux), Mach-O (macOS). Learn to read headers with PE-bear, CFF Explorer, readelf and objdump."]),
 ("Static Analysis", [
  "Static = without running the file. Start with: file, strings (find URLs, passwords, messages), hashes (VirusTotal lookup), PE/ELF headers, imported DLLs/functions (Imports reveal capability: CreateRemoteThread = injection, InternetOpen = network).",
  "Disassemblers/decompilers: Ghidra (free, NSA), IDA Free, Binary Ninja (commercial), radare2/cutter. Ghidra's decompiler view turns assembly into near-C pseudocode - read that first."]),
 ("Dynamic Analysis", [
  "Dynamic = run it and watch. Debuggers: x64dbg (Windows), gdb with gef/pwndbg (Linux). Set breakpoints on interesting API calls, step through, watch registers and memory change.",
  "Behavioral monitoring: Process Monitor (file/registry), Process Explorer, Wireshark (network), FakeNet-NG (simulate internet in a safe VM), Regshot. Always analyze malware in an isolated VM with no shared folders and a host-only network (FLARE-VM or REMnux)."]),
 ("Malware Analysis Workflow", [
  "1) Triage: hash, strings, AV detections. 2) Static: unpack if packed (UPX is trivial: upx -d; packed malware hides imports). 3) Dynamic: what files dropped, what registry keys, what C2 domains. 4) Write indicators of compromise (IOCs): hashes, domains, mutexes, file paths.",
  "Packing/obfuscation is the biggest beginner wall: look for high-entropy sections, few imports (LoadLibrary+GetProcAddress only), and a small stub that unpacks the real payload into memory at runtime."]),
 ("Crackmes & Practice", [
  "Learn safely with crackmes (crackmes.one): small legal puzzles where you find the correct serial/password by reading assembly. Beginner path: patch a JNE to JE, then derive the real serial algorithmically.",
  "Then progress to CTF reversing challenges (PicoCTF, HTB) and simple ransomware samples shared for education on MalwareBazaar (VM only, never on your host)."])]),
"network-security": ("Network Security", [
 ("Networking Essentials", [
  "Master the OSI/TCP-IP model: how a packet travels application -> transport (TCP/UDP, ports) -> network (IP, routing) -> link (MAC, switches). Know the TCP 3-way handshake (SYN, SYN-ACK, ACK) - scanning and firewall evasion both build on it.",
  "Key ports: 21 FTP, 22 SSH, 23 Telnet, 25 SMTP, 53 DNS, 80/443 HTTP(S), 110/143/993 mail, 139/445 SMB, 3306 MySQL, 3389 RDP, 5432 Postgres, 8080 proxy."]),
 ("Packet Analysis with Wireshark", [
  "Capture, then filter: ip.addr==10.0.0.5, tcp.port==80, dns, http.request, tcp.flags.syn==1. Follow TCP Stream reconstructs a whole conversation - credentials in plaintext protocols (FTP/Telnet/HTTP) appear instantly.",
  "Learn to spot: ARP spoofing storms, DNS tunneling (huge TXT queries), beaconing (regular identical intervals = C2), port scans (many SYNs, no ACK)."]),
 ("Firewalls, IDS/IPS, Segmentation", [
  "Firewalls: stateless vs stateful vs next-gen. Default-deny inbound, allow only what the business needs, log everything denied. Segment networks (VLANs, DMZ) so one compromised host cannot reach the crown jewels.",
  "IDS (Snort/Suricata) alerts; IPS blocks. Tune signatures to your environment or you drown in false positives."]),
 ("VPNs, Proxies and DNS", [
  "A VPN encrypts all traffic between you and the VPN server - your ISP sees only ciphertext to one destination. Protocols: WireGuard (fast, modern), OpenVPN (mature), IPsec (enterprise). A VPN protects transport privacy; it does NOT make you anonymous by itself.",
  "A proxy forwards requests for specific apps (browser). SOCKS5 (e.g. via ssh -D 1080) is flexible; HTTPS intercepting proxies (Burp, ZAP) let you inspect and modify your own web traffic - the core pentester workflow. Tor routes via 3 volunteer nodes for anonymity.",
  "DNS: use encrypted DNS (DoH/DoT) or a resolver you trust; block malicious domains at DNS level (Pi-hole). Attackers abuse DNS for exfiltration, so log and alert on unusual query volume/length."]),
 ("Hardening a Network", [
  "Kill legacy protocols (Telnet, FTP, HTTP, SMBv1), enforce WPA3/WPA2-Enterprise, 802.1X port auth, strong SNMPv3, patched firmware, central logging to a SIEM (Wazuh/Splunk free tier), and an incident response plan tested with tabletop exercises."])]),
"linux-security-tools": ("Linux & Security Tools Master Guide", [
 ("Linux for Security Work", [
  "Kali Linux is the standard pentest distro; Parrot OS is a lighter alternative. Learn the shell deeply: find, grep, awk, sed, chmod/chown, ps, netstat/ss, curl, wget, tar, systemctl, journalctl. Permissions (rwxrwxrwx, SUID, sudo) are a core privilege-escalation topic.",
  "Build a lab: VirtualBox/VMware + Kali + Metasploitable2 + DVWA on a host-only network. Snapshot before every experiment."]),
 ("Recon & Scanning Toolkit", [
  "Nmap: -sS stealth SYN, -sV version, -sC default scripts, -A aggressive, --script vuln, -oN/-oX output. Masscan for huge ranges (lab only). theHarvester & sublist3r for OSINT/subdomains.",
  "Web: ffuf/gobuster for directories (ffuf -w wordlist -u URL/FUZZ), whatweb/wappalyzer for fingerprinting, nikto for known misconfigs."]),
 ("Exploitation & Web Toolkit", [
  "Metasploit: modules for thousands of CVEs; meterpreter gives a powerful post-exploitation shell. sqlmap automates SQLi end-to-end including DB dump. Hydra/medusa brute-force logins (ssh, ftp, http forms).",
  "Burp Suite / OWASP ZAP: intercept, repeater, intruder, scanner. Configure your browser proxy to 127.0.0.1:8080 and install the CA cert to inspect HTTPS."]),
 ("Passwords, Wireless & Forensics", [
  "John the Ripper: john --wordlist=rockyou.txt hashes.txt. Hashcat uses your GPU: hashcat -m 0 hashes.txt rockyou.txt (mode 0 = MD5; 1000 = NTLM; 1800 = sha512crypt). Identify hash types with hashid.",
  "Wireless: aircrack-ng suite (airodump capture, aireplay deauth, aircrack crack WPA handshake) - only on your own network. Forensics: Autopsy (disk), volatility (memory), binwalk (firmware/embedded files), exiftool (metadata)."]),
 ("Reverse Engineering Tools", [
  "Ghidra (decompiler), IDA Free, cutter/radare2, x64dbg, gdb+gef, ltrace/strace (library/system call tracing), upx (packer), Detect It Easy (packer identification). Practice on crackmes.one - legal and addictive."])]),
"dfir": ("Digital Forensics & Incident Response", [
 ("Forensic Fundamentals", [
  "Goal: preserve and analyze evidence so findings would stand in court. Rules: work only on forensic images (bit-by-bit copies), hash everything (MD5/SHA256) before and after, document every action with timestamps (chain of custody), never boot or modify the original.",
  "Order of volatility: collect most-volatile first - RAM, network connections, running processes, then disk, then logs. Pulling the plug destroys RAM evidence; photograph the screen first."]),
 ("Disk Forensics", [
  "Acquire with dd/FTK Imager (dd if=/dev/sdb of=image.dd bs=4M status=progress; sha256sum image.dd). Analyze in Autopsy: recover deleted files (filesystems often only remove the index entry), timeline file activity, keyword search, carve files from unallocated space with foremost/scalpel.",
  "Windows artifacts worth gold: Prefetch (program execution), registry hives (user activity, USB devices via USBSTOR), $MFT, browser history, event logs (Event ID 4624 logon, 4688 process creation). Linux: /var/log/auth.log, bash_history, cron, journalctl."]),
 ("Memory Forensics", [
  "Volatility 3 on a RAM dump: windows.pslist (processes), windows.netscan (connections), windows.cmdline, windows.malfind (injected code - classic malware hiding spot), windows.handles. Memory reveals what disk hides: unpacked malware, keys, in-memory-only implants."]),
 ("Incident Response Lifecycle", [
  "NIST cycle: Preparation -> Detection & Analysis -> Containment -> Eradication -> Recovery -> Lessons Learned. Detection sources: SIEM alerts (Wazuh), EDR, IDS, user reports. During analysis, classify severity and scope: which hosts, which accounts, what data.",
  "Containment: isolate the host from the network (not power off if you need RAM), reset compromised credentials, block IOCs at firewall/DNS. Eradication: remove malware, close the entry vector (patch!). Recovery: restore from known-clean backups, monitor aggressively for re-infection."]),
 ("Building an IR-Ready Environment", [
  "Centralize logs off-box (attackers wipe local logs), enable PowerShell/process command-line logging, keep offline backups (3-2-1 rule), maintain an asset inventory and an IR runbook with contacts. Practice with tabletop scenarios and platforms like LetsDefend/CyberDefenders."])])
}

def build(fname, title, sections):
    doc = SimpleDocTemplate(os.path.join(OUT, fname + '.pdf'), pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm,
        title='CyTech - ' + title, author='CyTech Academy')
    h1 = ParagraphStyle('h1', fontName='Helvetica-Bold', fontSize=22, textColor=ACC, spaceAfter=14)
    h2 = ParagraphStyle('h2', fontName='Helvetica-Bold', fontSize=15, textColor=GREEN, spaceBefore=16, spaceAfter=8)
    body = ParagraphStyle('body', fontName='Helvetica', fontSize=11, leading=16, textColor=DARK, spaceAfter=8)
    sm = ParagraphStyle('sm', fontName='Helvetica-Oblique', fontSize=9, textColor=HexColor('#666666'))
    story = [Paragraph('CYTECH ACADEMY', ParagraphStyle('brand', fontName='Helvetica-Bold', fontSize=12, textColor=GREEN)),
             Spacer(1, 40), Paragraph(title, h1),
             Paragraph('Complete Study Notes - beginner friendly, exam and lab ready.', sm),
             Spacer(1, 20), Paragraph('(c) CyTech. For enrolled students. Unauthorized attack is illegal - practice only in labs.', sm),
             PageBreak()]
    story.append(Paragraph('Table of Contents', h1))
    for i, (t, _) in enumerate(sections, 1):
        story.append(Paragraph('%d. %s' % (i, t), body))
    story.append(PageBreak())
    for t, paras in sections:
        story.append(Paragraph(t, h2))
        for p in paras:
            story.append(Paragraph(p, body))
        story.append(Spacer(1, 6))
    def footer(canvas, doc_):
        canvas.saveState(); canvas.setFont('Helvetica', 8); canvas.setFillColor(GREEN)
        canvas.drawString(2*cm, 1*cm, 'CyTech Academy - ' + title)
        canvas.drawRightString(A4[0]-2*cm, 1*cm, 'Page %d' % doc_.page)
        canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print('built', fname)

if __name__ == '__main__':
    for k, (title, secs) in CONTENT.items():
        build(k, title, secs)
    print('ALL PDFS DONE')
