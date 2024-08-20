# RedTools

Set of tools developed by me to help me with my day-to-day activites as Penetration Tester.

## Scan Scope with Nmap (SSN)

Simple bash script that I've created to partially automate the process of Infrastracture Penetration Tests. I am planning to develop it further and include many other checks.

The `scope.txt` file should be defined by user. On the other hand, `scope-smb.txt` is empty because it's going to fill itself up while discovering new open SMB ports using TCP scan.

```bash
# Setup
chmod +x SSN.sh

# Run TCP detailed scan with port discovery
sudo ./SSN.sh tcp
# Run UDP scan on top 1000 ports
sudo ./SSN.sh udp
# Run SMB checks for hosts that are defined in scope-smb.txt
sudo ./SSN.sh smb
```

![SSN Scan](./images/ssn-scan.png)

![SSN Scan Results](./images/nmap-tcp-scan-results.png)

## Disclaimer

RedTools repository is intended solely for the purpose of testing and validating scopes of legitimate penetration tests. These tools are designed to assist administrators and auditors in ensuring that networks and devices adhere to predefined standards and guidelines.

The creators and maintainers of this tool are not responsible for any misuse or legal implications arising from its use. Always ensure that you have the proper authorization before performing any configuration analysis.
