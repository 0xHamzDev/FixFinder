import socket
import subprocess
import argparse
import nmap

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", metavar="TARGET", nargs="+",
                        help="IP address(es) or domain(s) to scan")
    parser.add_argument("-p", "--ports", default="1-65535",
                        help="Port range to scan (default: 1-65535)")
    parser.add_argument("-s", "--sev", default="medium",
                        choices=["low", "medium", "high"],
                        help="Severity level of vulnerabilities to scan for")
    parser.add_argument("-local", action="store_true",
                        help="Automatically use local IP address for the scan")
    args = parser.parse_args()
    
    print("Command line arguments parsed successfully")
    
    
    # Use local IP address if -local flag is provided
    if args.local:
        local_ip = socket.gethostbyname(socket.gethostname())
        print(f"Scanning {local_ip}...")
        args.targets = [local_ip]
    elif not args.targets:
        print("Error: no targets specified")
        exit()

    # Validate input
    targets = []
    for target in args.targets:
        try:
            socket.inet_aton(target)
            targets.append(target)
        except socket.error:
            try:
                ip = socket.gethostbyname(target)
                targets.append(ip)
            except socket.gaierror:
                print(f"Error: '{target}' is not a valid IP address or domain name")
                exit()
    print(f"Validated targets: {targets}")

    print("Input validation successful")

    # Scan hosts
    scan_results = []
    for target in targets:
        result = {"target": target}
        print(f"Scanning {target} for vulnerabilities...")
        # Scan for vulnerabilities
        vulnerabilities = scan_vulnerabilities(target)
        result["vulnerabilities"] = vulnerabilities
        print(f"Scanning {target} for open ports...")
        # Scan for open ports
        open_ports = scan_open_ports(target, args.ports)
        result["open_ports"] = open_ports
        print(f"Scanning {target} for misconfigurations...")
        # Scan for misconfigurations
        misconfigurations = scan_misconfigurations(target)
        result["misconfigurations"] = misconfigurations
        # Add result to scan results list
        scan_results.append(result)
        
        print("Scanning complete")

    # Generate report
    generate_report(scan_results)

    print("Report generated successfully")


def scan_open_ports(target, port_range):
    # Use nmap to scan for open ports
    nm = nmap.PortScanner()
    nm.scan(target, arguments=f"-p {port_range}")
    open_ports = []
    for port in nm[target]["tcp"]:
        if nm[target]["tcp"][port]["state"] == "open":
            open_ports.append(port)
    return open_ports


def scan_vulnerabilities(target):
    # Use an external tool like OpenVAS to scan for vulnerabilities
    # and collect data in a dictionary
    vuln_data = {
        "target": target,
        "vulnerabilities": [
            {
                "name": "CVE-2020-1234",
                "severity": "High",
                "description": "A remote attacker could exploit this vulnerability...",
                "solution": "Apply the appropriate patch or upgrade.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2020-1234",
                    "https://example.com/security-advisory/cve-2020-1234",
                ],
            },
            {
                "name": "CVE-2021-5678",
                "severity": "Medium",
                "description": "An attacker could exploit this vulnerability...",
                "solution": "Update to the latest version or apply the available patches.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-5678",
                    "https://example.com/security-advisory/cve-2021-5678",
                ],
            },
            # More vulnerabilities...
        ],
    }

    return vuln_data


def scan_misconfigurations(target):
    # Use an external tool like OpenVAS or a custom script to scan for misconfigurations
    # and collect data in a dictionary
    misconfig_data = {
        "target": target,
        "misconfigurations": [
            {
                "name": "Weak password",
                "severity": "High",
                "description": "The password for this user is weak and can be easily guessed...",
                "solution": "Change the password to a strong one.",
                "references": [
                    "https://example.com/security-policy/strong-passwords",
                ],
            },
            {
                "name": "Open ports for unnecessary services",
                "severity": "Medium",
                "description": "There are several ports open for services that are not needed...",
                "solution": "Close the unnecessary ports.",
                "references": [
                    "https://example.com/security-policy/reduce-attack-surface",
                ],
            },
            # More misconfigurations...
        ],
    }
    
    return misconfig_data

def generate_report(scan_results):
    for result in scan_results:
        # Print target information
        print(f"Results for target: {result['target']}")
        print("-" * 50)
        # Print open ports
        if result["open_ports"]:
            print("Open ports:")
            for port in result["open_ports"]:
                print(f"\t{port}")
        else:
            print("No open ports found.")
        print("-" * 50)
        # Print vulnerabilities
        if result["vulnerabilities"]:
            print("Vulnerabilities:")
            for vulnerability in result["vulnerabilities"]:
                if vulnerability["severity"] == "low":
                    continue  # Skip low severity vulnerabilities
                print(f"\tName: {vulnerability['name']}")
                print(f"\tSeverity: {vulnerability['severity']}")
                print(f"\tDescription: {vulnerability['description']}")
                print(f"\tSolution: {vulnerability['solution']}")
                print(f"\tReferences: {', '.join(vulnerability['references'])}")
                print("-" * 50)
        else:
            print("No vulnerabilities found.")
        print("-" * 50)
        # Print misconfigurations
        if result["misconfigurations"]:
            print("Misconfigurations:")
            for misconfiguration in result["misconfigurations"]:
                if misconfiguration["severity"] == "low":
                    continue  # Skip low severity misconfigurations
                print(f"\tName: {misconfiguration['name']}")
                print(f"\tSeverity: {misconfiguration['severity']}")
                print(f"\tDescription: {misconfiguration['description']}")
                print(f"\tSolution: {misconfiguration['solution']}")
                print(f"\tReferences: {', '.join(misconfiguration['references'])}")
                print("-" * 50)
        else:
            print("No misconfigurations found.")
        print("=" * 100)

def scan_with_nmap(target, port_range, severity):
    # If "-local" flag is passed, detect the local IP address
    if target == '-local':
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        target = s.getsockname()[0]
        s.close()

    # Use nmap to scan for vulnerabilities and collect data in a dictionary
    nm = nmap.PortScanner()
    nm.scan(hosts=target, ports=port_range, arguments='-sV -sC -O --script vuln')
    vulnerabilities_data = {
        "target": target,
        "port_range": port_range,
        "severity": severity,
        "vulnerabilities": {}
    }

    # Filter vulnerabilities based on severity
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                port_info = nm[host][proto][port]
                for vuln in port_info["script_results"]["vuln"]:
                    if vuln["severity"] == severity:
                        if host not in vulnerabilities_data["vulnerabilities"]:
                            vulnerabilities_data["vulnerabilities"][host] = {}
                        if proto not in vulnerabilities_data["vulnerabilities"][host]:
                            vulnerabilities_data["vulnerabilities"][host][proto] = {}
                        vulnerabilities_data["vulnerabilities"][host][proto][port] = {
                            "name": vuln["id"],
                            "description": vuln["output"],
                            "severity": vuln["severity"],
                            "cve": vuln["cve"] if "cve" in vuln else ""
                        }

    return vulnerabilities_data

def scan_with_openvas(target, severity):
    # Use an external tool like OpenVAS to scan for vulnerabilities
    # and collect data in a dictionary
    vuln_data = {
        "target": target,
        "vulnerabilities": [
            {
                "name": "CVE-2020-1234",
                "severity": "High",
                "description": "A remote attacker could exploit this vulnerability...",
                "solution": "Apply the appropriate patch or upgrade.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2020-1234",
                    "https://example.com/security-advisory/cve-2020-1234",
                ],
            },
            {
                "name": "CVE-2021-5678",
                "severity": "Medium",
                "description": "An attacker could exploit this vulnerability...",
                "solution": "Update to the latest version or apply the available patches.",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-5678",
                    "https://example.com/security-advisory/cve-2021-5678",
                ],
            },
            # More vulnerabilities...
        ],
    }

    # Filter vulnerabilities based on severity level
    vulnerabilities = []
    for vuln in vuln_data["vulnerabilities"]:
        if vuln["severity"] == severity:
            vulnerabilities.append(vuln)

    return vulnerabilities

from FixFinder import main

if __name__ == "__main__":
    main()
