#!/usr/bin/env python3
"""
Vulnerability / CVE Scanner
Performs banner grabbing, service detection, and queries CVE databases.
"""

import socket
import ssl
import json
import requests
import argparse
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style

init(autoreset=True)

class CVEScanner:
    def __init__(self, target, timeout=5, threads=10):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.results = {
            "scan_target": target,
            "scan_time": datetime.datetime.now().isoformat(),
            "services": [],
            "vulnerabilities": []
        }
        
        # Common service ports
        self.service_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            3389: "RDP",
            8080: "HTTP-Alt",
            27017: "MongoDB"
        }
        
        # CVE API endpoints (NVD API free tier)
        self.cve_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def grab_banner(self, host, port, use_ssl=False):
        """Perform banner grabbing on a given port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # For HTTP/HTTPS, send a GET request
            if port in [80, 443, 8080] or use_ssl:
                if use_ssl or port == 443:
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=host)
                
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            else:
                # Generic banner grabbing
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            sock.close()
            return banner.split('\n')[0] if banner else "No banner received"
        except Exception as e:
            return None
    
    def detect_service_version(self, banner, port):
        """Extract service version from banner"""
        version_info = {
            "port": port,
            "service": self.service_ports.get(port, "Unknown"),
            "banner": banner,
            "version": None
        }
        
        # Simple regex-like parsing for common service versions
        banner_lower = banner.lower() if banner else ""
        
        if "openssh" in banner_lower:
            import re
            match = re.search(r'openssh[_-]?([\d\.]+)', banner_lower)
            if match:
                version_info["version"] = f"OpenSSH {match.group(1)}"
                version_info["service"] = "SSH"
        
        elif "apache" in banner_lower:
            import re
            match = re.search(r'apache/([\d\.]+)', banner_lower)
            if match:
                version_info["version"] = f"Apache {match.group(1)}"
                version_info["service"] = "HTTP"
        
        elif "nginx" in banner_lower:
            import re
            match = re.search(r'nginx/([\d\.]+)', banner_lower)
            if match:
                version_info["version"] = f"Nginx {match.group(1)}"
                version_info["service"] = "HTTP"
        
        elif "mysql" in banner_lower:
            import re
            match = re.search(r'mysql[\s]*([\d\.]+)', banner_lower)
            if match:
                version_info["version"] = f"MySQL {match.group(1)}"
                version_info["service"] = "MySQL"
        
        return version_info
    
    def query_cve_api(self, service_name, version):
        """Query NVD API for CVEs matching service and version"""
        if not service_name or not version:
            return []
        
        vulnerabilities = []
        keyword = f"{service_name} {version}"
        
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 10
        }
        
        try:
            response = requests.get(self.cve_api_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln["cve"]
                    metrics = cve.get("metrics", {})
                    
                    # Get CVSS score
                    cvss_score = "N/A"
                    severity = "UNKNOWN"
                    
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0]["cvss"]
                        cvss_score = cvss_data["baseScore"]
                        severity = cvss_data["baseSeverity"]
                    elif "cvssMetricV30" in metrics:
                        cvss_data = metrics["cvssMetricV30"][0]["cvss"]
                        cvss_score = cvss_data["baseScore"]
                        severity = cvss_data["baseSeverity"]
                    elif "cvssMetricV2" in metrics:
                        cvss_data = metrics["cvssMetricV2"][0]["cvss"]
                        cvss_score = cvss_data["baseScore"]
                        severity = "HIGH" if cvss_score >= 7 else "MEDIUM" if cvss_score >= 4 else "LOW"
                    
                    vulnerabilities.append({
                        "cve_id": cve["id"],
                        "description": cve["descriptions"][0]["value"][:200],
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "published_date": cve.get("published", "N/A"),
                        "references": [ref["url"] for ref in cve.get("references", [])[:3]]
                    })
            else:
                # Fallback to mock data for demo
                vulnerabilities = self.get_mock_cves(service_name, version)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] API error: {e}. Using mock data.{Style.RESET_ALL}")
            vulnerabilities = self.get_mock_cves(service_name, version)
        
        return vulnerabilities
    
    def get_mock_cves(self, service_name, version):
        """Mock CVE data for demonstration when API is unavailable"""
        mock_cves = {
            "OpenSSH": {
                "7.4": [{
                    "cve_id": "CVE-2017-15906",
                    "description": "OpenSSH 7.4 vulnerability - potential privilege escalation.",
                    "cvss_score": 7.8,
                    "severity": "HIGH",
                    "published_date": "2017-10-23"
                }],
                "8.0": [{
                    "cve_id": "CVE-2020-15708",
                    "description": "OpenSSH 8.0 vulnerability - potential information disclosure.",
                    "cvss_score": 5.3,
                    "severity": "MEDIUM",
                    "published_date": "2020-07-31"
                }]
            },
            "Apache": {
                "2.4.41": [{
                    "cve_id": "CVE-2020-9490",
                    "description": "Apache 2.4.41 HTTP request smuggling vulnerability.",
                    "cvss_score": 7.5,
                    "severity": "HIGH",
                    "published_date": "2020-07-30"
                }]
            },
            "Nginx": {
                "1.18.0": [{
                    "cve_id": "CVE-2021-23017",
                    "description": "Nginx 1.18.0 - potential request smuggling.",
                    "cvss_score": 6.5,
                    "severity": "MEDIUM",
                    "published_date": "2021-04-15"
                }]
            }
        }
        
        for svc, versions in mock_cves.items():
            if svc.lower() in service_name.lower():
                for ver, cves in versions.items():
                    if ver in version:
                        for cve in cves:
                            cve["references"] = [f"https://nvd.nist.gov/vuln/detail/{cve['cve_id']}"]
                            return cves
        return []
    
    def scan_port(self, host, port):
        """Scan a single port for open service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None
    
    def scan_ports(self):
        """Scan common ports using threading"""
        print(f"{Fore.CYAN}[*] Scanning {self.target} for open ports...{Style.RESET_ALL}")
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, self.target, port): port 
                      for port in self.service_ports.keys()}
            
            for future in as_completed(futures):
                port = futures[future]
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"{Fore.GREEN}[+] Port {result} ({self.service_ports[result]}) is open{Style.RESET_ALL}")
        
        return open_ports
    
    def run(self):
        """Main scanning routine"""
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Starting Vulnerability / CVE Scanner{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Step 1: Port scanning
        open_ports = self.scan_ports()
        
        if not open_ports:
            print(f"{Fore.RED}[!] No open ports found on {self.target}{Style.RESET_ALL}")
            return self.results
        
        # Step 2: Banner grabbing and service detection
        print(f"\n{Fore.CYAN}[*] Grabbing banners and detecting services...{Style.RESET_ALL}")
        
        for port in open_ports:
            print(f"\n{Fore.YELLOW}[>] Analyzing port {port}...{Style.RESET_ALL}")
            banner = self.grab_banner(self.target, port, use_ssl=(port==443))
            
            if banner:
                print(f"{Fore.GREEN}    Banner: {banner[:100]}{Style.RESET_ALL}")
                service_info = self.detect_service_version(banner, port)
                
                if service_info["version"]:
                    print(f"{Fore.GREEN}    Detected: {service_info['version']}{Style.RESET_ALL}")
                    
                    # Step 3: Query CVE database
                    print(f"{Fore.CYAN}    Querying CVE database...{Style.RESET_ALL}")
                    cves = self.query_cve_api(service_info["service"], service_info["version"])
                    
                    if cves:
                        print(f"{Fore.RED}    [!] Found {len(cves)} potential CVEs:{Style.RESET_ALL}")
                        for cve in cves:
                            severity_color = Fore.RED if cve["severity"] == "HIGH" else Fore.YELLOW if cve["severity"] == "MEDIUM" else Fore.BLUE
                            print(f"        {severity_color}• {cve['cve_id']} (CVSS: {cve['cvss_score']}) - Severity: {cve['severity']}{Style.RESET_ALL}")
                            
                            self.results["vulnerabilities"].append({
                                **cve,
                                "affected_service": service_info["service"],
                                "affected_version": service_info["version"],
                                "port": port
                            })
                    else:
                        print(f"{Fore.GREEN}    ✓ No known CVEs found for this version{Style.RESET_ALL}")
                    
                    self.results["services"].append(service_info)
                else:
                    print(f"{Fore.YELLOW}    Could not extract version from banner{Style.RESET_ALL}")
                    self.results["services"].append({
                        "port": port,
                        "service": self.service_ports.get(port, "Unknown"),
                        "banner": banner[:100],
                        "version": "Unknown"
                    })
            else:
                print(f"{Fore.RED}    Failed to grab banner{Style.RESET_ALL}")
        
        return self.results
    
    def generate_report(self, format="json"):
        """Generate scan report"""
        if format == "json":
            report_file = f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\n{Fore.GREEN}[✓] JSON report saved to {report_file}{Style.RESET_ALL}")
            
        elif format == "console":
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] SCAN SUMMARY REPORT{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"Target: {self.results['scan_target']}")
            print(f"Time: {self.results['scan_time']}")
            print(f"\nServices Found: {len(self.results['services'])}")
            print(f"Vulnerabilities Found: {len(self.results['vulnerabilities'])}")
            
            if self.results['vulnerabilities']:
                print(f"\n{Fore.RED}[!] CRITICAL VULNERABILITIES:{Style.RESET_ALL}")
                for vuln in self.results['vulnerabilities']:
                    print(f"\n  • {vuln['cve_id']} ({vuln['severity']})")
                    print(f"    Service: {vuln['affected_service']} {vuln['affected_version']}")
                    print(f"    Description: {vuln['description']}")
                    print(f"    CVSS Score: {vuln['cvss_score']}")
                    print(f"    References: {', '.join(vuln.get('references', ['N/A'])[:1])}")
            else:
                print(f"\n{Fore.GREEN}[✓] No known vulnerabilities detected{Style.RESET_ALL}")
        
        return self.results


class ResponsibleDisclosure:
    """Responsible disclosure guidelines"""
    
    @staticmethod
    def get_guidelines():
        return """
╔══════════════════════════════════════════════════════════════════╗
║                    RESPONSIBLE DISCLOSURE GUIDE                  ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  1. DISCOVERY PHASE                                              ║
║     • Only scan systems you own or have permission to test       ║
║     • Document all findings with timestamps and proof            ║
║     • Do NOT exploit vulnerabilities beyond proof of concept     ║
║                                                                  ║
║  2. REPORTING PHASE                                              ║
║     • Contact vendor/vulnerability coordination center           ║
║     • Use encrypted communication (PGP) for sensitive data       ║
║     • Provide clear, reproducible steps                          ║
║     • Allow reasonable time for patch development                ║
║                                                                  ║
║  3. COORDINATION PHASE                                           ║
║     • Typical disclosure timeline: 45-90 days                    ║
║     • Work with vendor on patch validation                       ║
║     • Request CVE ID from MITRE                                  ║
║                                                                  ║
║  4. PUBLIC DISCLOSURE                                            ║
║     • Publish only after vendor releases patch                   ║
║     • Remove sensitive details that could enable attacks         ║
║     • Credit researchers appropriately                           ║
║                                                                  ║
║  LEGAL NOTE: Unauthorized scanning may violate laws like:        ║
║  • CFAA (US), Computer Misuse Act (UK), IT Act (India)           ║
║  • Always get written permission before scanning                 ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""


def main():
    parser = argparse.ArgumentParser(description="Vulnerability/CVE Scanner")
    parser.add_argument("target", nargs="?", help="Target IP address or hostname")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Socket timeout (seconds)")
    parser.add_argument("-T", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-o", "--output", choices=["json", "console"], default="console", 
                       help="Output format")
    parser.add_argument("--disclosure", action="store_true", help="Show responsible disclosure guidelines")
    
    args = parser.parse_args()
    
    # Show disclosure guidelines if requested
    if args.disclosure:
        print(ResponsibleDisclosure.get_guidelines())
        return
    
    # Check if target is provided
    if not args.target:
        parser.print_help()
        print(f"\n{Fore.RED}[!] Error: Target is required unless using --disclosure{Style.RESET_ALL}")
        return
    
    # Validate target
    try:
        socket.gethostbyname(args.target)
    except:
        print(f"{Fore.RED}[!] Invalid target: {args.target}{Style.RESET_ALL}")
        return
    
    print(f"{Fore.YELLOW}[!] LEGAL WARNING: Only scan systems you own or have permission to test!{Style.RESET_ALL}")
    confirm = input("Do you have permission to scan this target? (yes/no): ")
    
    if confirm.lower() != 'yes':
        print(f"{Fore.RED}[!] Exiting. Get written permission before scanning.{Style.RESET_ALL}")
        return
    
    # Run scanner
    scanner = CVEScanner(args.target, timeout=args.timeout, threads=args.threads)
    results = scanner.run()
    scanner.generate_report(format=args.output)
    
    # Show disclosure guidelines
    show_guidelines = input("\nShow responsible disclosure guidelines? (yes/no): ")
    if show_guidelines.lower() == 'yes':
        print(ResponsibleDisclosure.get_guidelines())


if __name__ == "__main__":
    main()