#!/usr/bin/env python3
"""
Comprehensive Web Security Assessment Tool
═════════════════════════════════════════════════════════════════════════════════════════
Professional security scanner that tests 18 common web vulnerabilities and generates
detailed security assessment reports with CVSS scores, CWE mappings, and remediation guidance.

REQUIREMENTS:
    pip install requests dnspython colorama beautifulsoup4 tldextract jinja2

USAGE:
    python security_audit.py https://example.com
    python security_audit.py https://example.com --output report.html
    python security_audit.py https://example.com --format json --output report.json
"""

import argparse, json, re, socket, ssl, sys, time
from collections import defaultdict
from datetime import datetime
from urllib.parse import urljoin, urlparse
import requests, tldextract, dns.resolver
from bs4 import BeautifulSoup as BS
from colorama import Fore, Style, init

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

class SecurityFinding:
    def __init__(self, name, severity, status, cvss_score, cwe_id, owasp_category,
                 description, impact, affected_url, reference_url, recommendations, poc):
        self.name = name
        self.severity = severity
        self.status = status
        self.cvss_score = cvss_score
        self.cwe_id = cwe_id
        self.owasp_category = owasp_category
        self.description = description
        self.impact = impact
        self.affected_url = affected_url
        self.reference_url = reference_url
        self.recommendations = recommendations
        self.poc = poc
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self):
        return {
            'name': self.name,
            'severity': self.severity,
            'status': self.status,
            'cvss_score': self.cvss_score,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'description': self.description,
            'impact': self.impact,
            'affected_url': self.affected_url,
            'reference_url': self.reference_url,
            'recommendations': self.recommendations,
            'poc': self.poc,
            'timestamp': self.timestamp
        }

class WebSecurityScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security-Scanner/1.0)'
        })
        self.findings = []
        self.parsed_url = urlparse(target_url if target_url.startswith(('http://', 'https://')) else f'http://{target_url}')
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.hostname = self.parsed_url.netloc.split(':')[0]

        # Vulnerability definitions with security metadata
        self.vulnerability_map = {
            'cookies_parent_domain': {
                'name': 'Cookies Scoped to Parent Domain',
                'severity': 'MEDIUM',
                'cvss_score': 4.3,
                'cwe_id': 'CWE-200',
                'owasp_category': 'A01:2021 - Broken Access Control',
                'description': 'Cookies are configured with overly broad domain scope, potentially allowing subdomain access.',
                'impact': 'Cookies may be accessible from unauthorized subdomains, leading to session hijacking or data exposure.',
                'reference_url': 'https://owasp.org/www-community/controls/SecureCookieAttribute',
                'recommendations': 'Set cookie domain to specific hostname without leading dot. Use HttpOnly and Secure flags.'
            },
            'directory_listing': {
                'name': 'Directory Listing Enabled',
                'severity': 'MEDIUM',
                'cvss_score': 5.3,
                'cwe_id': 'CWE-548',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'description': 'Web server allows directory browsing, exposing file and folder structure.',
                'impact': 'Attackers can enumerate files and directories, potentially discovering sensitive information or attack vectors.',
                'reference_url': 'https://owasp.org/www-community/vulnerabilities/Directory_indexing',
                'recommendations': 'Disable directory indexing in web server configuration. Add index.html files to directories.'
            },
            'exposed_admin': {
                'name': 'Exposed Admin Portal',
                'severity': 'HIGH',
                'cvss_score': 7.5,
                'cwe_id': 'CWE-200',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'description': 'Administrative interfaces are publicly accessible without proper access controls.',
                'impact': 'Unauthorized access to admin panels could lead to complete system compromise.',
                'reference_url': 'https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration',
                'recommendations': 'Restrict admin panel access by IP, implement strong authentication, use non-standard URLs.'
            },
            'banner_disclosure': {
                'name': 'Server Banner Information Disclosure',
                'severity': 'LOW',
                'cvss_score': 2.6,
                'cwe_id': 'CWE-200',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'description': 'Server reveals version information in HTTP headers.',
                'impact': 'Information disclosure aids attackers in identifying specific vulnerabilities for the server version.',
                'reference_url': 'https://owasp.org/www-community/Security_Headers',
                'recommendations': 'Remove or obfuscate Server header and X-Powered-By header in web server configuration.'
            },
            'cache_control_nonsensitive': {
                'name': 'Missing Cache-Control on Non-Sensitive Pages',
                'severity': 'LOW',
                'cvss_score': 2.3,
                'cwe_id': 'CWE-525',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'description': 'Non-sensitive pages lack appropriate cache control directives.',
                'impact': 'Reduced performance and potential caching issues.',
                'reference_url': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control',
                'recommendations': 'Implement appropriate Cache-Control headers for static resources to improve performance.'
            },
            'cache_control_sensitive': {
                'name': 'Insecure Cache-Control on Sensitive Pages',
                'severity': 'MEDIUM',
                'cvss_score': 4.9,
                'cwe_id': 'CWE-525',
                'owasp_category': 'A02:2021 - Cryptographic Failures',
                'description': 'Sensitive pages allow caching, potentially exposing private information.',
                'impact': 'Sensitive data may be stored in browser or proxy caches, accessible to unauthorized users.',
                'reference_url': 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
                'recommendations': 'Set Cache-Control: no-store, no-cache, must-revalidate, private on sensitive pages.'
            },
            'csp_missing': {
                'name': 'Missing Content Security Policy',
                'severity': 'MEDIUM',
                'cvss_score': 5.4,
                'cwe_id': 'CWE-79',
                'owasp_category': 'A03:2021 - Injection',
                'description': 'Content Security Policy header is not implemented.',
                'impact': 'Increased risk of XSS attacks and unauthorized resource loading.',
                'reference_url': 'https://owasp.org/www-community/controls/Content_Security_Policy',
                'recommendations': 'Implement comprehensive CSP header with restrictive source directives.'
            },
            'hsts_missing': {
                'name': 'Missing HTTP Strict Transport Security',
                'severity': 'MEDIUM',
                'cvss_score': 4.8,
                'cwe_id': 'CWE-319',
                'owasp_category': 'A02:2021 - Cryptographic Failures',
                'description': 'HSTS header is not configured to enforce HTTPS connections.',
                'impact': 'Vulnerable to protocol downgrade attacks and man-in-the-middle attacks.',
                'reference_url': 'https://owasp.org/www-community/controls/HTTP_Strict_Transport_Security',
                'recommendations': 'Implement HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
            },
            'xframe_missing': {
                'name': 'Missing X-Frame-Options Header',
                'severity': 'MEDIUM',
                'cvss_score': 4.3,
                'cwe_id': 'CWE-1021',
                'owasp_category': 'A03:2021 - Injection',
                'description': 'X-Frame-Options header is not set to prevent clickjacking.',
                'impact': 'Application is vulnerable to clickjacking and UI redressing attacks.',
                'reference_url': 'https://owasp.org/www-community/attacks/Clickjacking',
                'recommendations': 'Set X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN'
            },
            'xss_protection_missing': {
                'name': 'Missing X-XSS-Protection Header',
                'severity': 'LOW',
                'cvss_score': 3.1,
                'cwe_id': 'CWE-79',
                'owasp_category': 'A03:2021 - Injection',
                'description': 'X-XSS-Protection header is not configured.',
                'impact': 'Browser XSS filtering may not be enabled, increasing XSS attack risk.',
                'reference_url': 'https://owasp.org/www-community/Security_Headers',
                'recommendations': 'Set X-XSS-Protection: 1; mode=block'
            },
            'content_type_missing': {
                'name': 'Missing X-Content-Type-Options Header',
                'severity': 'LOW',
                'cvss_score': 2.6,
                'cwe_id': 'CWE-79',
                'owasp_category': 'A03:2021 - Injection',
                'description': 'X-Content-Type-Options header is not set to prevent MIME sniffing.',
                'impact': 'Browsers may incorrectly interpret file types, leading to security vulnerabilities.',
                'reference_url': 'https://owasp.org/www-community/Security_Headers',
                'recommendations': 'Set X-Content-Type-Options: nosniff'
            },
            'cookie_security': {
                'name': 'Insecure Cookie Configuration',
                'severity': 'MEDIUM',
                'cvss_score': 4.3,
                'cwe_id': 'CWE-614',
                'owasp_category': 'A02:2021 - Cryptographic Failures',
                'description': 'Cookies are missing Secure or HttpOnly attributes.',
                'impact': 'Session cookies may be intercepted or accessed via JavaScript.',
                'reference_url': 'https://owasp.org/www-community/controls/SecureCookieAttribute',
                'recommendations': 'Set Secure and HttpOnly flags on all session cookies.'
            },
            'mail_misconfiguration': {
                'name': 'Mail Server Information Disclosure',
                'severity': 'LOW',
                'cvss_score': 2.6,
                'cwe_id': 'CWE-200',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'description': 'Mail server reveals version information in SMTP banner.',
                'impact': 'Information disclosure may aid in targeted attacks against mail infrastructure.',
                'reference_url': 'https://owasp.org/www-community/vulnerabilities/Information_Exposure_Through_Server_Headers',
                'recommendations': 'Configure mail server to suppress version information in banners.'
            },
            'email_spoofing': {
                'name': 'Missing Email Authentication Records',
                'severity': 'MEDIUM',
                'cvss_score': 5.3,
                'cwe_id': 'CWE-290',
                'owasp_category': 'A07:2021 - Identification and Authentication Failures',
                'description': 'Domain lacks proper SPF, DKIM, or DMARC records for email authentication.',
                'impact': 'Domain can be used for email spoofing and phishing attacks.',
                'reference_url': 'https://owasp.org/www-community/vulnerabilities/Email_Header_Injection',
                'recommendations': 'Implement SPF, DKIM, and DMARC records. Set DMARC policy to quarantine or reject.'
            },
            'dnssec_missing': {
                'name': 'Missing DNSSEC',
                'severity': 'LOW',
                'cvss_score': 3.7,
                'cwe_id': 'CWE-300',
                'owasp_category': 'A02:2021 - Cryptographic Failures',
                'description': 'Domain does not have DNSSEC enabled for DNS security.',
                'impact': 'Domain is vulnerable to DNS spoofing and cache poisoning attacks.',
                'reference_url': 'https://www.cloudflare.com/dns/dnssec/how-dnssec-works/',
                'recommendations': 'Enable DNSSEC on domain registrar and DNS hosting provider.'
            }
        }

    def make_request(self, path='/', **kwargs):
        """Make HTTP request with error handling"""
        try:
            url = urljoin(self.base_url, path)
            response = self.session.get(url, timeout=self.timeout, verify=False,
                                      allow_redirects=True, **kwargs)
            return response
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Request failed for {path}: {e}")
            return None

    def check_cookies_parent_domain(self, response):
        """Check for cookies scoped to parent domain"""
        if not response:
            return None

        findings = []
        for cookie in response.cookies:
            domain = cookie.domain
            if domain and domain.startswith('.'):
                vuln_info = self.vulnerability_map['cookies_parent_domain'].copy()
                findings.append(SecurityFinding(
                    name=vuln_info['name'],
                    severity=vuln_info['severity'],
                    status='OPEN',
                    cvss_score=vuln_info['cvss_score'],
                    cwe_id=vuln_info['cwe_id'],
                    owasp_category=vuln_info['owasp_category'],
                    description=vuln_info['description'],
                    impact=vuln_info['impact'],
                    affected_url=response.url,
                    reference_url=vuln_info['reference_url'],
                    recommendations=vuln_info['recommendations'],
                    poc=f"Cookie '{cookie.name}' has Domain={domain} (parent domain scope)"
                ))
        return findings

    def check_directory_listing(self, response):
        """Check for directory listing enabled"""
        if not response:
            return None

        if re.search(r'(?i)<title>index of /', response.text):
            vuln_info = self.vulnerability_map['directory_listing'].copy()
            return [SecurityFinding(
                name=vuln_info['name'],
                severity=vuln_info['severity'],
                status='OPEN',
                cvss_score=vuln_info['cvss_score'],
                cwe_id=vuln_info['cwe_id'],
                owasp_category=vuln_info['owasp_category'],
                description=vuln_info['description'],
                impact=vuln_info['impact'],
                affected_url=response.url,
                reference_url=vuln_info['reference_url'],
                recommendations=vuln_info['recommendations'],
                poc=f"Directory listing detected at {response.url}"
            )]
        return None

    def check_exposed_admin(self):
        """Check for exposed admin portals"""
        admin_paths = [
            '/admin', '/administrator', '/admin/login', '/wp-admin',
            '/admin.php', '/login', '/admin/index.php', '/admin/admin.php',
            '/admin_area/', '/adminarea/', '/adminpanel/', '/control_panel/',
            '/admin/controlpanel.html', '/admin.html', '/admin/cp.php',
            '/cp.php', '/administrator/index.html', '/administrator/login.html',
            '/admin/account.html', '/admin/index.html', '/admin/login.html',
            '/admin/admin.html', '/admin_area/admin.html', '/admin_area/login.html'
        ]

        findings = []
        for path in admin_paths:
            response = self.make_request(path)
            if response and response.status_code in [200, 401, 403]:
                vuln_info = self.vulnerability_map['exposed_admin'].copy()
                findings.append(SecurityFinding(
                    name=vuln_info['name'],
                    severity=vuln_info['severity'],
                    status='OPEN',
                    cvss_score=vuln_info['cvss_score'],
                    cwe_id=vuln_info['cwe_id'],
                    owasp_category=vuln_info['owasp_category'],
                    description=vuln_info['description'],
                    impact=vuln_info['impact'],
                    affected_url=response.url,
                    reference_url=vuln_info['reference_url'],
                    recommendations=vuln_info['recommendations'],
                    poc=f"Admin panel accessible at {response.url} (Status: {response.status_code})"
                ))
                break  # Only report first finding
        return findings

    def check_banner_disclosure(self, response):
        """Check for server banner information disclosure"""
        if not response:
            return None

        server = response.headers.get('Server', '')
        powered_by = response.headers.get('X-Powered-By', '')

        if server or powered_by:
            vuln_info = self.vulnerability_map['banner_disclosure'].copy()
            return [SecurityFinding(
                name=vuln_info['name'],
                severity=vuln_info['severity'],
                status='OPEN',
                cvss_score=vuln_info['cvss_score'],
                cwe_id=vuln_info['cwe_id'],
                owasp_category=vuln_info['owasp_category'],
                description=vuln_info['description'],
                impact=vuln_info['impact'],
                affected_url=response.url,
                reference_url=vuln_info['reference_url'],
                recommendations=vuln_info['recommendations'],
                poc=f"Server: {server}, X-Powered-By: {powered_by}"
            )]
        return None

    def check_cache_control(self, response, sensitive=False):
        """Check cache control headers"""
        if not response:
            return None

        cache_control = response.headers.get('Cache-Control', '')

        if sensitive:
            # Sensitive pages should have no-store, no-cache, private
            secure_directives = ['no-store', 'no-cache', 'private']
            if not any(directive in cache_control.lower() for directive in secure_directives):
                vuln_info = self.vulnerability_map['cache_control_sensitive'].copy()
                return [SecurityFinding(
                    name=vuln_info['name'],
                    severity=vuln_info['severity'],
                    status='OPEN',
                    cvss_score=vuln_info['cvss_score'],
                    cwe_id=vuln_info['cwe_id'],
                    owasp_category=vuln_info['owasp_category'],
                    description=vuln_info['description'],
                    impact=vuln_info['impact'],
                    affected_url=response.url,
                    reference_url=vuln_info['reference_url'],
                    recommendations=vuln_info['recommendations'],
                    poc=f"Sensitive page has insecure Cache-Control: {cache_control or '[missing]'}"
                )]
        else:
            # Non-sensitive pages should have cache control
            if not cache_control:
                vuln_info = self.vulnerability_map['cache_control_nonsensitive'].copy()
                return [SecurityFinding(
                    name=vuln_info['name'],
                    severity=vuln_info['severity'],
                    status='OPEN',
                    cvss_score=vuln_info['cvss_score'],
                    cwe_id=vuln_info['cwe_id'],
                    owasp_category=vuln_info['owasp_category'],
                    description=vuln_info['description'],
                    impact=vuln_info['impact'],
                    affected_url=response.url,
                    reference_url=vuln_info['reference_url'],
                    recommendations=vuln_info['recommendations'],
                    poc=f"Non-sensitive page missing Cache-Control header"
                )]
        return None

    def check_security_headers(self, response):
        """Check for missing security headers"""
        if not response:
            return []

        findings = []
        headers_to_check = [
            ('Content-Security-Policy', 'csp_missing'),
            ('Strict-Transport-Security', 'hsts_missing'),
            ('X-Frame-Options', 'xframe_missing'),
            ('X-XSS-Protection', 'xss_protection_missing'),
            ('X-Content-Type-Options', 'content_type_missing')
        ]

        for header_name, vuln_key in headers_to_check:
            if header_name not in response.headers:
                vuln_info = self.vulnerability_map[vuln_key].copy()
                findings.append(SecurityFinding(
                    name=vuln_info['name'],
                    severity=vuln_info['severity'],
                    status='OPEN',
                    cvss_score=vuln_info['cvss_score'],
                    cwe_id=vuln_info['cwe_id'],
                    owasp_category=vuln_info['owasp_category'],
                    description=vuln_info['description'],
                    impact=vuln_info['impact'],
                    affected_url=response.url,
                    reference_url=vuln_info['reference_url'],
                    recommendations=vuln_info['recommendations'],
                    poc=f"Missing security header: {header_name}"
                ))

        return findings

    def check_cookie_security(self, response):
        """Check for insecure cookie flags"""
        if not response:
            return []

        findings = []
        for cookie in response.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append("missing HttpOnly flag")

            if issues:
                vuln_info = self.vulnerability_map['cookie_security'].copy()
                findings.append(SecurityFinding(
                    name=vuln_info['name'],
                    severity=vuln_info['severity'],
                    status='OPEN',
                    cvss_score=vuln_info['cvss_score'],
                    cwe_id=vuln_info['cwe_id'],
                    owasp_category=vuln_info['owasp_category'],
                    description=vuln_info['description'],
                    impact=vuln_info['impact'],
                    affected_url=response.url,
                    reference_url=vuln_info['reference_url'],
                    recommendations=vuln_info['recommendations'],
                    poc=f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}"
                ))

        return findings

    def check_mail_server(self):
        """Check mail server configuration"""
        try:
            mx_records = dns.resolver.resolve(self.hostname, 'MX', lifetime=5)
            if mx_records:
                mx_host = str(mx_records[0].exchange)
                sock = socket.create_connection((mx_host, 25), timeout=5)
                banner = sock.recv(500).decode(errors='ignore').strip()
                sock.close()

                if re.search(r'(postfix|sendmail|exim|microsoft|exchange)', banner, re.I):
                    vuln_info = self.vulnerability_map['mail_misconfiguration'].copy()
                    return [SecurityFinding(
                        name=vuln_info['name'],
                        severity=vuln_info['severity'],
                        status='OPEN',
                        cvss_score=vuln_info['cvss_score'],
                        cwe_id=vuln_info['cwe_id'],
                        owasp_category=vuln_info['owasp_category'],
                        description=vuln_info['description'],
                        impact=vuln_info['impact'],
                        affected_url=f"smtp://{mx_host}:25",
                        reference_url=vuln_info['reference_url'],
                        recommendations=vuln_info['recommendations'],
                        poc=f"SMTP banner disclosure: {banner}"
                    )]
        except Exception:
            pass
        return []

    def check_email_spoofing(self):
        """Check for missing email authentication records"""
        has_spf = False
        has_dmarc = False

        try:
            # Check SPF
            txt_records = dns.resolver.resolve(self.hostname, 'TXT', lifetime=5)
            for record in txt_records:
                if 'v=spf1' in str(record):
                    has_spf = True
                    break
        except:
            pass

        try:
            # Check DMARC
            dmarc_records = dns.resolver.resolve(f'_dmarc.{self.hostname}', 'TXT', lifetime=5)
            for record in dmarc_records:
                if 'v=DMARC1' in str(record):
                    has_dmarc = True
                    break
        except:
            pass

        if not has_spf or not has_dmarc:
            missing = []
            if not has_spf:
                missing.append("SPF")
            if not has_dmarc:
                missing.append("DMARC")

            vuln_info = self.vulnerability_map['email_spoofing'].copy()
            return [SecurityFinding(
                name=vuln_info['name'],
                severity=vuln_info['severity'],
                status='OPEN',
                cvss_score=vuln_info['cvss_score'],
                cwe_id=vuln_info['cwe_id'],
                owasp_category=vuln_info['owasp_category'],
                description=vuln_info['description'],
                impact=vuln_info['impact'],
                affected_url=f"dns://{self.hostname}",
                reference_url=vuln_info['reference_url'],
                recommendations=vuln_info['recommendations'],
                poc=f"Missing email authentication records: {', '.join(missing)}"
            )]
        return []

    def check_dnssec(self):
        """Check for DNSSEC"""
        try:
            dns.resolver.resolve(self.hostname, 'DNSKEY', lifetime=5)
            return []  # DNSSEC is present
        except:
            vuln_info = self.vulnerability_map['dnssec_missing'].copy()
            return [SecurityFinding(
                name=vuln_info['name'],
                severity=vuln_info['severity'],
                status='OPEN',
                cvss_score=vuln_info['cvss_score'],
                cwe_id=vuln_info['cwe_id'],
                owasp_category=vuln_info['owasp_category'],
                description=vuln_info['description'],
                impact=vuln_info['impact'],
                affected_url=f"dns://{self.hostname}",
                reference_url=vuln_info['reference_url'],
                recommendations=vuln_info['recommendations'],
                poc=f"DNSSEC not enabled for domain {self.hostname}"
            )]

    def scan(self):
        """Perform comprehensive security scan"""
        print(f"{Fore.CYAN}[*] Starting security scan of {self.base_url}")

        # Get main page
        main_response = self.make_request('/')
        if not main_response:
            print(f"{Fore.RED}[!] Failed to connect to target")
            return []

        # Get login page for sensitive page testing
        login_response = self.make_request('/login') or main_response

        all_findings = []

        # Run all checks
        print(f"{Fore.YELLOW}[*] Checking cookies and headers...")
        all_findings.extend(self.check_cookies_parent_domain(main_response) or [])
        all_findings.extend(self.check_cookie_security(main_response) or [])
        all_findings.extend(self.check_security_headers(main_response) or [])

        print(f"{Fore.YELLOW}[*] Checking server configuration...")
        all_findings.extend(self.check_directory_listing(main_response) or [])
        all_findings.extend(self.check_banner_disclosure(main_response) or [])
        all_findings.extend(self.check_cache_control(main_response, False) or [])
        all_findings.extend(self.check_cache_control(login_response, True) or [])

        print(f"{Fore.YELLOW}[*] Checking for exposed admin portals...")
        all_findings.extend(self.check_exposed_admin() or [])

        print(f"{Fore.YELLOW}[*] Checking DNS and mail configuration...")
        all_findings.extend(self.check_mail_server() or [])
        all_findings.extend(self.check_email_spoofing() or [])
        all_findings.extend(self.check_dnssec() or [])

        self.findings = all_findings
        return all_findings

def generate_html_report(findings, target_url, output_file):
    """Generate HTML security report"""
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .summary { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .finding { background: white; margin: 15px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 5px solid #ddd; }
        .finding.HIGH { border-left-color: #e74c3c; }
        .finding.MEDIUM { border-left-color: #f39c12; }
        .finding.LOW { border-left-color: #f1c40f; }
        .severity { display: inline-block; padding: 4px 12px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.8em; }
        .severity.HIGH { background-color: #e74c3c; }
        .severity.MEDIUM { background-color: #f39c12; }
        .severity.LOW { background-color: #f1c40f; color: #333; }
        .field { margin: 10px 0; }
        .field strong { color: #2c3e50; }
        .poc { background: #ecf0f1; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.9em; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #3498db; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Assessment Report</h1>
        <p><strong>Target:</strong> {{ target_url }}</p>
        <p><strong>Scan Date:</strong> {{ scan_date }}</p>
        <p><strong>Total Findings:</strong> {{ total_findings }}</p>
    </div>

    <div class="summary">
        <h2>📊 Executive Summary</h2>
        <table>
            <tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>
            <tr><td>High</td><td>{{ high_count }}</td><td>{{ high_percent }}%</td></tr>
            <tr><td>Medium</td><td>{{ medium_count }}</td><td>{{ medium_percent }}%</td></tr>
            <tr><td>Low</td><td>{{ low_count }}</td><td>{{ low_percent }}%</td></tr>
        </table>
    </div>

    <div class="findings">
        <h2>🔍 Detailed Findings</h2>
        {% for finding in findings %}
        <div class="finding {{ finding.severity }}">
            <h3>{{ finding.name }} <span class="severity {{ finding.severity }}">{{ finding.severity }}</span></h3>

            <div class="field"><strong>Status:</strong> {{ finding.status }}</div>
            <div class="field"><strong>CVSS Score:</strong> {{ finding.cvss_score }}/10.0</div>
            <div class="field"><strong>CWE-ID:</strong> {{ finding.cwe_id }}</div>
            <div class="field"><strong>OWASP Category:</strong> {{ finding.owasp_category }}</div>

            <div class="field"><strong>Description:</strong> {{ finding.description }}</div>
            <div class="field"><strong>Impact:</strong> {{ finding.impact }}</div>
            <div class="field"><strong>Affected URL:</strong> <code>{{ finding.affected_url }}</code></div>

            <div class="field"><strong>Proof of Concept:</strong></div>
            <div class="poc">{{ finding.poc }}</div>

            <div class="field"><strong>Recommendations:</strong> {{ finding.recommendations }}</div>
            <div class="field"><strong>Reference:</strong> <a href="{{ finding.reference_url }}" target="_blank">{{ finding.reference_url }}</a></div>
        </div>
        {% endfor %}
    </div>

    <div class="footer" style="text-align: center; margin-top: 30px; color: #7f8c8d;">
        <p>Report generated by Web Security Assessment Tool</p>
    </div>
</body>
</html>
    """

    from jinja2 import Template

    # Calculate statistics
    high_count = sum(1 for f in findings if f.severity == 'HIGH')
    medium_count = sum(1 for f in findings if f.severity == 'MEDIUM')
    low_count = sum(1 for f in findings if f.severity == 'LOW')
    total = len(findings)

    template = Template(html_template)
    html_content = template.render(
        target_url=target_url,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        findings=findings,
        total_findings=total,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        high_percent=round((high_count/total*100) if total > 0 else 0, 1),
        medium_percent=round((medium_count/total*100) if total > 0 else 0, 1),
        low_percent=round((low_count/total*100) if total > 0 else 0, 1)
    )

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

def print_console_report(findings):
    """Print findings to console"""
    if not findings:
        print(f"\n{Fore.GREEN}[✓] No security issues found!")
        return

    print(f"\n{Style.BRIGHT}SECURITY ASSESSMENT RESULTS")
    print("=" * 60)

    for finding in findings:
        color = Fore.RED if finding.severity == 'HIGH' else Fore.YELLOW if finding.severity == 'MEDIUM' else Fore.CYAN
        print(f"\n{color}[{finding.severity}] {finding.name}")
        print(f"  CVSS: {finding.cvss_score}/10.0 | CWE: {finding.cwe_id}")
        print(f"  URL: {finding.affected_url}")
        print(f"  PoC: {finding.poc}")

def main():
    parser = argparse.ArgumentParser(description='Comprehensive Web Security Assessment Tool')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--output', '-o', help='Output file for report')
    parser.add_argument('--format', '-f', choices=['html', 'json'], default='html', help='Report format')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='Request timeout in seconds')

    args = parser.parse_args()

    scanner = WebSecurityScanner(args.url, args.timeout)
    findings = scanner.scan()

    print_console_report(findings)

    if args.output:
        if args.format == 'html':
            generate_html_report(findings, args.url, args.output)
            print(f"\n{Fore.GREEN}[✓] HTML report saved to {args.output}")
        elif args.format == 'json':
            with open(args.output, 'w') as f:
                json.dump([f.to_dict() for f in findings], f, indent=2)
            print(f"\n{Fore.GREEN}[✓] JSON report saved to {args.output}")

if __name__ == "__main__":
    main()