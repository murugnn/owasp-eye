#!/usr/bin/env python3

import requests
import urllib.parse
import re
import json
import time
import subprocess
import sys
import argparse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

class DASTScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DAST-Scanner/1.0 (Security Testing)'
        })
        self.vulnerabilities = []
        
    def log_vulnerability(self, category, severity, description, details=None):
        """Log a discovered vulnerability"""
        vuln = {
            'category': category,
            'severity': severity,
            'description': description,
            'details': details or {},
            'url': self.target_url
        }
        self.vulnerabilities.append(vuln)
        
    def safe_request(self, method, url, **kwargs):
        """Make a safe HTTP request with error handling"""
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('verify', False)  # For testing environments
            return self.session.request(method, url, **kwargs)
        except Exception as e:
            print(f"Request failed for {url}: {str(e)}")
            return None

    def scan_injection_flaws(self):
        """A01:2021 – Injection (SQL, NoSQL, LDAP, OS Command)"""
        print("Scanning for Injection Flaws...")
        
        # SQL Injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1#",
            "admin'--",
            "' OR 'x'='x",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 AND '1'='1"
        ]
        
        # NoSQL Injection payloads
        nosql_payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}'
        ]
        
        # OS Command Injection payloads
        cmd_payloads = [
            '; ls -la',
            '| whoami',
            '&& ping -c 1 127.0.0.1',
            '; cat /etc/passwd',
            '`id`'
        ]
        
        # Test GET parameters
        test_url = f"{self.target_url}?id=1"
        
        for payload in sql_payloads + nosql_payloads + cmd_payloads:
            test_payload_url = f"{self.target_url}?id={urllib.parse.quote(payload)}"
            response = self.safe_request('GET', test_payload_url)
            
            if response and self._check_injection_response(response, payload):
                self.log_vulnerability(
                    'A01:2021 – Injection',
                    'High',
                    f'Potential injection vulnerability detected with payload: {payload}',
                    {'payload': payload, 'response_length': len(response.text)}
                )
        
        # Test POST parameters
        for payload in sql_payloads:
            data = {'username': payload, 'password': 'test'}
            response = self.safe_request('POST', f"{self.target_url}/login", data=data)
            
            if response and self._check_injection_response(response, payload):
                self.log_vulnerability(
                    'A01:2021 – Injection',
                    'High',
                    f'Potential SQL injection in POST parameters with payload: {payload}',
                    {'payload': payload, 'method': 'POST'}
                )

    def _check_injection_response(self, response, payload):
        """Check if response indicates potential injection vulnerability"""
        error_patterns = [
            r'mysql_fetch_array\(\)',
            r'ORA-\d{5}',
            r'Microsoft OLE DB Provider',
            r'PostgreSQL query failed',
            r'Warning: mysql_',
            r'valid MySQL result',
            r'MySqlClient\.',
            r'SQLException',
            r'sqlite3\.OperationalError',
            r'MongoDB.*Error'
        ]
        
        response_text = response.text.lower()
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        # Check for unusual response times (time-based injection)
        if response.elapsed.total_seconds() > 5:
            return True
            
        return False

    def scan_broken_authentication(self):
        """A02:2021 – Cryptographic Failures (formerly Broken Authentication)"""
        print("Scanning for Authentication Issues...")
        
        # Check for common authentication endpoints
        auth_endpoints = ['/login', '/admin', '/auth', '/signin', '/user/login']
        
        for endpoint in auth_endpoints:
            url = urljoin(self.target_url, endpoint)
            response = self.safe_request('GET', url)
            
            if response and response.status_code == 200:
                # Check for weak authentication mechanisms
                if self._check_weak_auth(response):
                    self.log_vulnerability(
                        'A02:2021 – Cryptographic Failures',
                        'Medium',
                        f'Weak authentication mechanism detected at {endpoint}',
                        {'endpoint': endpoint}
                    )
        
        # Test for default credentials
        self._test_default_credentials()
        
        # Check for session management issues
        self._check_session_management()

    def _check_weak_auth(self, response):
        """Check for indicators of weak authentication"""
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for forms without CSRF protection
        forms = soup.find_all('form')
        for form in forms:
            csrf_fields = form.find_all('input', {'name': re.compile(r'csrf|token', re.I)})
            if not csrf_fields and form.find('input', {'type': 'password'}):
                return True
        
        return False

    def _test_default_credentials(self):
        """Test for default/weak credentials"""
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('test', 'test')
        ]
        
        login_url = f"{self.target_url}/login"
        
        for username, password in common_creds:
            data = {'username': username, 'password': password}
            response = self.safe_request('POST', login_url, data=data)
            
            if response and ('dashboard' in response.text.lower() or 
                           'welcome' in response.text.lower() or
                           response.status_code == 302):
                self.log_vulnerability(
                    'A02:2021 – Cryptographic Failures',
                    'Critical',
                    f'Default credentials found: {username}/{password}',
                    {'username': username, 'password': password}
                )

    def _check_session_management(self):
        """Check for session management vulnerabilities"""
        response = self.safe_request('GET', self.target_url)
        if not response:
            return
            
        # Check for secure cookie flags
        for cookie in response.cookies:
            if not cookie.secure:
                self.log_vulnerability(
                    'A02:2021 – Cryptographic Failures',
                    'Medium',
                    f'Cookie {cookie.name} missing Secure flag',
                    {'cookie_name': cookie.name}
                )
            
            if not hasattr(cookie, 'httponly') or not cookie.httponly:
                self.log_vulnerability(
                    'A02:2021 – Cryptographic Failures',
                    'Medium',
                    f'Cookie {cookie.name} missing HttpOnly flag',
                    {'cookie_name': cookie.name}
                )

    def scan_sensitive_data_exposure(self):
        """A03:2021 – Injection (Sensitive Data Exposure aspects)"""
        print("Scanning for Sensitive Data Exposure...")
        
        # Check for sensitive files
        sensitive_files = [
            '/.env',
            '/config.php',
            '/wp-config.php',
            '/database.yml',
            '/config/database.yml',
            '/.git/config',
            '/backup.sql',
            '/phpinfo.php',
            '/server-status',
            '/server-info'
        ]
        
        for file_path in sensitive_files:
            url = urljoin(self.target_url, file_path)
            response = self.safe_request('GET', url)
            
            if response and response.status_code == 200:
                if self._contains_sensitive_data(response.text):
                    self.log_vulnerability(
                        'A03:2021 – Sensitive Data Exposure',
                        'High',
                        f'Sensitive file exposed: {file_path}',
                        {'file_path': file_path}
                    )
        
        # Check for HTTP vs HTTPS
        if not self.target_url.startswith('https://'):
            self.log_vulnerability(
                'A03:2021 – Sensitive Data Exposure',
                'Medium',
                'Application not using HTTPS encryption',
                {'protocol': 'HTTP'}
            )

    def _contains_sensitive_data(self, content):
        """Check if content contains sensitive information"""
        sensitive_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'mysql://.*:.*@',
            r'mongodb://.*:.*@',
            r'BEGIN RSA PRIVATE KEY',
            r'AWS_SECRET_ACCESS_KEY'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def scan_xxe(self):
        """A04:2021 – Insecure Design (XXE aspects)"""
        print("Scanning for XML External Entity (XXE) vulnerabilities...")
        
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>'''
        
        # Test XML endpoints
        xml_endpoints = ['/api/xml', '/upload', '/import', '/parse']
        
        for endpoint in xml_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            headers = {'Content-Type': 'application/xml'}
            response = self.safe_request('POST', url, data=xxe_payload, headers=headers)
            
            if response and ('root:x:0:0' in response.text or 
                           'daemon:x:1:1' in response.text):
                self.log_vulnerability(
                    'A04:2021 – Insecure Design (XXE)',
                    'High',
                    f'XXE vulnerability detected at {endpoint}',
                    {'endpoint': endpoint, 'payload': xxe_payload}
                )

    def scan_broken_access_control(self):
        """A05:2021 – Security Misconfiguration (Access Control aspects)"""
        print("Scanning for Broken Access Control...")
        
        # Test for directory traversal
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        
        for payload in traversal_payloads:
            test_url = f"{self.target_url}?file={payload}"
            response = self.safe_request('GET', test_url)
            
            if response and ('root:x:0:0' in response.text or 
                           '# Copyright (c)' in response.text):
                self.log_vulnerability(
                    'A05:2021 – Broken Access Control',
                    'High',
                    f'Directory traversal vulnerability with payload: {payload}',
                    {'payload': payload}
                )
        
        # Test for privilege escalation
        self._test_privilege_escalation()

    def _test_privilege_escalation(self):
        """Test for horizontal/vertical privilege escalation"""
        # Test accessing admin pages without authentication
        admin_pages = ['/admin', '/admin/', '/administrator', '/manage', '/control']
        
        for page in admin_pages:
            url = urljoin(self.target_url, page)
            response = self.safe_request('GET', url)
            
            if response and response.status_code == 200:
                if 'admin' in response.text.lower() or 'manage' in response.text.lower():
                    self.log_vulnerability(
                        'A05:2021 – Broken Access Control',
                        'High',
                        f'Admin page accessible without authentication: {page}',
                        {'admin_page': page}
                    )

    def scan_security_misconfiguration(self):
        """A06:2021 – Vulnerable and Outdated Components"""
        print("Scanning for Security Misconfiguration...")
        
        response = self.safe_request('GET', self.target_url)
        if not response:
            return
        
        # Check security headers
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME type sniffing protection missing',
            'X-XSS-Protection': 'XSS protection missing',
            'Strict-Transport-Security': 'HSTS missing',
            'Content-Security-Policy': 'CSP missing'
        }
        
        for header, description in security_headers.items():
            if header not in response.headers:
                self.log_vulnerability(
                    'A06:2021 – Security Misconfiguration',
                    'Medium',
                    description,
                    {'missing_header': header}
                )
        
        # Check for verbose error messages
        if 'stack trace' in response.text.lower() or 'exception' in response.text.lower():
            self.log_vulnerability(
                'A06:2021 – Security Misconfiguration',
                'Low',
                'Verbose error messages detected',
                {'issue': 'Error disclosure'}
            )

    def scan_xss(self):
        """A07:2021 – Identification and Authentication Failures (XSS aspects)"""
        print("Scanning for Cross-Site Scripting (XSS)...")
        
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "javascript:alert('XSS')",
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            "'><script>alert(String.fromCharCode(88,83,83))</script>"
        ]
        
        # Test reflected XSS
        for payload in xss_payloads:
            test_url = f"{self.target_url}?q={urllib.parse.quote(payload)}"
            response = self.safe_request('GET', test_url)
            
            if response and payload in response.text:
                self.log_vulnerability(
                    'A07:2021 – Cross-Site Scripting (XSS)',
                    'Medium',
                    f'Reflected XSS vulnerability with payload: {payload}',
                    {'payload': payload, 'type': 'Reflected'}
                )
        
        # Test stored XSS (if forms are present)
        self._test_stored_xss()

    def _test_stored_xss(self):
        """Test for stored XSS vulnerabilities"""
        # Look for forms that might store data
        response = self.safe_request('GET', self.target_url)
        if not response:
            return
            
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action', '')
            if action:
                form_url = urljoin(self.target_url, action)
            else:
                form_url = self.target_url
            
            # Prepare form data with XSS payload
            form_data = {}
            inputs = form.find_all('input')
            
            for input_tag in inputs:
                name = input_tag.get('name')
                if name and input_tag.get('type') != 'submit':
                    form_data[name] = '<script>alert("StoredXSS")</script>'
            
            if form_data:
                self.safe_request('POST', form_url, data=form_data)

    def scan_insecure_deserialization(self):
        """A08:2021 – Software and Data Integrity Failures"""
        print("Scanning for Insecure Deserialization...")
        
        # Test for common serialization endpoints
        serialization_endpoints = ['/api/deserialize', '/upload', '/import']
        
        # PHP Object Injection payload
        php_payload = 'O:8:"stdClass":1:{s:4:"test";s:4:"data";}'
        
        # Python pickle payload (base64 encoded)
        python_payload = 'gANjX19idWlsdGluX18KZXZhbApxAFgEAAAAdGVzdHEBhXECUnEDLg=='
        
        payloads = [php_payload, python_payload]
        
        for endpoint in serialization_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            for payload in payloads:
                response = self.safe_request('POST', url, data={'data': payload})
                
                if response and ('unserialized' in response.text.lower() or
                               'object' in response.text.lower()):
                    self.log_vulnerability(
                        'A08:2021 – Insecure Deserialization',
                        'High',
                        f'Potential deserialization vulnerability at {endpoint}',
                        {'endpoint': endpoint, 'payload_type': 'serialized_object'}
                    )

    def scan_vulnerable_components(self):
        """A09:2021 – Security Logging and Monitoring Failures"""
        print("Scanning for Vulnerable Components...")
        
        response = self.safe_request('GET', self.target_url)
        if not response:
            return
        
        # Check server headers for version information
        server_header = response.headers.get('Server', '')
        if server_header:
            # Look for known vulnerable versions (simplified check)
            vulnerable_patterns = [
                r'Apache/2\.[01]\.',  # Old Apache versions
                r'nginx/1\.[01]\.',   # Old Nginx versions
                r'PHP/[5-7]\.[0-2]\.', # Old PHP versions
            ]
            
            for pattern in vulnerable_patterns:
                if re.search(pattern, server_header):
                    self.log_vulnerability(
                        'A09:2021 – Vulnerable Components',
                        'Medium',
                        f'Potentially vulnerable server version detected: {server_header}',
                        {'server_header': server_header}
                    )
        
        # Check for common vulnerable files/paths
        self._check_vulnerable_files()

    def _check_vulnerable_files(self):
        """Check for files indicating vulnerable components"""
        vulnerable_paths = [
            '/phpMyAdmin/',
            '/phpmyadmin/',
            '/pma/',
            '/adminer.php',
            '/old_site/',
            '/backup/',
            '/test/',
            '/demo/'
        ]
        
        for path in vulnerable_paths:
            url = urljoin(self.target_url, path)
            response = self.safe_request('GET', url)
            
            if response and response.status_code == 200:
                self.log_vulnerability(
                    'A09:2021 – Vulnerable Components',
                    'Medium',
                    f'Potentially vulnerable component found: {path}',
                    {'path': path}
                )

    def scan_logging_monitoring(self):
        """A10:2021 – Server-Side Request Forgery (SSRF)"""
        print("Scanning for Insufficient Logging & Monitoring...")
        
        # This is harder to test automatically, but we can check for some indicators
        # Test for SSRF vulnerabilities which relate to monitoring failures
        
        ssrf_payloads = [
            'http://localhost:80',
            'http://127.0.0.1:22',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'file:///etc/passwd',
            'gopher://127.0.0.1:22/_test'
        ]
        
        for payload in ssrf_payloads:
            test_url = f"{self.target_url}?url={urllib.parse.quote(payload)}"
            response = self.safe_request('GET', test_url)
            
            if response and (len(response.text) > 1000 or 
                           'ssh' in response.text.lower() or
                           'http' in response.text.lower()):
                self.log_vulnerability(
                    'A10:2021 – SSRF/Monitoring Issues',
                    'High',
                    f'Potential SSRF vulnerability with payload: {payload}',
                    {'payload': payload, 'type': 'SSRF'}
                )

    def run_scan(self):
        """Execute all vulnerability scans"""
        print(f"Starting DAST scan for: {self.target_url}")
        print("=" * 60)
        
        # Verify target is reachable
        response = self.safe_request('GET', self.target_url)
        if not response:
            print(f"Error: Could not reach target URL: {self.target_url}")
            return
        
        print(f"Target is reachable (Status: {response.status_code})")
        print("Starting vulnerability scans...\n")
        
        # Run all scans
        scan_methods = [
            self.scan_injection_flaws,
            self.scan_broken_authentication,
            self.scan_sensitive_data_exposure,
            self.scan_xxe,
            self.scan_broken_access_control,
            self.scan_security_misconfiguration,
            self.scan_xss,
            self.scan_insecure_deserialization,
            self.scan_vulnerable_components,
            self.scan_logging_monitoring
        ]
        
        for scan_method in scan_methods:
            try:
                scan_method()
                time.sleep(1)  # Be respectful to the target
            except Exception as e:
                print(f"Error in {scan_method.__name__}: {str(e)}")
        
        self.generate_report()

    def generate_report(self):
        """Generate and display the vulnerability report"""
        print("\n" + "=" * 60)
        print("VULNERABILITY SCAN REPORT")
        print("=" * 60)
        
        if not self.vulnerabilities:
            print("✅ No vulnerabilities detected!")
            return
        
        # Sort vulnerabilities by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_vulns = sorted(self.vulnerabilities, 
                            key=lambda x: severity_order.get(x['severity'], 4))
        
        # Count by severity
        severity_counts = {}
        for vuln in sorted_vulns:
            severity_counts[vuln['severity']] = severity_counts.get(vuln['severity'], 0) + 1
        
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")
        
        print("\nDETAILED FINDINGS:")
        print("-" * 40)
        
        for i, vuln in enumerate(sorted_vulns, 1):
            print(f"\n{i}. {vuln['category']}")
            print(f"   Severity: {vuln['severity']}")
            print(f"   Description: {vuln['description']}")
            if vuln['details']:
                print(f"   Details: {vuln['details']}")
        
        print("\n" + "=" * 60)
        print("RECOMMENDATIONS:")
        print("- Review and fix all Critical and High severity issues immediately")
        print("- Implement proper input validation and output encoding")
        print("- Use security headers and HTTPS")
        print("- Keep all components updated")
        print("- Implement proper access controls")
        print("- Add comprehensive logging and monitoring")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description='OWASP Top 10 DAST Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='Request timeout in seconds (default: 10)')
    
    args = parser.parse_args()
    
    # Validate URL
    parsed_url = urlparse(args.url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print("Error: Please provide a valid URL (e.g., http://example.com)")
        sys.exit(1)
    
    # Initialize and run scanner
    scanner = DASTScanner(args.url, timeout=args.timeout)
    scanner.run_scan()


if __name__ == "__main__":
    main()