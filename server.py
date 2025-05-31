#!/usr/bin/env python3
"""
Flask DAST Scanner API Server
OWASP Top 10 Dynamic Application Security Testing Service

This Flask server provides a REST API for conducting security scans
against web applications based on OWASP Top 10 (2021) vulnerabilities.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import urllib.parse
import re
import json
import time
import subprocess
import threading
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import uuid
import logging
import os
import shutil
import tempfile

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests

# Global storage for scan results (in production, use a database)
scan_results = {}
active_scans = {}

sast_results = {}
active_sast_scans = {}


class DASTScanner:
    def __init__(self, target_url, scan_id, timeout=10):
        self.target_url = target_url.rstrip('/')
        self.scan_id = scan_id
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DAST-Scanner-API/1.0 (Security Testing)'
        })
        self.vulnerabilities = []
        self.scan_status = 'running'
        self.start_time = datetime.now()
        self.current_step = 'Initializing'
        
    def log_vulnerability(self, category, severity, description, details=None):
        """Log a discovered vulnerability"""
        vuln = {
            'id': str(uuid.uuid4()),
            'category': category,
            'severity': severity,
            'description': description,
            'details': details or {},
            'target_url': self.target_url,
            'discovered_at': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        logger.info(f"Vulnerability found: {category} - {severity}")
        
    def update_status(self, step):
        """Update current scanning step"""
        self.current_step = step
        if self.scan_id in active_scans:
            active_scans[self.scan_id]['current_step'] = step
            active_scans[self.scan_id]['vulnerabilities_found'] = len(self.vulnerabilities)
        
    def safe_request(self, method, url, **kwargs):
        """Make a safe HTTP request with error handling"""
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('verify', False)  # For testing environments
            return self.session.request(method, url, **kwargs)
        except Exception as e:
            logger.warning(f"Request failed for {url}: {str(e)}")
            return None

    def scan_injection_flaws(self):
        """A01:2021 – Injection (SQL, NoSQL, LDAP, OS Command)"""
        self.update_status("Scanning for Injection Flaws")
        
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
        for payload in sql_payloads + nosql_payloads + cmd_payloads:
            test_payload_url = f"{self.target_url}?id={urllib.parse.quote(payload)}"
            response = self.safe_request('GET', test_payload_url)
            
            if response and self._check_injection_response(response, payload):
                self.log_vulnerability(
                    'A01:2021 – Injection',
                    'High',
                    f'Potential injection vulnerability detected with payload: {payload}',
                    {'payload': payload, 'response_length': len(response.text), 'method': 'GET'}
                )
        
        # Test POST parameters
        for payload in sql_payloads[:3]:  # Limit for API response time
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
        """A02:2021 – Cryptographic Failures"""
        self.update_status("Scanning for Authentication Issues")
        
        # Check for common authentication endpoints
        auth_endpoints = ['/login', '/admin', '/auth', '/signin', '/user/login']
        
        for endpoint in auth_endpoints:
            url = urljoin(self.target_url, endpoint)
            response = self.safe_request('GET', url)
            
            if response and response.status_code == 200:
                if self._check_weak_auth(response):
                    self.log_vulnerability(
                        'A02:2021 – Cryptographic Failures',
                        'Medium',
                        f'Weak authentication mechanism detected at {endpoint}',
                        {'endpoint': endpoint}
                    )
        
        # Test for default credentials (limited for API)
        self._test_default_credentials()
        
        # Check for session management issues
        self._check_session_management()

    def _check_weak_auth(self, response):
        """Check for indicators of weak authentication"""
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                csrf_fields = form.find_all('input', {'name': re.compile(r'csrf|token', re.I)})
                if not csrf_fields and form.find('input', {'type': 'password'}):
                    return True
        except Exception:
            pass
        return False

    def _test_default_credentials(self):
        """Test for default/weak credentials (limited set for API)"""
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
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
        """A03:2021 – Sensitive Data Exposure"""
        self.update_status("Scanning for Sensitive Data Exposure")
        
        # Check for sensitive files
        sensitive_files = [
            '/.env',
            '/config.php',
            '/wp-config.php',
            '/.git/config',
            '/phpinfo.php',
            '/server-status'
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
                        {'file_path': file_path, 'file_size': len(response.text)}
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
        """A04:2021 – XXE Vulnerabilities"""
        self.update_status("Scanning for XXE Vulnerabilities")
        
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>'''
        
        # Test XML endpoints
        xml_endpoints = ['/api/xml', '/upload', '/import']
        
        for endpoint in xml_endpoints:
            url = urljoin(self.target_url, endpoint)
            
            headers = {'Content-Type': 'application/xml'}
            response = self.safe_request('POST', url, data=xxe_payload, headers=headers)
            
            if response and ('root:x:0:0' in response.text or 
                           'daemon:x:1:1' in response.text):
                self.log_vulnerability(
                    'A04:2021 – XXE',
                    'High',
                    f'XXE vulnerability detected at {endpoint}',
                    {'endpoint': endpoint}
                )

    def scan_broken_access_control(self):
        """A05:2021 – Broken Access Control"""
        self.update_status("Scanning for Access Control Issues")
        
        # Test for directory traversal (limited payloads for API)
        traversal_payloads = [
            '../../../etc/passwd',
            '....//....//....//etc/passwd'
        ]
        
        for payload in traversal_payloads:
            test_url = f"{self.target_url}?file={payload}"
            response = self.safe_request('GET', test_url)
            
            if response and ('root:x:0:0' in response.text):
                self.log_vulnerability(
                    'A05:2021 – Broken Access Control',
                    'High',
                    f'Directory traversal vulnerability with payload: {payload}',
                    {'payload': payload}
                )
        
        # Test for privilege escalation
        self._test_privilege_escalation()

    def _test_privilege_escalation(self):
        """Test for admin page access"""
        admin_pages = ['/admin', '/administrator', '/manage']
        
        for page in admin_pages:
            url = urljoin(self.target_url, page)
            response = self.safe_request('GET', url)
            
            if response and response.status_code == 200:
                if 'admin' in response.text.lower():
                    self.log_vulnerability(
                        'A05:2021 – Broken Access Control',
                        'High',
                        f'Admin page accessible without authentication: {page}',
                        {'admin_page': page}
                    )

    def scan_security_misconfiguration(self):
        """A06:2021 – Security Misconfiguration"""
        self.update_status("Scanning for Security Misconfiguration")
        
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

    def scan_xss(self):
        """A07:2021 – Cross-Site Scripting"""
        self.update_status("Scanning for XSS Vulnerabilities")
        
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>'
        ]
        
        # Test reflected XSS
        for payload in xss_payloads:
            test_url = f"{self.target_url}?q={urllib.parse.quote(payload)}"
            response = self.safe_request('GET', test_url)
            
            if response and payload in response.text:
                self.log_vulnerability(
                    'A07:2021 – Cross-Site Scripting',
                    'Medium',
                    f'Reflected XSS vulnerability detected',
                    {'payload': payload, 'type': 'Reflected'}
                )

    def scan_insecure_deserialization(self):
        """A08:2021 – Insecure Deserialization"""
        self.update_status("Scanning for Deserialization Issues")
        
        # Test common endpoints with serialization payloads
        endpoints = ['/api/deserialize', '/upload']
        php_payload = 'O:8:"stdClass":1:{s:4:"test";s:4:"data";}'
        
        for endpoint in endpoints:
            url = urljoin(self.target_url, endpoint)
            response = self.safe_request('POST', url, data={'data': php_payload})
            
            if response and ('unserialized' in response.text.lower()):
                self.log_vulnerability(
                    'A08:2021 – Insecure Deserialization',
                    'High',
                    f'Potential deserialization vulnerability at {endpoint}',
                    {'endpoint': endpoint}
                )

    def scan_vulnerable_components(self):
        """A09:2021 – Vulnerable Components"""
        self.update_status("Scanning for Vulnerable Components")
        
        response = self.safe_request('GET', self.target_url)
        if not response:
            return
        
        # Check server headers
        server_header = response.headers.get('Server', '')
        if server_header:
            vulnerable_patterns = [
                r'Apache/2\.[01]\.',
                r'nginx/1\.[01]\.',
                r'PHP/[5-7]\.[0-2]\.',
            ]
            
            for pattern in vulnerable_patterns:
                if re.search(pattern, server_header):
                    self.log_vulnerability(
                        'A09:2021 – Vulnerable Components',
                        'Medium',
                        f'Potentially vulnerable server version: {server_header}',
                        {'server_header': server_header}
                    )

    def scan_logging_monitoring(self):
        """A10:2021 – SSRF and Monitoring Issues"""
        self.update_status("Scanning for SSRF and Monitoring Issues")
        
        # SSRF payloads (limited for API)
        ssrf_payloads = [
            'http://localhost:80',
            'http://127.0.0.1:22'
        ]
        
        for payload in ssrf_payloads:
            test_url = f"{self.target_url}?url={urllib.parse.quote(payload)}"
            response = self.safe_request('GET', test_url)
            
            if response and len(response.text) > 1000:
                self.log_vulnerability(
                    'A10:2021 – SSRF',
                    'High',
                    f'Potential SSRF vulnerability detected',
                    {'payload': payload}
                )

    def run_scan(self):
        """Execute all vulnerability scans"""
        try:
            self.update_status("Verifying target accessibility")
            
            # Verify target is reachable
            response = self.safe_request('GET', self.target_url)
            if not response:
                self.scan_status = 'failed'
                return self._generate_json_report()
            
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
                    time.sleep(0.5)  # Brief delay between scans
                except Exception as e:
                    logger.error(f"Error in {scan_method.__name__}: {str(e)}")
            
            self.scan_status = 'completed'
            self.update_status("Scan completed")
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            self.scan_status = 'failed'
        
        return self._generate_json_report()

    def _generate_json_report(self):
        """Generate JSON format vulnerability report"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        # Count vulnerabilities by severity
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        report = {
            'scan_info': {
                'scan_id': self.scan_id,
                'target_url': self.target_url,
                'start_time': self.start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': round(duration, 2),
                'status': self.scan_status
            },
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'severity_breakdown': severity_counts,
                'risk_score': self._calculate_risk_score()
            },
            'vulnerabilities': self.vulnerabilities,
            'recommendations': [
                "Review and fix all Critical and High severity issues immediately",
                "Implement proper input validation and output encoding",
                "Use security headers and HTTPS encryption",
                "Keep all components updated to latest versions",
                "Implement proper access controls and authentication",
                "Add comprehensive logging and monitoring"
            ]
        }
        
        return report

    def _calculate_risk_score(self):
        """Calculate overall risk score based on vulnerabilities"""
        score_map = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
        total_score = sum(score_map.get(v['severity'], 0) for v in self.vulnerabilities)
        return min(total_score, 100)  # Cap at 100

class SASTScanner:
    def __init__(self, source_code, scan_id, language='javascript'):
        self.source_code = source_code
        self.scan_id = scan_id
        self.language = language
        self.vulnerabilities = []
        self.scan_status = 'running'
        self.start_time = datetime.now()
        self.current_step = 'Initializing'
        self.target_dir = None
        
    def log_vulnerability(self, check_id, severity, message, metadata=None, file_path=None, line_info=None):
        """Log a discovered vulnerability"""
        vuln = {
            'id': str(uuid.uuid4()),
            'check_id': check_id,
            'severity': severity,
            'message': message,
            'metadata': metadata or {},
            'file_path': file_path,
            'line_info': line_info,
            'discovered_at': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        logger.info(f"SAST Vulnerability found: {check_id} - {severity}")
        
    def update_status(self, step):
        """Update current scanning step"""
        self.current_step = step
        if self.scan_id in active_sast_scans:
            active_sast_scans[self.scan_id]['current_step'] = step
            active_sast_scans[self.scan_id]['vulnerabilities_found'] = len(self.vulnerabilities)
    
    def setup_target_directory(self):
        """Create target directory and save source code"""
        try:
            self.update_status("Setting up target directory")
            
            # Create target directory if it doesn't exist
            if not os.path.exists('target'):
                os.makedirs('target')
            
            # Write source code to main.js
            target_file = os.path.join('target', 'main.js')
            with open(target_file, 'w', encoding='utf-8') as f:
                f.write(self.source_code)
            
            self.target_dir = 'target'
            logger.info(f"Source code saved to {target_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error setting up target directory: {str(e)}")
            return False
    
    def run_semgrep_scan(self):
        """Execute Semgrep scan on the target directory"""
        try:
            self.update_status("Running Semgrep analysis")
            
            # Check if semgrep is available
            check_cmd = subprocess.run(['semgrep', '--version'], 
                                     capture_output=True, text=True)
            if check_cmd.returncode != 0:
                raise Exception("Semgrep not found. Please install semgrep.")
            
            # Run semgrep with built-in rules
            semgrep_cmd = [
                'semgrep',
                '--config=auto',  # Use auto-detection for rules
                '--json',
                '--no-git-ignore',
                self.target_dir
            ]
            
            result = subprocess.run(
                semgrep_cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            if result.returncode not in [0, 1]:  # 0 = no findings, 1 = findings found
                logger.error(f"Semgrep error: {result.stderr}")
                raise Exception(f"Semgrep scan failed: {result.stderr}")
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            raise Exception("Semgrep scan timed out")
        except Exception as e:
            logger.error(f"Error running Semgrep: {str(e)}")
            raise e
    
    def parse_semgrep_results(self, semgrep_output):
        """Parse Semgrep JSON output and extract vulnerabilities"""
        try:
            self.update_status("Parsing scan results")
            
            if not semgrep_output.strip():
                logger.info("No Semgrep output to parse")
                return
            
            semgrep_data = json.loads(semgrep_output)
            
            if 'results' not in semgrep_data:
                logger.warning("No results found in Semgrep output")
                return
            
            for finding in semgrep_data['results']:
                # Map Semgrep severity to our severity levels
                severity_map = {
                    'ERROR': 'High',
                    'WARNING': 'Medium',
                    'INFO': 'Low'
                }
                
                severity = severity_map.get(
                    finding.get('extra', {}).get('severity', 'INFO'), 
                    'Medium'
                )
                
                # Extract line information
                line_info = {
                    'start_line': finding.get('start', {}).get('line'),
                    'end_line': finding.get('end', {}).get('line'),
                    'start_col': finding.get('start', {}).get('col'),
                    'end_col': finding.get('end', {}).get('col')
                }
                
                # Extract metadata
                metadata = finding.get('extra', {}).get('metadata', {})
                
                self.log_vulnerability(
                    check_id=finding.get('check_id', 'unknown'),
                    severity=severity,
                    message=finding.get('extra', {}).get('message', 'Security issue detected'),
                    metadata=metadata,
                    file_path=finding.get('path', 'main.js'),
                    line_info=line_info
                )
            
            # Log any errors from Semgrep
            if 'errors' in semgrep_data and semgrep_data['errors']:
                for error in semgrep_data['errors']:
                    logger.warning(f"Semgrep error: {error.get('message', 'Unknown error')}")
                    
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep JSON output: {str(e)}")
            raise Exception("Invalid JSON output from Semgrep")
        except Exception as e:
            logger.error(f"Error parsing Semgrep results: {str(e)}")
            raise e
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            if self.target_dir and os.path.exists(self.target_dir):
                # Only remove the specific file we created
                target_file = os.path.join(self.target_dir, 'main.js')
                if os.path.exists(target_file):
                    os.remove(target_file)
                    logger.info(f"Cleaned up {target_file}")
        except Exception as e:
            logger.warning(f"Error during cleanup: {str(e)}")
    
    def run_scan(self):
        """Execute complete SAST scan"""
        try:
            # Setup target directory and save code
            if not self.setup_target_directory():
                self.scan_status = 'failed'
                return self._generate_report()
            
            # Run Semgrep scan
            semgrep_output = self.run_semgrep_scan()
            
            # Parse results
            self.parse_semgrep_results(semgrep_output)
            
            self.scan_status = 'completed'
            self.update_status("Scan completed")
            
        except Exception as e:
            logger.error(f"SAST scan failed: {str(e)}")
            self.scan_status = 'failed'
            # Add error as a vulnerability for reporting
            self.log_vulnerability(
                check_id='scan_error',
                severity='High',
                message=f"Scan failed: {str(e)}",
                metadata={'error_type': 'scan_failure'}
            )
        finally:
            self.cleanup()
        
        return self._generate_report()
    
    def _generate_report(self):
        """Generate SAST scan report"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        # Count vulnerabilities by severity
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count vulnerabilities by category
        category_counts = {}
        for vuln in self.vulnerabilities:
            category = vuln.get('metadata', {}).get('category', 'unknown')
            category_counts[category] = category_counts.get(category, 0) + 1
        
        report = {
            'scan_info': {
                'scan_id': self.scan_id,
                'scan_type': 'SAST',
                'language': self.language,
                'start_time': self.start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': round(duration, 2),
                'status': self.scan_status,
                'lines_of_code': len(self.source_code.splitlines())
            },
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'severity_breakdown': severity_counts,
                'category_breakdown': category_counts,
                'risk_score': self._calculate_risk_score()
            },
            'vulnerabilities': self.vulnerabilities,
            'recommendations': [
                "Fix all High and Critical severity vulnerabilities immediately",
                "Implement input validation and output encoding",
                "Use secure coding practices and frameworks",
                "Regular code reviews and security testing",
                "Keep dependencies updated to latest secure versions",
                "Implement proper error handling and logging"
            ]
        }
        
        return report
    
    def _calculate_risk_score(self):
        """Calculate risk score based on vulnerabilities"""
        score_map = {'Critical': 10, 'High': 8, 'Medium': 5, 'Low': 2}
        total_score = sum(score_map.get(v['severity'], 0) for v in self.vulnerabilities)
        return min(total_score, 100)
# Flask API Routes

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'DAST Scanner API',
        'version': '1.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'Missing required parameter: url',
                'status': 'error'
            }), 400
        
        target_url = data['url']
        timeout = data.get('timeout', 10)
        
        # Validate URL
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return jsonify({
                'error': 'Invalid URL format',
                'status': 'error'
            }), 400
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Initialize scan tracking
        active_scans[scan_id] = {
            'target_url': target_url,
            'status': 'starting',
            'start_time': datetime.now().isoformat(),
            'current_step': 'Initializing',
            'vulnerabilities_found': 0
        }
        
        # Start scan in background thread
        def run_background_scan():
            scanner = DASTScanner(target_url, scan_id, timeout)
            result = scanner.run_scan()
            scan_results[scan_id] = result
            if scan_id in active_scans:
                del active_scans[scan_id]
        
        thread = threading.Thread(target=run_background_scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'message': 'Scan initiated successfully',
            'target_url': target_url
        })
        
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'status': 'error'
        }), 500

@app.route('/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get the status of a running scan"""
    try:
        # Check if scan is completed
        if scan_id in scan_results:
            return jsonify({
                'scan_id': scan_id,
                'status': 'completed',
                'result_available': True
            })
        
        # Check if scan is active
        if scan_id in active_scans:
            scan_info = active_scans[scan_id]
            return jsonify({
                'scan_id': scan_id,
                'status': scan_info['status'],
                'current_step': scan_info['current_step'],
                'vulnerabilities_found': scan_info['vulnerabilities_found'],
                'start_time': scan_info['start_time']
            })
        
        return jsonify({
            'error': 'Scan not found',
            'status': 'error'
        }), 404
        
    except Exception as e:
        logger.error(f"Error getting scan status: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'status': 'error'
        }), 500

@app.route('/scan/<scan_id>/result', methods=['GET'])
def get_scan_result(scan_id):
    """Get the results of a completed scan"""
    try:
        if scan_id not in scan_results:
            return jsonify({
                'error': 'Scan results not found or scan still in progress',
                'status': 'error'
            }), 404
        
        return jsonify(scan_results[scan_id])
        
    except Exception as e:
        logger.error(f"Error getting scan result: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'status': 'error'
        }), 500

@app.route('/scans', methods=['GET'])
def list_scans():
    """List all active and completed scans"""
    try:
        all_scans = []
        
        # Add active scans
        for scan_id, scan_info in active_scans.items():
            all_scans.append({
                'scan_id': scan_id,
                'target_url': scan_info['target_url'],
                'status': scan_info['status'],
                'start_time': scan_info['start_time']
            })
        
        # Add completed scans
        for scan_id, result in scan_results.items():
            all_scans.append({
                'scan_id': scan_id,
                'target_url': result['scan_info']['target_url'],
                'status': 'completed',
                'start_time': result['scan_info']['start_time'],
                'vulnerabilities_found': result['summary']['total_vulnerabilities']
            })
        
        return jsonify({
            'scans': all_scans,
            'total': len(all_scans)
        })
        
    except Exception as e:
        logger.error(f"Error listing scans: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'status': 'error'
        }), 500

@app.route('/sast/scan', methods=['POST'])
def start_sast_scan():
    """Start a new SAST scan"""
    try:
        data = request.get_json()
        
        if not data or 'code' not in data:
            return jsonify({
                'error': 'Missing required parameter: code',
                'status': 'error'
            }), 400
        
        source_code = data['code']
        language = data.get('language', 'javascript')
        
        if not source_code.strip():
            return jsonify({
                'error': 'Source code cannot be empty',
                'status': 'error'
            }), 400
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Initialize scan tracking
        active_sast_scans[scan_id] = {
            'language': language,
            'status': 'starting',
            'start_time': datetime.now().isoformat(),
            'current_step': 'Initializing',
            'vulnerabilities_found': 0,
            'lines_of_code': len(source_code.splitlines())
        }
        
        # Start scan in background thread
        def run_background_sast_scan():
            scanner = SASTScanner(source_code, scan_id, language)
            result = scanner.run_scan()
            sast_results[scan_id] = result
            if scan_id in active_sast_scans:
                del active_sast_scans[scan_id]
        
        thread = threading.Thread(target=run_background_sast_scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'message': 'SAST scan initiated successfully',
            'language': language,
            'lines_of_code': len(source_code.splitlines())
        })
        
    except Exception as e:
        logger.error(f"Error starting SAST scan: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'status': 'error'
        }), 500

@app.route('/sast/scan/<scan_id>/status', methods=['GET'])
def get_sast_scan_status(scan_id):
    """Get the status of a running SAST scan"""
    try:
        # Check if scan is completed
        if scan_id in sast_results:
            return jsonify({
                'scan_id': scan_id,
                'status': 'completed',
                'result_available': True
            })
        
        # Check if scan is active
        if scan_id in active_sast_scans:
            scan_info = active_sast_scans[scan_id]
            return jsonify({
                'scan_id': scan_id,
                'status': scan_info['status'],
                'current_step': scan_info['current_step'],
                'vulnerabilities_found': scan_info['vulnerabilities_found'],
                'start_time': scan_info['start_time'],
                'lines_of_code': scan_info['lines_of_code']
            })
        
        return jsonify({
            'error': 'SAST scan not found',
            'status': 'error'
        }), 404
        
    except Exception as e:
        logger.error(f"Error getting SAST scan status: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'status': 'error'
        }), 500

@app.route('/sast/scan/<scan_id>/result', methods=['GET'])
def get_sast_scan_result(scan_id):
    """Get the results of a completed SAST scan"""
    try:
        if scan_id not in sast_results:
            return jsonify({
                'error': 'SAST scan results not found or scan still in progress',
                'status': 'error'
            }), 404
        
        return jsonify(sast_results[scan_id])
        
    except Exception as e:
        logger.error(f"Error getting SAST scan result: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'status': 'error'
        }), 500

@app.route('/sast/scans', methods=['GET'])
def list_sast_scans():
    """List all active and completed SAST scans"""
    try:
        all_scans = []
        
        # Add active scans
        for scan_id, scan_info in active_sast_scans.items():
            all_scans.append({
                'scan_id': scan_id,
                'language': scan_info['language'],
                'status': scan_info['status'],
                'start_time': scan_info['start_time'],
                'lines_of_code': scan_info['lines_of_code']
            })
        
        # Add completed scans
        for scan_id, result in sast_results.items():
            all_scans.append({
                'scan_id': scan_id,
                'language': result['scan_info']['language'],
                'status': 'completed',
                'start_time': result['scan_info']['start_time'],
                'vulnerabilities_found': result['summary']['total_vulnerabilities'],
                'lines_of_code': result['scan_info']['lines_of_code']
            })
        
        return jsonify({
            'scans': all_scans,
            'total': len(all_scans)
        })
        
    except Exception as e:
        logger.error(f"Error listing SAST scans: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'status': 'error'
        }), 500    

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'status': 'error'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'status': 'error'
    }), 500

if __name__ == '__main__':
    print("Starting DAST Scanner API Server...")
    print("Available endpoints:")
    print("  POST /scan - Start a new vulnerability scan")
    print("  GET /scan/<scan_id>/status - Get scan status")
    print("  GET /scan/<scan_id>/result - Get scan results")
    print("  GET /scans - List all scans")
    print("  GET /health - Health check")
    print("Starting DAST/SAST Scanner API Server...")
    print("Available endpoints:")
    print("  DAST:")
    print("    POST /scan - Start a new vulnerability scan")
    print("    GET /scan/<scan_id>/status - Get scan status")
    print("    GET /scan/<scan_id>/result - Get scan results")
    print("    GET /scans - List all scans")
    print("  SAST:")
    print("    POST /sast/scan - Start a new SAST scan")
    print("    GET /sast/scan/<scan_id>/status - Get SAST scan status")
    print("    GET /sast/scan/<scan_id>/result - Get SAST scan results")
    print("    GET /sast/scans - List all SAST scans")
    print("  General:")
    print("    GET /health - Health check")
    
    # Ensure target directory exists
    if not os.path.exists('target'):
        os.makedirs('target')
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)