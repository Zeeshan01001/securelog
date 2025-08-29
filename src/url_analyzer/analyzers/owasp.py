"""
OWASP Top 10 Vulnerability Analyzer

Comprehensive detection engine for all OWASP Top 10 web vulnerabilities
through advanced pattern matching and behavioral analysis.
"""

import re
import logging
from typing import Dict, List, Optional
from datetime import datetime
from urllib.parse import unquote_plus, parse_qs

logger = logging.getLogger(__name__)


class OWASPAnalyzer:
    """
    Advanced OWASP Top 10 vulnerability detection engine.
    
    Provides comprehensive detection capabilities for all OWASP Top 10
    vulnerabilities through sophisticated pattern matching, heuristics,
    and behavioral analysis.
    """
    
    def __init__(self):
        """Initialize the OWASP Top 10 analyzer with detection patterns."""
        self.vulnerability_patterns = self._initialize_patterns()
        
        logger.info("OWASP Top 10 Analyzer initialized with comprehensive detection patterns")
    
    def _initialize_patterns(self) -> Dict:
        """Initialize comprehensive vulnerability detection patterns."""
        return {
            'A01_Broken_Access_Control': self._get_access_control_patterns(),
            'A02_Cryptographic_Failures': self._get_crypto_failure_patterns(),
            'A03_SQL_Injection': self._get_sql_injection_patterns(),
            'A04_Cross_Site_Scripting': self._get_xss_patterns(),
            'A05_Security_Misconfigurations': self._get_misconfig_patterns(),
            'A06_Vulnerable_Components': self._get_vulnerable_component_patterns(),
            'A07_Authentication_Failures': self._get_auth_failure_patterns(),
            'A08_Integrity_Failures': self._get_integrity_failure_patterns(),
            'A09_Logging_Failures': self._get_logging_failure_patterns(),
            'A10_Server_Side_Request_Forgery': self._get_ssrf_patterns()
        }
    
    def _get_access_control_patterns(self) -> Dict:
        """Patterns for A01: Broken Access Control & IDOR detection."""
        return {
            'idor_patterns': {
                'numeric_id': re.compile(r'[?&](?:id|user_id|account_id|order_id|file_id)=(\d+)', re.IGNORECASE),
                'uuid_reference': re.compile(r'[?&](?:uuid|guid|token)=([a-f0-9-]{36})', re.IGNORECASE),
                'filename_traversal': re.compile(r'[?&](?:file|filename|document)=([^&]*(?:\.\.\/|\.\.\\|%2e%2e%2f))', re.IGNORECASE),
                'user_reference': re.compile(r'[?&](?:user|username|email)=([^&]*)', re.IGNORECASE),
                'admin_paths': re.compile(r'\/(?:admin|administrator|manage|control|panel|dashboard)(?:\/|\?|$)', re.IGNORECASE),
                'api_endpoints': re.compile(r'\/api\/v?\d*\/(?:users?|accounts?|orders?|files?)\/(\d+|[a-f0-9-]+)', re.IGNORECASE),
            },
            'access_control_patterns': {
                'privilege_escalation': [
                    re.compile(r'[?&](?:role|privilege|access|level|type)=(?:admin|administrator|root|superuser)', re.IGNORECASE),
                    re.compile(r'[?&](?:is_admin|is_root|is_superuser)=(?:true|1|yes)', re.IGNORECASE),
                ],
                'authorization_bypass': [
                    re.compile(r'[?&](?:bypass|skip|ignore)_(?:auth|authorization|check)=(?:true|1|yes)', re.IGNORECASE),
                    re.compile(r'[?&](?:debug|test|dev)_mode=(?:true|1|yes)', re.IGNORECASE),
                ]
            }
        }
    
    def _get_crypto_failure_patterns(self) -> Dict:
        """Patterns for A02: Cryptographic Failures detection."""
        return {
            'weak_encryption': [
                re.compile(r'[?&](?:encrypt|hash|cipher)=(?:md5|sha1|des|3des|rc4)', re.IGNORECASE),
                re.compile(r'[?&](?:algorithm|algo)=(?:md5|sha1|des)', re.IGNORECASE),
            ],
            'exposed_keys': [
                re.compile(r'[?&](?:key|secret|token|password)=([a-zA-Z0-9+/]{20,})', re.IGNORECASE),
                re.compile(r'[?&]api_key=([a-zA-Z0-9-_]{20,})', re.IGNORECASE),
            ],
            'sensitive_data_exposure': [
                re.compile(r'[?&](?:ssn|social_security|credit_card|cc_number)=(\d+)', re.IGNORECASE),
                re.compile(r'[?&](?:password|passwd|pwd)=([^&]+)', re.IGNORECASE),
            ]
        }
    
    def _get_sql_injection_patterns(self) -> Dict:
        """Patterns for A03: SQL Injection detection."""
        return {
            'union_based': [
                re.compile(r'(?:union\s+(?:all\s+)?select|union\s+select\s+all)', re.IGNORECASE),
                re.compile(r'(?:union(?:\s+all)?\s+select(?:\s+top\s+\d+)?\s+(?:null|0x|@@|char|concat|group_concat|load_file|hex))', re.IGNORECASE),
                re.compile(r'(?:\s+union\s+.*?\s+from\s+)', re.IGNORECASE),
            ],
            'boolean_blind': [
                re.compile(r'(?:\s+(?:and|or)\s+\d+\s*[=<>]\s*\d+)', re.IGNORECASE),
                re.compile(r'(?:\s+(?:and|or)\s+(?:true|false))', re.IGNORECASE),
                re.compile(r'(?:\s+(?:and|or)\s+\d+\s+(?:like|rlike|sounds\s+like))', re.IGNORECASE),
                re.compile(r'(?:(?:and|or)\s+(?:\d+|null)\s*(?:=|!=|<>)\s*(?:\d+|null))', re.IGNORECASE),
            ],
            'time_based': [
                re.compile(r'(?:sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay)', re.IGNORECASE),
                re.compile(r'(?:(?:and|or)\s+(?:if|case)\s*\([^)]+\)\s*(?:sleep|benchmark|pg_sleep|waitfor))', re.IGNORECASE),
                re.compile(r'(?:select\s+(?:sleep|benchmark|pg_sleep)\s*\([^)]+\))', re.IGNORECASE),
            ],
            'error_based': [
                re.compile(r'(?:(?:and|or)\s+extractvalue\s*\(|(?:and|or)\s+updatexml\s*\()', re.IGNORECASE),
                re.compile(r'(?:(?:and|or)\s+exp\s*\(\s*~\s*\(|(?:and|or)\s+floor\s*\(\s*rand)', re.IGNORECASE),
                re.compile(r'(?:convert\s*\(\s*int\s*,|cast\s*\(\s*)', re.IGNORECASE),
            ],
            'nosql': [
                re.compile(r'(?:\$(?:ne|eq|lt|lte|gt|gte|in|nin|regex|where|exists))', re.IGNORECASE),
                re.compile(r'(?:javascript:|this\.|db\.|ObjectId\()', re.IGNORECASE),
            ]
        }
    
    def _get_xss_patterns(self) -> Dict:
        """Patterns for A04: Cross-Site Scripting detection."""
        return {
            'script_tags': [
                re.compile(r'<\s*script[^>]*>[^<]*<\s*/\s*script\s*>', re.IGNORECASE | re.DOTALL),
                re.compile(r'<\s*script[^>]*>', re.IGNORECASE),
                re.compile(r'javascript\s*:', re.IGNORECASE),
            ],
            'event_handlers': [
                re.compile(r'on(?:load|error|click|mouseover|focus|blur|change|submit)\s*=', re.IGNORECASE),
                re.compile(r'on\w+\s*=\s*["\']?[^"\']*(?:alert|prompt|confirm|eval|setTimeout|setInterval)', re.IGNORECASE),
            ],
            'html_injection': [
                re.compile(r'<(?:iframe|embed|object|applet|form|meta|link|base)[^>]*>', re.IGNORECASE),
                re.compile(r'<\s*img[^>]*\s+src\s*=\s*["\']?(?:javascript|data|vbscript):', re.IGNORECASE),
            ],
            'dom_xss': [
                re.compile(r'(?:document\.(?:write|writeln|createElement)|innerHTML|outerHTML)\s*(?:\(|\=)', re.IGNORECASE),
                re.compile(r'(?:location\.(?:href|hash|search)|window\.(?:location|name))', re.IGNORECASE),
                re.compile(r'eval\s*\([^)]*(?:location|document|window)', re.IGNORECASE),
            ]
        }
    
    def _get_misconfig_patterns(self) -> Dict:
        """Patterns for A05: Security Misconfigurations detection."""
        return {
            'debug_info_exposure': [
                re.compile(r'[?&](?:debug|trace|verbose|dev)=(?:true|1|yes|on)', re.IGNORECASE),
                re.compile(r'\/(?:debug|trace|test|dev|staging)(?:\/|\?|$)', re.IGNORECASE),
            ],
            'default_credentials': [
                re.compile(r'[?&](?:username|user|login)=(?:admin|administrator|root|test)', re.IGNORECASE),
                re.compile(r'[?&](?:password|pass|pwd)=(?:admin|administrator|password|123456|test)', re.IGNORECASE),
            ],
            'sensitive_files': [
                re.compile(r'\/(?:\.env|\.git\/config|config\.php|wp-config\.php|web\.config)', re.IGNORECASE),
                re.compile(r'\/(?:backup|dump|export)\/.*\.(?:sql|db|bak)', re.IGNORECASE),
            ]
        }
    
    def _get_vulnerable_component_patterns(self) -> Dict:
        """Patterns for A06: Vulnerable and Outdated Components detection."""
        return {
            'web_server_vulns': [
                re.compile(r'\/\.(?:htaccess|htpasswd)', re.IGNORECASE),
                re.compile(r'\/server-status|\/server-info', re.IGNORECASE),
            ],
            'cms_vulns': [
                re.compile(r'\/wp-admin\/admin-ajax\.php.*?action=', re.IGNORECASE),
                re.compile(r'\/wp-content\/(?:plugins|themes)\/[^\/]+\/.*\.php', re.IGNORECASE),
                re.compile(r'\/\?q=admin|\/admin\/.*', re.IGNORECASE),
            ],
            'framework_vulns': [
                re.compile(r'\.action(?:\?|$)', re.IGNORECASE),
                re.compile(r'[?&]redirect:.*?\.action', re.IGNORECASE),
            ]
        }
    
    def _get_auth_failure_patterns(self) -> Dict:
        """Patterns for A07: Identification and Authentication Failures detection."""
        return {
            'sql_auth_bypass': [
                re.compile(r'[?&](?:username|user|login|email)=.*?(?:\'|\\")\s*(?:or|and)\s+(?:1=1|true)', re.IGNORECASE),
                re.compile(r'[?&]password=.*?(?:\'|\\")\s*(?:or|and)\s+(?:1=1|true)', re.IGNORECASE),
            ],
            'parameter_pollution': [
                re.compile(r'[?&](?:username|user|login)=.*?[?&](?:username|user|login)=', re.IGNORECASE),
                re.compile(r'[?&]password=.*?[?&]password=', re.IGNORECASE),
            ],
            'session_fixation': [
                re.compile(r'[?&](?:session|sess|token|id)=([a-zA-Z0-9]{20,})', re.IGNORECASE),
                re.compile(r'[?&]PHPSESSID=|[?&]JSESSIONID=', re.IGNORECASE),
            ]
        }
    
    def _get_integrity_failure_patterns(self) -> Dict:
        """Patterns for A08: Software and Data Integrity Failures detection."""
        return {
            'deserialization_attacks': [
                re.compile(r'(?:rO0AB|aced0005)', re.IGNORECASE),  # Java serialization
                re.compile(r'(?:O:\d+:|a:\d+:|s:\d+:)', re.IGNORECASE),  # PHP serialization
                re.compile(r'(?:\}(?:__proto__|constructor|prototype))', re.IGNORECASE),  # JS prototype pollution
            ],
            'package_confusion': [
                re.compile(r'\/(?:npm|pip|composer|maven)\/.*?(?:install|download)', re.IGNORECASE),
                re.compile(r'[?&]package=.*?(?:@|%40)', re.IGNORECASE),
            ]
        }
    
    def _get_logging_failure_patterns(self) -> Dict:
        """Patterns for A09: Security Logging and Monitoring Failures detection."""
        return {
            'log_injection': [
                re.compile(r'(?:%0d|%0a|\r|\n)', re.IGNORECASE),  # CRLF injection
                re.compile(r'(?:\x00|%00)', re.IGNORECASE),  # Null byte injection
            ],
            'user_agent_anomalies': [
                re.compile(r'^(?:curl|wget|python|java|go-http)', re.IGNORECASE),
                re.compile(r'(?:scanner|bot|crawler|spider)', re.IGNORECASE),
            ]
        }
    
    def _get_ssrf_patterns(self) -> Dict:
        """Patterns for A10: Server-Side Request Forgery detection."""
        return {
            'internal_addresses': [
                re.compile(r'(?:127\.0\.0\.1|localhost|0\.0\.0\.0)', re.IGNORECASE),
                re.compile(r'(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)', re.IGNORECASE),  # RFC1918
                re.compile(r'(?:169\.254\.)', re.IGNORECASE),  # Link-local
            ],
            'url_parameters': [
                re.compile(r'[?&](?:url|uri|link|redirect|callback|jsonp)=(?:https?://|ftp://|file://)', re.IGNORECASE),
                re.compile(r'[?&](?:proxy|fetch|download|image)=(?:https?://)', re.IGNORECASE),
            ],
            'protocol_handlers': [
                re.compile(r'(?:file://|ftp://|gopher://|dict://|ldap://)', re.IGNORECASE),
                re.compile(r'(?:jar://|netdoc://|mailto://)', re.IGNORECASE),
            ],
            'aws_metadata': [
                re.compile(r'169\.254\.169\.254', re.IGNORECASE),  # AWS metadata service
                re.compile(r'metadata\.google\.internal', re.IGNORECASE),  # GCP metadata
            ]
        }
    
    def analyze(self, log_entries: List[Dict]) -> Dict:
        """
        Analyze log entries for OWASP Top 10 vulnerabilities.
        
        Args:
            log_entries: List of parsed log entry dictionaries
            
        Returns:
            Dictionary containing vulnerability findings organized by OWASP category
        """
        try:
            logger.info(f"Starting OWASP Top 10 analysis of {len(log_entries)} log entries")
            
            findings = {
                'A01_Broken_Access_Control': self._analyze_access_control(log_entries),
                'A02_Cryptographic_Failures': self._analyze_crypto_failures(log_entries),
                'A03_SQL_Injection': self._analyze_sql_injection(log_entries),
                'A04_Cross_Site_Scripting': self._analyze_xss(log_entries),
                'A05_Security_Misconfigurations': self._analyze_misconfigurations(log_entries),
                'A06_Vulnerable_Components': self._analyze_vulnerable_components(log_entries),
                'A07_Authentication_Failures': self._analyze_auth_failures(log_entries),
                'A08_Integrity_Failures': self._analyze_integrity_failures(log_entries),
                'A09_Logging_Failures': self._analyze_logging_failures(log_entries),
                'A10_Server_Side_Request_Forgery': self._analyze_ssrf(log_entries)
            }
            
            # Calculate summary statistics
            summary = self._calculate_findings_summary(findings)
            findings['summary'] = summary
            
            logger.info(f"OWASP Top 10 analysis completed. Found {summary['total_findings']} vulnerabilities")
            
            return findings
            
        except Exception as e:
            logger.error(f"OWASP Top 10 analysis failed: {e}")
            return {'error': str(e)}
    
    def _analyze_access_control(self, log_entries: List[Dict]) -> Dict:
        """Analyze for A01: Broken Access Control vulnerabilities."""
        findings = []
        patterns = self.vulnerability_patterns['A01_Broken_Access_Control']
        
        for entry in log_entries:
            url = entry.get('url', '')
            decoded_url = self._safe_url_decode(url)
            
            # Check IDOR patterns
            for pattern_name, pattern in patterns['idor_patterns'].items():
                matches = pattern.findall(decoded_url)
                if matches:
                    findings.append({
                        'type': 'IDOR_Vulnerability',
                        'pattern': pattern_name,
                        'matches': matches,
                        'url': decoded_url,
                        'severity': 'HIGH',
                        'timestamp': entry.get('timestamp'),
                        'source_ip': entry.get('source_ip'),
                        'description': f'Potential IDOR vulnerability detected with {pattern_name} pattern'
                    })
            
            # Check access control violations
            for violation_type, violation_patterns in patterns['access_control_patterns'].items():
                for pattern in violation_patterns:
                    if pattern.search(decoded_url):
                        findings.append({
                            'type': 'Access_Control_Violation',
                            'violation_type': violation_type,
                            'url': decoded_url,
                            'severity': 'CRITICAL',
                            'timestamp': entry.get('timestamp'),
                            'source_ip': entry.get('source_ip'),
                            'description': f'Access control violation detected: {violation_type}'
                        })
        
        return {'findings': findings, 'count': len(findings)}
    
    def _analyze_crypto_failures(self, log_entries: List[Dict]) -> Dict:
        """Analyze for A02: Cryptographic Failures vulnerabilities."""
        findings = []
        patterns = self.vulnerability_patterns['A02_Cryptographic_Failures']
        
        for entry in log_entries:
            url = entry.get('url', '')
            decoded_url = self._safe_url_decode(url)
            
            for category, category_patterns in patterns.items():
                for pattern in category_patterns:
                    matches = pattern.findall(decoded_url)
                    if matches:
                        findings.append({
                            'type': 'Cryptographic_Failure',
                            'category': category,
                            'matches': matches,
                            'url': decoded_url,
                            'severity': 'HIGH',
                            'timestamp': entry.get('timestamp'),
                            'source_ip': entry.get('source_ip'),
                            'description': f'Cryptographic failure detected: {category}'
                        })
        
        return {'findings': findings, 'count': len(findings)}
    
    def _analyze_sql_injection(self, log_entries: List[Dict]) -> Dict:
        """Analyze for A03: SQL Injection vulnerabilities."""
        findings = []
        patterns = self.vulnerability_patterns['A03_SQL_Injection']
        
        for entry in log_entries:
            url = entry.get('url', '')
            decoded_url = self._safe_url_decode(url)
            
            for injection_type, injection_patterns in patterns.items():
                for pattern in injection_patterns:
                    if pattern.search(decoded_url):
                        findings.append({
                            'type': 'SQL_Injection',
                            'injection_type': injection_type,
                            'url': decoded_url,
                            'severity': 'CRITICAL',
                            'timestamp': entry.get('timestamp'),
                            'source_ip': entry.get('source_ip'),
                            'description': f'SQL injection detected: {injection_type}'
                        })
        
        return {'findings': findings, 'count': len(findings)}
    
    def _analyze_xss(self, log_entries: List[Dict]) -> Dict:
        """Analyze for A04: Cross-Site Scripting vulnerabilities."""
        findings = []
        patterns = self.vulnerability_patterns['A04_Cross_Site_Scripting']
        
        for entry in log_entries:
            url = entry.get('url', '')
            decoded_url = self._safe_url_decode(url)
            
            for xss_type, xss_patterns in patterns.items():
                for pattern in xss_patterns:
                    if pattern.search(decoded_url):
                        findings.append({
                            'type': 'Cross_Site_Scripting',
                            'xss_type': xss_type,
                            'url': decoded_url,
                            'severity': 'HIGH',
                            'timestamp': entry.get('timestamp'),
                            'source_ip': entry.get('source_ip'),
                            'description': f'XSS vulnerability detected: {xss_type}'
                        })
        
        return {'findings': findings, 'count': len(findings)}
    
    def _analyze_misconfigurations(self, log_entries: List[Dict]) -> Dict:
        """Analyze for A05: Security Misconfigurations."""
        findings = []
        patterns = self.vulnerability_patterns['A05_Security_Misconfigurations']
        
        for entry in log_entries:
            url = entry.get('url', '')
            decoded_url = self._safe_url_decode(url)
            
            for misconfig_type, misconfig_patterns in patterns.items():
                for pattern in misconfig_patterns:
                    if pattern.search(decoded_url):
                        findings.append({
                            'type': 'Security_Misconfiguration',
                            'misconfig_type': misconfig_type,
                            'url': decoded_url,
                            'severity': 'MEDIUM',
                            'timestamp': entry.get('timestamp'),
                            'source_ip': entry.get('source_ip'),
                            'description': f'Security misconfiguration detected: {misconfig_type}'
                        })
        
        return {'findings': findings, 'count': len(findings)}
    
    def _analyze_vulnerable_components(self, log_entries: List[Dict]) -> Dict:
        """Analyze for A06: Vulnerable and Outdated Components."""
        findings = []
        patterns = self.vulnerability_patterns['A06_Vulnerable_Components']
        
        for entry in log_entries:
            url = entry.get('url', '')
            decoded_url = self._safe_url_decode(url)
            
            for component_type, component_patterns in patterns.items():
                for pattern in component_patterns:
                    if pattern.search(decoded_url):
                        findings.append({
                            'type': 'Vulnerable_Component',
                            'component_type': component_type,
                            'url': decoded_url,
                            'severity': 'MEDIUM',
                            'timestamp': entry.get('timestamp'),
                            'source_ip': entry.get('source_ip'),
                            'description': f'Vulnerable component detected: {component_type}'
                        })
        
        return {'findings': findings, 'count': len(findings)}
    
    def _analyze_auth_failures(self, log_entries: List[Dict]) -> Dict:
        """Analyze for A07: Identification and Authentication Failures."""
        findings = []
        patterns = self.vulnerability_patterns['A07_Authentication_Failures']
        
        for entry in log_entries:
            url = entry.get('url', '')
            decoded_url = self._safe_url_decode(url)
            
            for auth_failure_type, auth_failure_patterns in patterns.items():
                for pattern in auth_failure_patterns:
                    if pattern.search(decoded_url):
                        findings.append({
                            'type': 'Authentication_Failure',
                            'failure_type': auth_failure_type,
                            'url': decoded_url,
                            'severity': 'HIGH',
                            'timestamp': entry.get('timestamp'),
                            'source_ip': entry.get('source_ip'),
                            'description': f'Authentication failure detected: {auth_failure_type}'
                        })
        
        return {'findings': findings, 'count': len(findings)}
    
    def _analyze_integrity_failures(self, log_entries: List[Dict]) -> Dict:
        """Analyze for A08: Software and Data Integrity Failures."""
        findings = []
        patterns = self.vulnerability_patterns['A08_Integrity_Failures']
        
        for entry in log_entries:
            url = entry.get('url', '')
            decoded_url = self._safe_url_decode(url)
            
            for integrity_failure_type, integrity_failure_patterns in patterns.items():
                for pattern in integrity_failure_patterns:
                    if pattern.search(decoded_url):
                        findings.append({
                            'type': 'Integrity_Failure',
                            'failure_type': integrity_failure_type,
                            'url': decoded_url,
                            'severity': 'HIGH',
                            'timestamp': entry.get('timestamp'),
                            'source_ip': entry.get('source_ip'),
                            'description': f'Integrity failure detected: {integrity_failure_type}'
                        })
        
        return {'findings': findings, 'count': len(findings)}
    
    def _analyze_logging_failures(self, log_entries: List[Dict]) -> Dict:
        """Analyze for A09: Security Logging and Monitoring Failures."""
        findings = []
        patterns = self.vulnerability_patterns['A09_Logging_Failures']
        
        for entry in log_entries:
            url = entry.get('url', '')
            decoded_url = self._safe_url_decode(url)
            
            for logging_failure_type, logging_failure_patterns in patterns.items():
                for pattern in logging_failure_patterns:
                    if pattern.search(decoded_url):
                        findings.append({
                            'type': 'Logging_Failure',
                            'failure_type': logging_failure_type,
                            'url': decoded_url,
                            'severity': 'MEDIUM',
                            'timestamp': entry.get('timestamp'),
                            'source_ip': entry.get('source_ip'),
                            'description': f'Logging failure detected: {logging_failure_type}'
                        })
        
        return {'findings': findings, 'count': len(findings)}
    
    def _analyze_ssrf(self, log_entries: List[Dict]) -> Dict:
        """Analyze for A10: Server-Side Request Forgery."""
        findings = []
        patterns = self.vulnerability_patterns['A10_Server_Side_Request_Forgery']
        
        for entry in log_entries:
            url = entry.get('url', '')
            decoded_url = self._safe_url_decode(url)
            
            for ssrf_type, ssrf_patterns in patterns.items():
                for pattern in ssrf_patterns:
                    if pattern.search(decoded_url):
                        findings.append({
                            'type': 'SSRF',
                            'ssrf_type': ssrf_type,
                            'url': decoded_url,
                            'severity': 'HIGH',
                            'timestamp': entry.get('timestamp'),
                            'source_ip': entry.get('source_ip'),
                            'description': f'SSRF vulnerability detected: {ssrf_type}'
                        })
        
        return {'findings': findings, 'count': len(findings)}
    
    def _safe_url_decode(self, url: str) -> str:
        """Safely decode URL-encoded strings."""
        try:
            return unquote_plus(url)
        except Exception:
            return url
    
    def _calculate_findings_summary(self, findings: Dict) -> Dict:
        """Calculate summary statistics for all findings."""
        total_findings = 0
        by_severity = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        by_category = {}
        
        for category, result in findings.items():
            if category == 'summary':
                continue
                
            if 'findings' in result:
                category_findings = result['findings']
                total_findings += len(category_findings)
                
                for finding in category_findings:
                    severity = finding.get('severity', 'MEDIUM')
                    by_severity[severity] += 1
                    
                    finding_type = finding.get('type', 'unknown')
                    if finding_type not in by_category:
                        by_category[finding_type] = 0
                    by_category[finding_type] += 1
        
        return {
            'total_findings': total_findings,
            'by_severity': by_severity,
            'by_category': by_category,
            'categories_analyzed': len([k for k in findings.keys() if k != 'summary'])
        }




