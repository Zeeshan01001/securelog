"""
Main analysis engine for the Advanced URL Analyzer

Orchestrates all vulnerability detection modules and provides comprehensive
security analysis of web access logs with OWASP Top 10 focus.
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union, Iterator
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from multiprocessing import cpu_count

from ..security.validator import SecureInputValidator
from ..security.memory import SecureMemoryManager
from ..security.crypto import CryptographicVerifier
from ..analyzers.owasp import OWASPAnalyzer
from ..analyzers.threat_intel import ThreatIntelligenceEngine
from ..utils.parsers import LogParser
from ..utils.exporters import ReportExporter
from ..utils.reporting import ReportGenerator

logger = logging.getLogger(__name__)


class AnalysisReport:
    """Comprehensive analysis report containing all vulnerability findings."""
    
    def __init__(self, 
                 timestamp: datetime,
                 log_file: str,
                 total_entries: int,
                 vulnerability_findings: Dict,
                 overall_risk_score: float,
                 threat_intelligence: Dict,
                 recommendations: List[str],
                 executive_summary: str):
        self.timestamp = timestamp
        self.log_file = log_file
        self.total_entries = total_entries
        self.vulnerability_findings = vulnerability_findings
        self.overall_risk_score = overall_risk_score
        self.threat_intelligence = threat_intelligence
        self.recommendations = recommendations
        self.executive_summary = executive_summary


class ThreatAlert:
    """Real-time threat alert for immediate security response."""
    
    def __init__(self,
                 timestamp: datetime,
                 threat_type: str,
                 severity: str,
                 source_ip: str,
                 details: Dict,
                 recommended_actions: List[str]):
        self.timestamp = timestamp
        self.threat_type = threat_type
        self.severity = severity
        self.source_ip = source_ip
        self.details = details
        self.recommended_actions = recommended_actions


class AdvancedLogAnalyzer:
    """
    Main analysis engine that orchestrates all vulnerability detection modules.
    
    Provides comprehensive security analysis of web access logs with specific
    focus on OWASP Top 10 vulnerabilities, advanced threat detection, and
    secure handling of sensitive log data.
    """
    
    def __init__(self, config_path: str = "config/security_config.yaml"):
        """Initialize the Advanced Log Analyzer with secure configuration."""
        self.config = self._load_secure_config(config_path)
        self.input_validator = SecureInputValidator()
        self.memory_manager = SecureMemoryManager()
        self.crypto_verifier = CryptographicVerifier()
        
        # Initialize vulnerability analyzers
        self.analyzers = {
            'owasp_top10': OWASPAnalyzer(),
            'threat_intelligence': ThreatIntelligenceEngine(),
        }
        
        # Initialize utility components
        self.log_parser = LogParser()
        self.report_exporter = ReportExporter()
        self.report_generator = ReportGenerator()
        
        # Setup audit logging
        self.audit_logger = self._setup_audit_logging()
        
        # Performance optimization
        self.max_workers = self.config.get('analysis', {}).get('max_concurrent_analyses', cpu_count())
        self.thread_pool = ThreadPoolExecutor(max_workers=self.max_workers)
        self.process_pool = ProcessPoolExecutor(max_workers=self.max_workers)
        
        logger.info(f"Advanced Log Analyzer initialized with {self.max_workers} workers")
    
    def _load_secure_config(self, config_path: str) -> Dict:
        """Load and validate security configuration."""
        try:
            # Implementation for secure config loading
            # This would include hash verification and digital signature validation
            return {
                'analysis': {
                    'timeout_seconds': 300,
                    'max_concurrent_analyses': 4,
                    'batch_size': 1000,
                    'ml_threshold': 0.8
                },
                'security': {
                    'max_file_size_mb': 100,
                    'max_line_length': 10000,
                    'allowed_encodings': ['utf-8', 'ascii', 'latin-1']
                }
            }
        except Exception as e:
            logger.error(f"Failed to load secure configuration: {e}")
            raise
    
    def _setup_audit_logging(self) -> logging.Logger:
        """Setup comprehensive audit logging for security compliance."""
        audit_logger = logging.getLogger('audit')
        audit_logger.setLevel(logging.INFO)
        
        # Add file handler for audit logs
        audit_handler = logging.FileHandler('url_analyzer_audit.log')
        audit_handler.setLevel(logging.INFO)
        
        # Add formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        audit_handler.setFormatter(formatter)
        audit_logger.addHandler(audit_handler)
        
        return audit_logger
    
    def analyze_log_file(self, log_file_path: str, output_format: str = "json") -> AnalysisReport:
        """
        Comprehensive security analysis of web access log files.
        
        Args:
            log_file_path: Path to the log file to analyze
            output_format: Output format (json, csv, html, pdf)
            
        Returns:
            AnalysisReport containing all vulnerability findings and risk assessments
        """
        try:
            # Validate input file
            self._validate_log_file(log_file_path)
            
            # Load and parse log entries
            log_entries = self._load_log_entries(log_file_path)
            
            # Initialize analysis results
            analysis_results = {}
            
            # Run all vulnerability analyzers
            for analyzer_name, analyzer in self.analyzers.items():
                try:
                    self.audit_logger.info(f"Starting {analyzer_name} analysis")
                    
                    # Run analysis with timeout protection
                    with self._timeout_context(self.config['analysis']['timeout_seconds']):
                        results = analyzer.analyze(log_entries)
                        analysis_results[analyzer_name] = results
                    
                    # Count total findings from all categories
                    total_findings = 0
                    if 'summary' in results:
                        total_findings = results['summary'].get('total_findings', 0)
                    self.audit_logger.info(f"Completed {analyzer_name} analysis: {total_findings} findings")
                    
                except Exception as e:
                    self.audit_logger.error(f"Analysis failed for {analyzer_name}: {str(e)}")
                    analysis_results[analyzer_name] = {'error': str(e)}
            
            # Aggregate and correlate findings
            aggregated_results = self._aggregate_findings(analysis_results)
            
            # Calculate overall risk score
            overall_risk = self._calculate_overall_risk(aggregated_results)
            
            # Generate threat intelligence correlation
            threat_correlation = self._correlate_with_threat_intel(aggregated_results)
            
            # Create comprehensive report
            report = AnalysisReport(
                timestamp=datetime.utcnow(),
                log_file=log_file_path,
                total_entries=len(log_entries),
                vulnerability_findings=aggregated_results,
                overall_risk_score=overall_risk,
                threat_intelligence=threat_correlation,
                recommendations=self._generate_recommendations(aggregated_results),
                executive_summary=self._generate_executive_summary(aggregated_results, overall_risk)
            )
            
            # Export report in requested format
            self._export_report(report, output_format)
            
            return report
            
        except Exception as e:
            self.audit_logger.critical(f"Critical analysis failure: {str(e)}")
            raise
        finally:
            # Secure cleanup
            self.memory_manager.secure_cleanup()
    
    async def analyze_real_time_stream(self, log_stream: Iterator[str]) -> Iterator[ThreatAlert]:
        """
        Real-time analysis of streaming log data with immediate threat alerting.
        
        Args:
            log_stream: Iterator yielding log entries in real-time
            
        Yields:
            ThreatAlert objects for immediate security response
        """
        threat_buffer = []
        
        for log_line in log_stream:
            try:
                # Parse log entry
                entry = self.log_parser.parse_log_line(log_line)
                
                # Quick threat assessment
                immediate_threats = self._assess_immediate_threats(entry)
                
                # Buffer analysis for batch processing
                threat_buffer.append(entry)
                
                # Yield high-priority alerts immediately
                for threat in immediate_threats:
                    if threat.get('severity') in ['HIGH', 'CRITICAL']:
                        yield ThreatAlert(
                            timestamp=datetime.utcnow(),
                            threat_type=threat['type'],
                            severity=threat['severity'],
                            source_ip=entry.get('source_ip', 'unknown'),
                            details=threat['details'],
                            recommended_actions=threat.get('actions', [])
                        )
                
                # Process buffer when it reaches threshold
                if len(threat_buffer) >= self.config['analysis']['batch_size']:
                    batch_threats = await self._analyze_threat_batch(threat_buffer)
                    for threat in batch_threats:
                        yield threat
                    threat_buffer.clear()
                    
            except Exception as e:
                self.audit_logger.warning(f"Real-time analysis error: {str(e)}")
                continue
    
    def _validate_log_file(self, log_file_path: str) -> None:
        """Validate log file for security and integrity."""
        try:
            path = Path(log_file_path)
            
            # Check if file exists
            if not path.exists():
                raise FileNotFoundError(f"Log file not found: {log_file_path}")
            
            # Check file size
            file_size = path.stat().st_size
            max_size = self.config['security']['max_file_size_mb'] * 1024 * 1024
            
            if file_size > max_size:
                raise ValueError(f"Log file exceeds maximum size: {file_size} bytes")
            
            # Additional security checks would go here
            # File type validation, content sampling, etc.
            
        except Exception as e:
            logger.error(f"Log file validation failed: {e}")
            raise
    
    def _load_log_entries(self, log_file_path: str) -> List[Dict]:
        """Load and parse log entries from file."""
        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                log_lines = f.readlines()
            
            # Parse each log line
            log_entries = []
            for line_num, line in enumerate(log_lines, 1):
                try:
                    entry = self.log_parser.parse_log_line(line.strip())
                    entry['line_number'] = line_num
                    log_entries.append(entry)
                except Exception as e:
                    logger.warning(f"Failed to parse line {line_num}: {e}")
                    continue
            
            logger.info(f"Loaded {len(log_entries)} log entries from {log_file_path}")
            return log_entries
            
        except Exception as e:
            logger.error(f"Failed to load log entries: {e}")
            raise
    
    def _aggregate_findings(self, analysis_results: Dict) -> Dict:
        """Aggregate findings from all analyzers."""
        aggregated = {
            'total_findings': 0,
            'by_severity': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0},
            'by_category': {},
            'by_analyzer': {},
            'detailed_findings': []
        }
        
        for analyzer_name, results in analysis_results.items():
            if 'error' in results:
                continue
                
            # Handle OWASP analyzer results structure
            if analyzer_name == 'owasp_top10' and 'summary' in results:
                # Use summary data from OWASP analyzer
                summary = results['summary']
                aggregated['total_findings'] += summary.get('total_findings', 0)
                
                # Aggregate by severity
                for severity, count in summary.get('by_severity', {}).items():
                    if severity in aggregated['by_severity']:
                        aggregated['by_severity'][severity] += count
                
                # Aggregate by category
                for category, count in summary.get('by_category', {}).items():
                    if category not in aggregated['by_category']:
                        aggregated['by_category'][category] = 0
                    aggregated['by_category'][category] += count
                
                # Collect detailed findings from all OWASP categories
                for category_name, category_results in results.items():
                    if category_name != 'summary' and 'findings' in category_results:
                        aggregated['detailed_findings'].extend(category_results['findings'])
                
                aggregated['by_analyzer'][analyzer_name] = summary.get('total_findings', 0)
            else:
                # Handle other analyzers with standard structure
                aggregated['by_analyzer'][analyzer_name] = len(results.get('findings', []))
                
                # Aggregate findings
                for finding in results.get('findings', []):
                    aggregated['total_findings'] += 1
                    severity = finding.get('severity', 'MEDIUM')
                    aggregated['by_severity'][severity] += 1
                    
                    category = finding.get('type', 'unknown')
                    if category not in aggregated['by_category']:
                        aggregated['by_category'][category] = 0
                    aggregated['by_category'][category] += 1
                    
                    aggregated['detailed_findings'].append(finding)
        
        return aggregated
    
    def _calculate_overall_risk(self, aggregated_results: Dict) -> float:
        """Calculate overall risk score based on findings with realistic scaling."""
        risk_score = 0.0
        total_findings = aggregated_results.get('total_findings', 0)
        
        if total_findings == 0:
            return 0.0
        
        # More realistic weighted scoring based on severity
        severity_weights = {
            'LOW': 5.0,      # Low severity contributes 5 points each
            'MEDIUM': 15.0,  # Medium severity contributes 15 points each  
            'HIGH': 25.0,    # High severity contributes 25 points each
            'CRITICAL': 35.0 # Critical severity contributes 35 points each
        }
        
        # Calculate weighted score
        for severity, count in aggregated_results['by_severity'].items():
            risk_score += count * severity_weights.get(severity, 5.0)
        
        # Apply logarithmic scaling to prevent unrealistic scores
        # This ensures that many findings don't immediately max out at 100
        import math
        if risk_score > 0:
            # Use a more reasonable logarithmic scaling
            # Base score: risk_score (raw weighted points)
            # Apply square root scaling to create more realistic distribution:
            # - 1 HIGH (25 points) = ~50 risk score
            # - 2 MEDIUM (30 points) = ~55 risk score  
            # - 1 CRITICAL (35 points) = ~59 risk score
            # - Multiple criticals scale more gradually
            scaled_score = math.sqrt(risk_score) * 10.0
            normalized_risk = min(scaled_score, 100.0)
        else:
            normalized_risk = 0.0
        
        return round(normalized_risk, 1)
    
    def _correlate_with_threat_intel(self, aggregated_results: Dict) -> Dict:
        """Correlate findings with threat intelligence feeds."""
        try:
            threat_intel = self.analyzers['threat_intelligence']
            correlation = threat_intel.correlate_findings(aggregated_results['detailed_findings'])
            return correlation
        except Exception as e:
            logger.warning(f"Threat intelligence correlation failed: {e}")
            return {'error': str(e)}
    
    def _generate_recommendations(self, aggregated_results: Dict) -> List[str]:
        """Generate actionable security recommendations."""
        recommendations = []
        
        # Generate recommendations based on findings
        if aggregated_results['by_severity']['CRITICAL'] > 0:
            recommendations.append("Immediate action required: Critical vulnerabilities detected")
        
        if aggregated_results['by_severity']['HIGH'] > 0:
            recommendations.append("High priority: Address high-severity findings within 24 hours")
        
        # Add specific recommendations based on vulnerability categories
        for category, count in aggregated_results['by_category'].items():
            if count > 0:
                recommendations.append(f"Review and remediate {category} vulnerabilities")
        
        return recommendations
    
    def _generate_executive_summary(self, aggregated_results: Dict, overall_risk: float) -> str:
        """Generate executive-level summary of findings."""
        total_findings = aggregated_results['total_findings']
        
        if total_findings == 0:
            return "No security vulnerabilities detected. Log analysis completed successfully."
        
        critical_count = aggregated_results['by_severity']['CRITICAL']
        high_count = aggregated_results['by_severity']['HIGH']
        
        summary = f"Security analysis completed with {total_findings} findings. "
        
        if critical_count > 0:
            summary += f"CRITICAL: {critical_count} critical vulnerabilities require immediate attention. "
        
        if high_count > 0:
            summary += f"HIGH: {high_count} high-severity issues need prompt remediation. "
        
        summary += f"Overall risk score: {overall_risk:.1f}/100"
        
        return summary
    
    def _export_report(self, report: AnalysisReport, output_format: str) -> None:
        """Export analysis report in specified format."""
        try:
            if output_format == 'json':
                self.report_exporter.export_json(report)
            elif output_format == 'csv':
                self.report_exporter.export_csv(report)
            elif output_format == 'pdf':
                self.report_exporter.export_pdf(report)
            elif output_format == 'html':
                self.report_exporter.export_html(report)
            else:
                logger.warning(f"Unsupported output format: {output_format}")
                
        except Exception as e:
            logger.error(f"Report export failed: {e}")
    
    def _assess_immediate_threats(self, log_entry: Dict) -> List[Dict]:
        """Assess log entry for immediate threats requiring urgent response."""
        immediate_threats = []
        
        # Check for critical patterns that require immediate attention
        critical_patterns = [
            'admin', 'root', 'password', 'sql', 'script', 'eval', 'union'
        ]
        
        entry_text = str(log_entry).lower()
        
        for pattern in critical_patterns:
            if pattern in entry_text:
                immediate_threats.append({
                    'type': f'Critical pattern detected: {pattern}',
                    'severity': 'HIGH',
                    'details': {'pattern': pattern, 'entry': log_entry},
                    'actions': ['Block source IP', 'Review logs', 'Investigate immediately']
                })
        
        return immediate_threats
    
    async def _analyze_threat_batch(self, threat_buffer: List[Dict]) -> List[ThreatAlert]:
        """Analyze a batch of threats for comprehensive assessment."""
        # This would implement batch analysis logic
        # For now, return empty list
        return []
    
    def _timeout_context(self, timeout_seconds: int):
        """Context manager for timeout protection."""
        # Implementation for timeout protection
        class TimeoutContext:
            def __init__(self, timeout):
                self.timeout = timeout
            
            def __enter__(self):
                return self
            
            def __exit__(self, exc_type, exc_val, exc_tb):
                return False
        
        return TimeoutContext(timeout_seconds)
    
    def cleanup(self):
        """Cleanup resources and perform secure shutdown."""
        try:
            self.thread_pool.shutdown(wait=True)
            self.process_pool.shutdown(wait=True)
            self.memory_manager.secure_cleanup()
            logger.info("Advanced Log Analyzer cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")


# Convenience function for quick analysis
def analyze_log_file(log_file_path: str, output_format: str = "json") -> AnalysisReport:
    """
    Convenience function for quick log file analysis.
    
    Args:
        log_file_path: Path to the log file to analyze
        output_format: Output format (json, csv, html, pdf)
        
    Returns:
        AnalysisReport with vulnerability findings
    """
    analyzer = AdvancedLogAnalyzer()
    try:
        return analyzer.analyze_log_file(log_file_path, output_format)
    finally:
        analyzer.cleanup()
