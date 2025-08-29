"""
Log Parser for Advanced URL Analyzer

Provides log parsing and analysis capabilities.
"""

import logging
import re
from typing import Dict, List
from datetime import datetime

logger = logging.getLogger(__name__)


class LogParser:
    """Log parsing and analysis."""
    
    def __init__(self):
        """Initialize the log parser."""
        logger.info("Log Parser initialized")
    
    def parse_log_line(self, log_line: str) -> Dict:
        """Parse a single log line into structured data."""
        try:
            # Basic log parsing - this is a simplified version
            # In a real implementation, this would handle various log formats
            
            # Common log line pattern: IP - - [timestamp] "method path query_string" status size
            pattern = r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+)(?:\?([^"]*))? HTTP/[^"]*" (\d+) (\d+)'
            match = re.match(pattern, log_line)
            
            if match:
                source_ip, timestamp_str, method, path, query_string, status, size = match.groups()
                
                return {
                    'source_ip': source_ip,
                    'timestamp': timestamp_str,
                    'method': method,
                    'path': path,
                    'query_string': query_string or '',
                    'url': f"{path}?{query_string}" if query_string else path,
                    'status': int(status),
                    'size': int(size),
                    'raw_line': log_line
                }
            else:
                # Fallback for non-standard log formats
                return {
                    'raw_line': log_line,
                    'url': log_line,
                    'source_ip': 'unknown',
                    'timestamp': datetime.now().isoformat(),
                    'method': 'GET',
                    'path': '/',
                    'query_string': '',
                    'status': 200,
                    'size': 0
                }
                
        except Exception as e:
            logger.error(f"Log parsing failed: {e}")
            return {
                'raw_line': log_line,
                'url': log_line,
                'source_ip': 'unknown',
                'timestamp': datetime.now().isoformat(),
                'method': 'GET',
                'path': '/',
                'query_string': '',
                'status': 200,
                'size': 0,
                'parse_error': str(e)
            }




