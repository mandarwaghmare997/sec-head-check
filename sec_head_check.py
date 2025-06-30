#!/usr/bin/env python3
"""
sec-head-check: A comprehensive HTTP Security Headers Checker CLI Tool
Author: Vulnuris Security
License: MIT
"""

import argparse
import json
import csv
import sys
import requests
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
import re
from datetime import datetime

class SecurityHeaderChecker:
    """Main class for checking HTTP security headers"""
    
    def __init__(self):
        self.security_headers = {
            'Content-Security-Policy': {
                'description': 'Prevents XSS attacks by controlling resource loading',
                'severity': 'high',
                'recommendation': 'Implement a strict CSP policy'
            },
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS connections',
                'severity': 'high',
                'recommendation': 'Add HSTS header with max-age and includeSubDomains'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'severity': 'medium',
                'recommendation': 'Set to DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'severity': 'medium',
                'recommendation': 'Set to nosniff'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information sent with requests',
                'severity': 'medium',
                'recommendation': 'Set to strict-origin-when-cross-origin or stricter'
            },
            'Permissions-Policy': {
                'description': 'Controls browser features and APIs',
                'severity': 'low',
                'recommendation': 'Define specific permissions for features'
            },
            'X-XSS-Protection': {
                'description': 'Legacy XSS protection (deprecated but still useful)',
                'severity': 'low',
                'recommendation': 'Set to 1; mode=block (though CSP is preferred)'
            },
            'Cross-Origin-Embedder-Policy': {
                'description': 'Controls cross-origin resource embedding',
                'severity': 'low',
                'recommendation': 'Set to require-corp for enhanced security'
            },
            'Cross-Origin-Opener-Policy': {
                'description': 'Controls cross-origin window interactions',
                'severity': 'low',
                'recommendation': 'Set to same-origin for enhanced security'
            },
            'Cross-Origin-Resource-Policy': {
                'description': 'Controls cross-origin resource access',
                'severity': 'low',
                'recommendation': 'Set to same-origin or cross-origin as needed'
            }
        }
        
        self.severity_scores = {
            'high': 30,
            'medium': 20,
            'low': 10
        }
    
    def check_url(self, url: str, timeout: int = 10) -> Dict:
        """Check security headers for a given URL"""
        try:
            # Ensure URL has protocol
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Make request
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            headers = response.headers
            
            result = {
                'url': url,
                'status_code': response.status_code,
                'timestamp': datetime.now().isoformat(),
                'headers_found': {},
                'headers_missing': {},
                'recommendations': [],
                'score': 0,
                'grade': 'F'
            }
            
            total_possible_score = sum(self.severity_scores.values()) * len(self.security_headers)
            current_score = 0
            
            # Check each security header
            for header_name, header_info in self.security_headers.items():
                header_value = headers.get(header_name)
                
                if header_value:
                    result['headers_found'][header_name] = {
                        'value': header_value,
                        'description': header_info['description'],
                        'severity': header_info['severity']
                    }
                    
                    # Validate header value
                    validation_result = self._validate_header_value(header_name, header_value)
                    result['headers_found'][header_name]['validation'] = validation_result
                    
                    if validation_result['is_valid']:
                        current_score += self.severity_scores[header_info['severity']]
                    else:
                        result['recommendations'].append({
                            'header': header_name,
                            'issue': validation_result['issue'],
                            'recommendation': validation_result['recommendation']
                        })
                else:
                    result['headers_missing'][header_name] = {
                        'description': header_info['description'],
                        'severity': header_info['severity'],
                        'recommendation': header_info['recommendation']
                    }
                    
                    result['recommendations'].append({
                        'header': header_name,
                        'issue': 'Header missing',
                        'recommendation': header_info['recommendation']
                    })
            
            # Calculate score and grade
            result['score'] = round((current_score / total_possible_score) * 100, 1)
            result['grade'] = self._calculate_grade(result['score'])
            
            return result
            
        except requests.exceptions.RequestException as e:
            return {
                'url': url,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _validate_header_value(self, header_name: str, header_value: str) -> Dict:
        """Validate specific header values for common misconfigurations"""
        validation_result = {'is_valid': True, 'issue': None, 'recommendation': None}
        
        if header_name == 'Content-Security-Policy':
            if 'unsafe-inline' in header_value or 'unsafe-eval' in header_value:
                validation_result = {
                    'is_valid': False,
                    'issue': 'CSP contains unsafe directives',
                    'recommendation': 'Remove unsafe-inline and unsafe-eval, use nonces or hashes instead'
                }
            elif '*' in header_value and 'script-src' in header_value:
                validation_result = {
                    'is_valid': False,
                    'issue': 'CSP uses wildcard in script-src',
                    'recommendation': 'Specify explicit domains instead of wildcards'
                }
        
        elif header_name == 'Strict-Transport-Security':
            if 'max-age=' not in header_value:
                validation_result = {
                    'is_valid': False,
                    'issue': 'HSTS missing max-age directive',
                    'recommendation': 'Add max-age directive with appropriate value (e.g., max-age=31536000)'
                }
            elif 'includeSubDomains' not in header_value:
                validation_result = {
                    'is_valid': False,
                    'issue': 'HSTS missing includeSubDomains',
                    'recommendation': 'Add includeSubDomains directive for better security'
                }
        
        elif header_name == 'X-Frame-Options':
            if header_value.upper() not in ['DENY', 'SAMEORIGIN']:
                validation_result = {
                    'is_valid': False,
                    'issue': 'X-Frame-Options has weak value',
                    'recommendation': 'Set to DENY or SAMEORIGIN'
                }
        
        elif header_name == 'X-Content-Type-Options':
            if header_value.lower() != 'nosniff':
                validation_result = {
                    'is_valid': False,
                    'issue': 'X-Content-Type-Options should be nosniff',
                    'recommendation': 'Set to nosniff'
                }
        
        return validation_result
    
    def _calculate_grade(self, score: float) -> str:
        """Calculate letter grade based on score"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def check_multiple_urls(self, urls: List[str], timeout: int = 10) -> List[Dict]:
        """Check multiple URLs"""
        results = []
        for url in urls:
            print(f"Checking {url}...")
            result = self.check_url(url, timeout)
            results.append(result)
        return results

class OutputFormatter:
    """Handle different output formats"""
    
    @staticmethod
    def format_console(results: List[Dict], verbose: bool = False) -> str:
        """Format results for console output"""
        output = []
        
        for result in results:
            if 'error' in result:
                output.append(f"❌ Error checking {result['url']}: {result['error']}")
                continue
            
            output.append(f"\n🔍 Security Header Analysis for {result['url']}")
            output.append(f"📊 Score: {result['score']}/100 (Grade: {result['grade']})")
            output.append(f"📅 Checked: {result['timestamp']}")
            
            if result['headers_found']:
                output.append(f"\n✅ Headers Found ({len(result['headers_found'])}):")
                for header, info in result['headers_found'].items():
                    status = "✅" if info['validation']['is_valid'] else "⚠️"
                    output.append(f"  {status} {header}: {info['value']}")
                    if verbose and not info['validation']['is_valid']:
                        output.append(f"     Issue: {info['validation']['issue']}")
            
            if result['headers_missing']:
                output.append(f"\n❌ Missing Headers ({len(result['headers_missing'])}):")
                for header, info in result['headers_missing'].items():
                    severity_emoji = "🔴" if info['severity'] == 'high' else "🟡" if info['severity'] == 'medium' else "🟢"
                    output.append(f"  {severity_emoji} {header} ({info['severity']} severity)")
                    if verbose:
                        output.append(f"     {info['description']}")
            
            if verbose and result['recommendations']:
                output.append(f"\n💡 Recommendations ({len(result['recommendations'])}):")
                for i, rec in enumerate(result['recommendations'], 1):
                    output.append(f"  {i}. {rec['header']}: {rec['recommendation']}")
        
        return '\n'.join(output)
    
    @staticmethod
    def format_json(results: List[Dict]) -> str:
        """Format results as JSON"""
        return json.dumps(results, indent=2)
    
    @staticmethod
    def format_csv(results: List[Dict]) -> str:
        """Format results as CSV"""
        if not results:
            return ""
        
        output = []
        fieldnames = ['url', 'score', 'grade', 'headers_found_count', 'headers_missing_count', 'timestamp']
        
        # Add header row
        output.append(','.join(fieldnames))
        
        for result in results:
            if 'error' in result:
                row = [result['url'], 'ERROR', 'ERROR', '0', '0', result['timestamp']]
            else:
                row = [
                    result['url'],
                    str(result['score']),
                    result['grade'],
                    str(len(result['headers_found'])),
                    str(len(result['headers_missing'])),
                    result['timestamp']
                ]
            output.append(','.join(row))
        
        return '\n'.join(output)

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description='sec-head-check: HTTP Security Headers Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sec-head-check https://example.com
  sec-head-check https://example.com --verbose
  sec-head-check https://example.com --output json
  sec-head-check --batch urls.txt --output csv > report.csv
  sec-head-check https://example.com --ci
        """
    )
    
    parser.add_argument('url', nargs='?', help='URL to check (can be omitted if using --batch)')
    parser.add_argument('--batch', '-b', help='File containing URLs to check (one per line)')
    parser.add_argument('--output', '-o', choices=['console', 'json', 'csv'], default='console',
                       help='Output format (default: console)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed information and recommendations')
    parser.add_argument('--timeout', '-t', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--ci', action='store_true',
                       help='CI/CD mode: exit with non-zero code if score < 70')
    parser.add_argument('--version', action='version', version='sec-head-check 1.0.0')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.url and not args.batch:
        parser.error("Either provide a URL or use --batch with a file")
    
    checker = SecurityHeaderChecker()
    formatter = OutputFormatter()
    
    # Get URLs to check
    urls = []
    if args.batch:
        try:
            with open(args.batch, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: File '{args.batch}' not found", file=sys.stderr)
            sys.exit(1)
    else:
        urls = [args.url]
    
    # Check URLs
    results = checker.check_multiple_urls(urls, args.timeout)
    
    # Format and output results
    if args.output == 'json':
        print(formatter.format_json(results))
    elif args.output == 'csv':
        print(formatter.format_csv(results))
    else:
        print(formatter.format_console(results, args.verbose))
    
    # CI mode: exit with error if any URL has score < 70
    if args.ci:
        for result in results:
            if 'error' in result or result.get('score', 0) < 70:
                sys.exit(1)

if __name__ == '__main__':
    main()

