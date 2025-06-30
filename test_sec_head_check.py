#!/usr/bin/env python3
"""
Tests for sec-head-check
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sec_head_check import SecurityHeaderChecker, OutputFormatter

class TestSecurityHeaderChecker(unittest.TestCase):
    """Test cases for SecurityHeaderChecker class"""
    
    def setUp(self):
        self.checker = SecurityHeaderChecker()
    
    def test_calculate_grade(self):
        """Test grade calculation"""
        self.assertEqual(self.checker._calculate_grade(95), 'A')
        self.assertEqual(self.checker._calculate_grade(85), 'B')
        self.assertEqual(self.checker._calculate_grade(75), 'C')
        self.assertEqual(self.checker._calculate_grade(65), 'D')
        self.assertEqual(self.checker._calculate_grade(55), 'F')
    
    def test_validate_header_value_csp(self):
        """Test CSP header validation"""
        # Test unsafe CSP
        result = self.checker._validate_header_value(
            'Content-Security-Policy', 
            "default-src 'self' 'unsafe-inline'"
        )
        self.assertFalse(result['is_valid'])
        self.assertIn('unsafe', result['issue'])
        
        # Test safe CSP
        result = self.checker._validate_header_value(
            'Content-Security-Policy', 
            "default-src 'self'"
        )
        self.assertTrue(result['is_valid'])
    
    def test_validate_header_value_hsts(self):
        """Test HSTS header validation"""
        # Test missing max-age
        result = self.checker._validate_header_value(
            'Strict-Transport-Security', 
            "includeSubDomains"
        )
        self.assertFalse(result['is_valid'])
        
        # Test valid HSTS
        result = self.checker._validate_header_value(
            'Strict-Transport-Security', 
            "max-age=31536000; includeSubDomains"
        )
        self.assertTrue(result['is_valid'])
    
    def test_validate_header_value_x_frame_options(self):
        """Test X-Frame-Options header validation"""
        # Test invalid value
        result = self.checker._validate_header_value(
            'X-Frame-Options', 
            "ALLOWALL"
        )
        self.assertFalse(result['is_valid'])
        
        # Test valid values
        result = self.checker._validate_header_value(
            'X-Frame-Options', 
            "DENY"
        )
        self.assertTrue(result['is_valid'])
        
        result = self.checker._validate_header_value(
            'X-Frame-Options', 
            "SAMEORIGIN"
        )
        self.assertTrue(result['is_valid'])
    
    @patch('requests.get')
    def test_check_url_success(self, mock_get):
        """Test successful URL checking"""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff'
        }
        mock_get.return_value = mock_response
        
        result = self.checker.check_url('https://example.com')
        
        self.assertEqual(result['url'], 'https://example.com')
        self.assertEqual(result['status_code'], 200)
        self.assertIn('score', result)
        self.assertIn('grade', result)
        self.assertIn('headers_found', result)
        self.assertIn('headers_missing', result)
    
    @patch('requests.get')
    def test_check_url_error(self, mock_get):
        """Test URL checking with network error"""
        import requests
        mock_get.side_effect = requests.exceptions.RequestException("Network error")
        
        result = self.checker.check_url('https://invalid-url.com')
        
        self.assertIn('error', result)
        self.assertEqual(result['url'], 'https://invalid-url.com')

class TestOutputFormatter(unittest.TestCase):
    """Test cases for OutputFormatter class"""
    
    def setUp(self):
        self.formatter = OutputFormatter()
        self.sample_result = {
            'url': 'https://example.com',
            'status_code': 200,
            'timestamp': '2024-01-01T00:00:00',
            'score': 75.0,
            'grade': 'C',
            'headers_found': {
                'X-Frame-Options': {
                    'value': 'DENY',
                    'description': 'Prevents clickjacking attacks',
                    'severity': 'medium',
                    'validation': {'is_valid': True}
                }
            },
            'headers_missing': {
                'Content-Security-Policy': {
                    'description': 'Prevents XSS attacks',
                    'severity': 'high',
                    'recommendation': 'Implement a strict CSP policy'
                }
            },
            'recommendations': [
                {
                    'header': 'Content-Security-Policy',
                    'issue': 'Header missing',
                    'recommendation': 'Implement a strict CSP policy'
                }
            ]
        }
    
    def test_format_json(self):
        """Test JSON formatting"""
        result = self.formatter.format_json([self.sample_result])
        self.assertIn('https://example.com', result)
        self.assertIn('75.0', result)
    
    def test_format_csv(self):
        """Test CSV formatting"""
        result = self.formatter.format_csv([self.sample_result])
        lines = result.split('\n')
        self.assertEqual(len(lines), 2)  # Header + data row
        self.assertIn('url,score,grade', lines[0])
        self.assertIn('https://example.com,75.0,C', lines[1])
    
    def test_format_console(self):
        """Test console formatting"""
        result = self.formatter.format_console([self.sample_result])
        self.assertIn('Security Header Analysis', result)
        self.assertIn('Score: 75.0/100', result)
        self.assertIn('Grade: C', result)

if __name__ == '__main__':
    unittest.main()

