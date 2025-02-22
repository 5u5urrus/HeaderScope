import requests
import sys
import argparse
import json
import re
from urllib.parse import urlparse
import textwrap
from colorama import Fore, Style, init

# Author: Vahe Demirkhanyan

init(autoreset=True)

class HeaderAnalyzer:
    def __init__(self, config_file=None):
        self.required_headers = self._load_header_requirements(config_file)
        self.analyzed_results = {}
        self.security_score = 0
        self.max_score = 0
        self.critical_issues = []
        self.warnings = []
        self.recommendations = []
        self.original_headers = {}
        self.normalized_headers = {}  # Case-insensitive header lookup
        
    def _load_header_requirements(self, config_file=None):
        """Load header requirements from config file or use default built-in configuration"""
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading config file: {str(e)}")
                print("Using default header requirements instead.")
        
        # Default comprehensive header requirements
        return {
            'Cache-Control': {
                'expected': ['no-store', 'no-cache', 'must-revalidate', 'max-age=0'],
                'not_expected': ['public'],
                'match_type': 'CONTAINS_ANY',
                'weight': 7,
                'critical': True,
                'optional': False,
                'info': 'Prevents the caching of the page, ensuring that sensitive information is not stored in the browser cache.',
                'recommendation': 'Set "Cache-Control: no-store, no-cache, must-revalidate, max-age=0" for sensitive pages.'
            },
            'Clear-Site-Data': {
                'expected': ['"cache"', '"cookies"', '"storage"'],
                'not_expected': [],
                'match_type': 'CONTAINS_ALL',
                'weight': 5,
                'critical': False,
                'optional': True,
                'info': 'Instructs the browser to clear all caches, cookies, and storage data related to the origin of the request. Useful for logout pages.',
                'recommendation': 'For logout pages, consider adding "Clear-Site-Data: "cache", "cookies", "storage"" header.'
            },
            'Content-Security-Policy': {
                'expected': [
                    "default-src", 
                    "script-src", 
                    "object-src 'none'", 
                    "base-uri", 
                    "frame-ancestors",
                    "upgrade-insecure-requests"
                ],
                'not_expected': ["unsafe-inline", "unsafe-eval", "data:", "*"],
                'match_type': 'CSP_ANALYSIS',  # Changed to custom CSP analysis
                'pattern': r"default-src[^;]+;",
                'weight': 10,
                'critical': True,
                'optional': False,
                'info': 'Helps prevent XSS, clickjacking, and other code injection attacks.',
                'recommendation': 'Implement a comprehensive CSP header with appropriate directives and avoid unsafe-inline/unsafe-eval.'
            },
            'Cross-Origin-Embedder-Policy': {
                'expected': ['require-corp', 'credentialless'],
                'not_expected': [],
                'match_type': 'EXACT_MATCH',
                'weight': 5,
                'critical': False,
                'optional': True,
                'info': 'Prevents the document from loading cross-origin resources that don\'t explicitly grant permission.',
                'recommendation': 'Add "Cross-Origin-Embedder-Policy: require-corp" header for cross-origin isolation.'
            },
            'Cross-Origin-Opener-Policy': {
                'expected': ['same-origin', 'same-origin-allow-popups'],
                'not_expected': [],
                'match_type': 'EXACT_MATCH',
                'weight': 6,
                'critical': False,
                'optional': True,
                'info': 'Isolates your origin by ensuring cross-origin documents don\'t share browsing context.',
                'recommendation': 'Add "Cross-Origin-Opener-Policy: same-origin" header for cross-origin isolation.'
            },
            'Cross-Origin-Resource-Policy': {
                'expected': ['same-origin', 'same-site'],
                'not_expected': ['cross-origin'],
                'match_type': 'EXACT_MATCH',
                'weight': 6,
                'critical': False,
                'optional': True,
                'info': 'Prevents other websites from embedding your resources.',
                'recommendation': 'Add "Cross-Origin-Resource-Policy: same-origin" header for sensitive resources.'
            },
            'Origin-Agent-Cluster': {
                'expected': ['?1'],
                'not_expected': [],
                'match_type': 'EXACT_MATCH',
                'weight': 3,
                'critical': False,
                'optional': True,
                'info': 'Provides a hint to browsers that separate agent clusters should be used for this origin.',
                'recommendation': 'Consider adding "Origin-Agent-Cluster: ?1" header for improved isolation.'
            },
            'Permissions-Policy': {
                'expected': [
                    "geolocation=()", 
                    "microphone=()", 
                    "camera=()",
                    "payment=()"
                ],
                'not_expected': [],
                'match_type': 'CONTAINS_ANY',
                'weight': 7,
                'critical': False,
                'optional': False,
                'info': 'Controls which browser features can be used by the page.',
                'recommendation': 'Implement a restrictive Permissions-Policy header to limit browser features.'
            },
            'Referrer-Policy': {
                'expected': [
                    'strict-origin-when-cross-origin', 
                    'no-referrer', 
                    'same-origin', 
                    'strict-origin'
                ],
                'not_expected': ['unsafe-url', 'no-referrer-when-downgrade'],
                'match_type': 'EXACT_MATCH',
                'weight': 6,
                'critical': False,
                'optional': False,
                'info': 'Controls how much referrer information should be included with requests.',
                'recommendation': 'Use "Referrer-Policy: strict-origin-when-cross-origin" to limit information leakage.'
            },
            'Strict-Transport-Security': {
                'expected': ['max-age='],
                'not_expected': [],
                'match_type': 'COMPLEX',
                'min_age': 15768000,  # 6 months in seconds
                'require_subdomains': True,
                'weight': 10,
                'critical': True,
                'optional': False,
                'info': 'Enforces HTTPS connections by telling browsers to only use HTTPS for a specified period.',
                'recommendation': 'Set "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" to enforce HTTPS.'
            },
            'X-Content-Type-Options': {
                'expected': ['nosniff'],
                'not_expected': [],
                'match_type': 'EXACT_MATCH',
                'weight': 8,
                'critical': True,
                'optional': False,
                'info': 'Prevents MIME type sniffing, which can be used to execute disguised malicious content.',
                'recommendation': 'Add "X-Content-Type-Options: nosniff" header.'
            },
            'X-Frame-Options': {
                'expected': ['DENY', 'SAMEORIGIN'],
                'not_expected': ['ALLOW-FROM'],
                'match_type': 'EXACT_MATCH',
                'weight': 8,
                'critical': True,
                'optional': False,
                'info': 'Protects against clickjacking attacks by preventing the page from being displayed in a frame.',
                'recommendation': 'Use "X-Frame-Options: DENY" for pages that should not be framed, or "SAMEORIGIN" for pages that can be framed by the same origin.'
            },
            'X-Permitted-Cross-Domain-Policies': {
                'expected': ['none'],
                'not_expected': ['all'],
                'match_type': 'EXACT_MATCH',
                'weight': 4,
                'critical': False,
                'optional': True,
                'info': 'Controls if cross-domain policy files can be used on your website.',
                'recommendation': 'Add "X-Permitted-Cross-Domain-Policies: none" header.'
            },
            'X-XSS-Protection': {
                'expected': ['0', '1; mode=block'],
                'not_expected': ['1'],
                'match_type': 'EXACT_MATCH',
                'weight': 5,
                'critical': False,
                'optional': True,
                'info': 'Legacy header to control XSS filtering in older browsers. "0" is recommended to avoid potential XSS vulnerabilities in older browsers.',
                'recommendation': 'Set "X-XSS-Protection: 0" as this header is deprecated and can be problematic in older browsers.'
            },
            'Content-Type': {
                'expected': ['charset=utf-8'],
                'not_expected': [],
                'match_type': 'CONTAINS',
                'weight': 4,
                'critical': False,
                'optional': True,
                'info': 'Specifies the media type and character encoding of the resource.',
                'recommendation': 'Ensure Content-Type includes "charset=utf-8" to prevent encoding-based attacks.'
            },
            'Set-Cookie': {
                'expected': ['Secure', 'HttpOnly', 'SameSite=Strict', 'SameSite=Lax'],
                'not_expected': ['SameSite=None'],
                'match_type': 'COOKIE_ANALYSIS',
                'weight': 9,
                'critical': True,
                'optional': True,
                'context_dependent': True,
                'info': 'Ensures cookies are sent over HTTPS, not accessible via JavaScript, and protected against CSRF attacks.',
                'recommendation': 'Ensure all cookies use "Secure; HttpOnly; SameSite=Strict" flags for sensitive cookies.'
            },
            'Access-Control-Allow-Origin': {
                'expected': [],
                'not_expected': ['*'],
                'match_type': 'CUSTOM',
                'weight': 7,
                'critical': True,
                'optional': True,
                'context_dependent': True,
                'info': 'Controls which websites can access resources on your site. "*" allows any origin which can be a security risk for sensitive APIs.',
                'recommendation': 'Avoid using wildcard "*" in ACAO header for sensitive endpoints; specify exact origins instead.'
            },
            'Access-Control-Allow-Credentials': {
                'expected': [],
                'not_expected': [],
                'match_type': 'CORS_CREDENTIALS',
                'weight': 6,
                'critical': False,
                'optional': True,
                'context_dependent': True,
                'info': 'Indicates whether the response can be shared with resources with the given origin and credentials.',
                'recommendation': 'Never use this with "Access-Control-Allow-Origin: *" as it creates a security risk.'
            },
            'Access-Control-Allow-Methods': {
                'expected': [],
                'not_expected': [],
                'match_type': 'CORS_METHODS',
                'weight': 4,
                'critical': False,
                'optional': True,
                'context_dependent': True,
                'info': 'Specifies the methods allowed when accessing the resource in response to a preflight request.',
                'recommendation': 'Restrict to only the HTTP methods your API needs.'
            },
            'Server': {
                'expected': [],
                'not_expected': [],
                'match_type': 'SERVER_INFO',
                'weight': 3,
                'critical': False,
                'optional': True,
                'info': 'Reveals information about the server software, which can help attackers identify vulnerabilities.',
                'recommendation': 'Consider removing or obfuscating the Server header to reduce information disclosure.'
            },
            'X-Powered-By': {
                'expected': [],
                'not_expected': [],
                'match_type': 'PRESENCE_CHECK',
                'weight': 3,
                'critical': False,
                'optional': True,
                'info': 'Reveals information about the technology used on the server, which can help attackers identify vulnerabilities.',
                'recommendation': 'Remove the X-Powered-By header to reduce information disclosure.'
            },
            'X-AspNet-Version': {
                'expected': [],
                'not_expected': [],
                'match_type': 'PRESENCE_CHECK',
                'weight': 3,
                'critical': False,
                'optional': True,
                'info': 'Reveals the version of ASP.NET being used, which helps attackers identify potential vulnerabilities.',
                'recommendation': 'Remove the X-AspNet-Version header to reduce information disclosure.'
            },
            'X-AspNetMvc-Version': {
                'expected': [],
                'not_expected': [],
                'match_type': 'PRESENCE_CHECK',
                'weight': 3,
                'critical': False,
                'optional': True,
                'info': 'Reveals the version of ASP.NET MVC being used, which helps attackers identify potential vulnerabilities.',
                'recommendation': 'Remove the X-AspNetMvc-Version header to reduce information disclosure.'
            },
            'Public-Key-Pins': {
                'expected': [],
                'not_expected': [],
                'match_type': 'DEPRECATED',
                'weight': 1,
                'critical': False,
                'optional': True,
                'info': 'Deprecated header that can lead to site lockout if misconfigured. Avoid using.',
                'recommendation': 'Don\'t use HPKP. It is deprecated and can cause site lockout if misconfigured.'
            },
            'Feature-Policy': {
                'expected': [],
                'not_expected': [],
                'match_type': 'DEPRECATED',
                'weight': 2,
                'critical': False,
                'optional': True,
                'info': 'Deprecated header that has been replaced by Permissions-Policy.',
                'recommendation': 'Replace Feature-Policy with the modern Permissions-Policy header.'
            },
            'Expect-CT': {
                'expected': [],
                'not_expected': [],
                'match_type': 'DEPRECATED',
                'weight': 2,
                'critical': False,
                'optional': True,
                'info': 'Deprecated header for Certificate Transparency enforcement, now built into browsers.',
                'recommendation': 'This header is no longer needed as CT is enforced by modern browsers.'
            },
            'NEL': {
                'expected': [],
                'not_expected': [],
                'match_type': 'NETWORK_ERROR',
                'weight': 2,
                'critical': False,
                'optional': True,
                'info': 'Network Error Logging helps monitor client-side connection issues.',
                'recommendation': 'Consider implementing NEL to monitor network errors clients encounter.'
            },
            'Report-To': {
                'expected': [],
                'not_expected': [],
                'match_type': 'REPORTING',
                'weight': 2,
                'critical': False,
                'optional': True,
                'info': 'Defines a reporting endpoint for various browser features.',
                'recommendation': 'Consider implementing Report-To for monitoring security issues.'
            }
        }

    def fetch_headers(self, url, follow_redirects=False, verify_ssl=True):
        """Fetch HTTP headers from a URL with proper error handling"""
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme:
                url = f"https://{url}"  # Default to HTTPS if no scheme provided
                
            response = requests.get(url, timeout=10, allow_redirects=follow_redirects, verify=verify_ssl)
            
            # Check if we got redirected (3xx status code)
            if not follow_redirects and 300 <= response.status_code < 400:
                redirect_url = response.headers.get('Location', '')
                print(f"{Fore.YELLOW}Warning: Received redirect to {redirect_url}")
                print(f"{Fore.YELLOW}Use the --follow-redirects flag to follow redirects.")
                
            return response.headers, response.status_code, url
        except requests.exceptions.SSLError:
            print(f"{Fore.RED}SSL Certificate verification failed. Use --no-verify to bypass.")
            return None, None, url
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}Connection error: Unable to connect to {url}")
            return None, None, url
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}Timeout error: The request to {url} timed out")
            return None, None, url
        except requests.exceptions.TooManyRedirects:
            print(f"{Fore.RED}Too many redirects for {url}")
            return None, None, url
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error fetching headers from {url}: {str(e)}")
            return None, None, url

    def read_headers_from_file(self, file_path):
        """Read headers from a file with improved parsing"""
        try:
            headers = {}
            with open(file_path, 'r') as file:
                # Process HTTP response line if present
                first_line = file.readline().strip()
                status_code = None
                if first_line.startswith('HTTP/'):
                    try:
                        protocol, status_parts = first_line.split(' ', 1)
                        status_code = int(status_parts.split(' ')[0])
                    except (ValueError, IndexError):
                        status_code = None
                else:
                    # If not a response line, reset to start of file
                    file.seek(0)
                
                # Process headers
                for line in file:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        # Handle multiple headers with the same name (e.g., Set-Cookie)
                        if key in headers:
                            if isinstance(headers[key], list):
                                headers[key].append(value)
                            else:
                                headers[key] = [headers[key], value]
                        else:
                            headers[key] = value
            
            return headers, status_code, file_path
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File {file_path} not found.")
            return None, None, file_path
        except Exception as e:
            print(f"{Fore.RED}Error reading headers from file: {str(e)}")
            return None, None, file_path

    def _normalize_headers(self, headers):
        """Create case-insensitive lookup for headers"""
        self.normalized_headers = {}
        for header, value in headers.items():
            self.normalized_headers[header.lower()] = (header, value)
        
    def _get_header_case_insensitive(self, header_name):
        """Get header value using case-insensitive lookup"""
        header_lower = header_name.lower()
        if header_lower in self.normalized_headers:
            return self.normalized_headers[header_lower][1]
        return None
        
    def _header_exists_case_insensitive(self, header_name):
        """Check if header exists using case-insensitive lookup"""
        return header_name.lower() in self.normalized_headers
            
    def analyze_headers(self, headers, source_url=None, show_all=True):
        """Analyze HTTP headers for security issues with improved checks"""
        if not headers:
            return
            
        self.security_score = 0
        self.max_score = 0
        self.partial_score = 0  # Added for partial credit system
        self.critical_issues = []
        self.warnings = []
        self.recommendations = set()  # Changed to set to avoid duplicates
        self.analyzed_results = {}
        self.original_headers = headers
        
        # Create normalized header lookup
        self._normalize_headers(headers)
        
        # Detect context-specific features
        has_cookies = self._header_exists_case_insensitive('Set-Cookie') 
        has_cors = any(h.lower().startswith('access-control-') for h in self.normalized_headers)
        
        # Analyze present headers
        for header_standard_name in self.required_headers.keys():
            # Check if header exists (case-insensitive)
            header_value = self._get_header_case_insensitive(header_standard_name)
            
            if header_value is not None:
                # Header exists, analyze it
                self._analyze_header(header_standard_name, header_value, source_url)
            else:
                # Header is missing, analyze as missing
                self._analyze_missing_header(header_standard_name, has_cookies, has_cors, show_all)
        
        # Analyze unknown headers
        for header_name, _ in self.normalized_headers.items():
            original_name, value = self.normalized_headers[header_name]
            if not any(std_name.lower() == header_name for std_name in self.required_headers.keys()):
                self._analyze_unknown_header(original_name, value)
        
        # Calculate final score with partial credit
        if self.max_score > 0:
            self.security_score = ((self.security_score + (self.partial_score * 0.5)) / self.max_score) * 100
        
        # Detect common misconfigurations
        self._detect_common_misconfigurations()
        
        return self.analyzed_results
    
    def _analyze_missing_header(self, header, has_cookies=True, has_cors=True, show_all=True):
        """Analyze a header that is missing"""
        settings = self.required_headers.get(header, {})
        
        # Skip contextual headers if they don't apply to this context
        is_contextual_skip = False
        if settings.get('context_dependent', False):
            if header == 'Set-Cookie' and not has_cookies:
                is_contextual_skip = True
            elif header.startswith('Access-Control-') and not has_cors:
                is_contextual_skip = True
                
        if is_contextual_skip:
            if show_all:
                self._analyze_missing_contextual(header, settings)
            return
        
        weight = settings.get('weight', 5)
        
        # Only add to max_score for required (non-optional) headers
        if not settings.get('optional', False):
            self.max_score += weight
            
        # Add to critical issues if it's a critical header
        if settings.get('critical', False) and not settings.get('optional', False):
            self.critical_issues.append(f"Missing critical header: {header}")
            
        # Add specific recommendation
        if settings.get('match_type') != 'PRESENCE_CHECK':
            # Only add "add header" recommendation for headers that should be present
            self.recommendations.add(settings.get('recommendation', f"Add the {header} header."))
        
        # Store result
        self.analyzed_results[header] = {
            'status': 'missing',
            'value': None,
            'issues': [f"Missing header. {settings.get('info', '')}"],
            'recommendations': [settings.get('recommendation', f"Add the {header} header.")] if settings.get('match_type') != 'PRESENCE_CHECK' else [],
            'score': 0,
            'max_score': weight,
            'critical': settings.get('critical', False),
            'optional': settings.get('optional', False)
        }
    
    def _analyze_missing_contextual(self, header, settings):
        """Analyze a contextual header that is missing but may not be required"""
        weight = settings.get('weight', 5)
        
        self.analyzed_results[header] = {
            'status': 'not_applicable',
            'value': None,
            'issues': [f"Not applicable in this context. {settings.get('info', '')}"],
            'recommendations': [settings.get('recommendation', '')] if settings.get('match_type') != 'PRESENCE_CHECK' else [],
            'score': 0,
            'max_score': weight,
            'critical': False,
            'optional': True
        }
    
    def _analyze_header(self, header, value, source_url=None):
        """Analyze a specific header against requirements"""
        settings = self.required_headers.get(header, {})
        match_type = settings.get('match_type', 'EXACT_MATCH')
        weight = settings.get('weight', 5)
        
        # For scoring, only consider non-optional headers
        if not settings.get('optional', False):
            self.max_score += weight
        
        # Initialize result structure
        result = {
            'status': 'unknown',
            'value': value,
            'issues': [],
            'recommendations': [],
            'score': 0,
            'max_score': weight,
            'critical': settings.get('critical', False),
            'optional': settings.get('optional', False)
        }
        
        # Handle multiple header values (typically for Set-Cookie)
        if isinstance(value, list):
            if header == 'Set-Cookie':
                return self._analyze_cookies(value, settings, result)
            else:
                # Join multiple values for analysis
                value = ', '.join(value)
        
        # Convert value to string and lowercase for matching
        if value is not None:
            value = str(value).lower()
        
        score = 0
        partial = 0
        
        # Different analysis methods based on match_type
        if match_type == 'DEPRECATED':
            result['issues'].append(f"Deprecated header. {settings.get('info', '')}")
            result['recommendations'].append(settings.get('recommendation', ''))
            result['status'] = 'warning'
            score = weight * 0.5  # Give partial credit for deprecated headers
            
        elif match_type == 'PRESENCE_CHECK':
            result['issues'].append(f"Information disclosure. {settings.get('info', '')}")
            result['recommendations'].append(settings.get('recommendation', ''))
            result['status'] = 'warning'
            score = 0  # No credit for headers that should be removed
            
        elif match_type == 'SERVER_INFO':
            self._analyze_server_header(value, result)
            score = result['score']
            
        elif match_type == 'EXACT_MATCH':
            self._check_exact_match(value, settings, result)
            score = result['score']
            
        elif match_type == 'CONTAINS':
            self._check_contains(value, settings, result)
            score = result['score']
            
        elif match_type == 'CONTAINS_ANY':
            self._check_contains_any(value, settings, result)
            score = result['score']
            
        elif match_type == 'CONTAINS_ALL':
            self._check_contains_all(value, settings, result)
            score = result['score']
            
        elif match_type == 'REGEX':
            self._check_regex(value, settings, result)
            score = result['score']
            
        elif match_type == 'CSP_ANALYSIS':
            score, partial = self._analyze_csp(value, settings, result)
            
        elif match_type == 'COMPLEX':
            if header == 'Strict-Transport-Security':
                self._analyze_hsts(value, settings, result, source_url)
                score = result['score']
            
        elif match_type == 'CUSTOM':
            if header == 'Access-Control-Allow-Origin':
                self._analyze_acao(value, settings, result)
                score = result['score']
                
        elif match_type == 'CORS_CREDENTIALS':
            self._analyze_cors_credentials(value, result)
            score = result['score']
            
        elif match_type == 'CORS_METHODS':
            self._analyze_cors_methods(value, result)
            score = result['score']
            
        elif match_type == 'NETWORK_ERROR':
            self._analyze_nel(value, result)
            score = result['score']
            
        elif match_type == 'REPORTING':
            self._analyze_reporting(value, result)
            score = result['score']
        
        # Update security score
        if not settings.get('optional', False):
            self.security_score += score
            self.partial_score += partial
        
        result['score'] = score
        self.analyzed_results[header] = result
        
        # Add to critical issues if needed
        if result['status'] == 'fail' and settings.get('critical', False):
            self.critical_issues.append(f"Critical security issue: {header} - {', '.join(result.get('issues', []))}")
        elif result['status'] == 'warning':
            self.warnings.append(f"{header}: {', '.join(result.get('issues', []))}")
        
        # Add recommendations
        for rec in result.get('recommendations', []):
            if rec:
                self.recommendations.add(rec)
                
        return result
    
    def _analyze_csp(self, value, settings, result):
        """Analyze Content-Security-Policy header"""
        expected = [str(e).lower() for e in settings.get('expected', [])]
        not_expected = [str(n).lower() for n in settings.get('not_expected', [])]
        weight = settings.get('weight', 10)
        
        # Parse CSP directives
        directives = {}
        parts = value.split(';')
        for part in parts:
            part = part.strip()
            if not part:
                continue
                
            directive_parts = part.split(None, 1)
            if len(directive_parts) == 1:
                directive_name = directive_parts[0]
                directive_value = ""
            else:
                directive_name, directive_value = directive_parts
                
            directives[directive_name] = directive_value.split()
            
        # Check for critical directives
        critical_directives = ['default-src', 'script-src', 'object-src', 'base-uri', 'frame-ancestors']
        found_critical = [d for d in critical_directives if d in directives]
        missing_critical = [d for d in critical_directives if d not in directives]
        
        # Check for unsafe values
        unsafe_values = []
        for directive, values in directives.items():
            for item in not_expected:
                if any(item in v for v in values):
                    unsafe_values.append(f"{directive} contains {item}")
        
        # Special case for upgrade-insecure-requests
        has_upgrade = 'upgrade-insecure-requests' in directives
        
        # Determine score based on completeness
        if len(found_critical) == len(critical_directives) and not unsafe_values:
            result['status'] = 'pass'
            result['score'] = weight
            return weight, 0
        elif has_upgrade and not missing_critical and not unsafe_values:
            # All critical directives and upgrade-insecure-requests
            result['status'] = 'pass'
            result['score'] = weight
            return weight, 0
        elif has_upgrade and not unsafe_values:
            # Partial implementation with upgrade-insecure-requests
            result['status'] = 'warning'
            if missing_critical:
                result['issues'].append(f"CSP has upgrade-insecure-requests but is missing critical directives: {', '.join(missing_critical)}")
            result['recommendations'].append("Enhance CSP with missing critical directives: " + 
                                          ', '.join(missing_critical))
            result['score'] = weight * 0.3  # 30% credit for having upgrade-insecure-requests
            return 0, weight * 0.5  # Return partial credit
        elif len(found_critical) > 0:
            # Some critical directives but incomplete
            result['status'] = 'warning'
            result['issues'].append(f"Incomplete CSP implementation. Missing: {', '.join(missing_critical)}")
            if unsafe_values:
                result['issues'].append(f"CSP contains unsafe values: {', '.join(unsafe_values)}")
            result['recommendations'].append(settings.get('recommendation', ''))
            result['score'] = weight * 0.2  # 20% credit
            return 0, weight * 0.3  # Return partial credit
        else:
            # Minimal or no CSP implementation
            result['status'] = 'fail'
            result['issues'].append("Minimal or ineffective CSP implementation.")
            result['recommendations'].append(settings.get('recommendation', ''))
            result['score'] = 0
            return 0, 0  # No credit
    
    def _check_exact_match(self, value, settings, result):
        """Check if the header value exactly matches any of the expected values"""
        expected = [str(e).lower() for e in settings.get('expected', [])]
        not_expected = [str(n).lower() for n in settings.get('not_expected', [])]
        
        if not expected:
            # If no expected values, check only for "not expected" values
            for item in not_expected:
                if item == value:
                    result['status'] = 'fail'
                    result['issues'].append(f"Value '{item}' should not be used.")
                    result['recommendations'].append(settings.get('recommendation', ''))
                    result['score'] = 0
                    return
            # If nothing forbidden is found, it's OK
            result['status'] = 'pass'
            result['score'] = settings.get('weight', 5)
            return
            
        # Check if value is among the expected values
        if value in expected:
            # Still check for forbidden parts
            for item in not_expected:
                if item == value:
                    result['status'] = 'fail'
                    result['issues'].append(f"Value '{item}' should not be used.")
                    result['recommendations'].append(settings.get('recommendation', ''))
                    result['score'] = 0
                    return
            # All good
            result['status'] = 'pass'
            result['score'] = settings.get('weight', 5)
        else:
            result['status'] = 'fail'
            expected_str = ', '.join(expected)
            result['issues'].append(f"Expected one of: {expected_str}")
            result['recommendations'].append(settings.get('recommendation', ''))
            result['score'] = 0
    
    def _check_contains(self, value, settings, result):
        """Check if the header value contains the expected substring"""
        expected = [str(e).lower() for e in settings.get('expected', [])]
        not_expected = [str(n).lower() for n in settings.get('not_expected', [])]
        
        # Check for forbidden values first
        for item in not_expected:
            if item in value:
                result['status'] = 'fail'
                result['issues'].append(f"Value should not contain '{item}'.")
                result['recommendations'].append(settings.get('recommendation', ''))
                result['score'] = 0
                return
        
        # Check if all expected values are present
        if not expected:
            # If no expectations, and no forbidden values, it's a pass
            result['status'] = 'pass'
            result['score'] = settings.get('weight', 5)
            return
            
        for item in expected:
            if item not in value:
                result['status'] = 'fail'
                result['issues'].append(f"Value should contain '{item}'.")
                result['recommendations'].append(settings.get('recommendation', ''))
                result['score'] = 0
                return
                
        # All expected values found and no forbidden values
        result['status'] = 'pass'
        result['score'] = settings.get('weight', 5)
    
    def _check_contains_any(self, value, settings, result):
        """Check if the header value contains any of the expected substrings"""
        expected = [str(e).lower() for e in settings.get('expected', [])]
        not_expected = [str(n).lower() for n in settings.get('not_expected', [])]
        
        # Check for forbidden values first
        for item in not_expected:
            if item in value:
                result['status'] = 'fail'
                result['issues'].append(f"Value should not contain '{item}'.")
                result['recommendations'].append(settings.get('recommendation', ''))
                result['score'] = 0
                return
        
        # Check if any expected value is present
        if not expected:
            # If no expectations, and no forbidden values, it's a pass
            result['status'] = 'pass'
            result['score'] = settings.get('weight', 5)
            return
            
        found_any = False
        for item in expected:
            if item in value:
                found_any = True
                break
                
        if found_any:
            result['status'] = 'pass'
            result['score'] = settings.get('weight', 5)
        else:
            result['status'] = 'fail'
            expected_str = ', '.join(expected)
            result['issues'].append(f"Value should contain at least one of: {expected_str}")
            result['recommendations'].append(settings.get('recommendation', ''))
            result['score'] = 0
    
    def _check_contains_all(self, value, settings, result):
        """Check if the header value contains all expected substrings"""
        expected = [str(e).lower() for e in settings.get('expected', [])]
        not_expected = [str(n).lower() for n in settings.get('not_expected', [])]
        
        # Check for forbidden values first
        for item in not_expected:
            if item in value:
                result['status'] = 'fail'
                result['issues'].append(f"Value should not contain '{item}'.")
                result['recommendations'].append(settings.get('recommendation', ''))
                result['score'] = 0
                return
        
        # Check if all expected values are present
        if not expected:
            # If no expectations, and no forbidden values, it's a pass
            result['status'] = 'pass'
            result['score'] = settings.get('weight', 5)
            return
            
        missing = []
        for item in expected:
            if item not in value:
                missing.append(item)
                
        if missing:
            result['status'] = 'fail'
            missing_str = ', '.join(missing)
            result['issues'].append(f"Missing required values: {missing_str}")
            result['recommendations'].append(settings.get('recommendation', ''))
            result['score'] = 0
        else:
            result['status'] = 'pass'
            result['score'] = settings.get('weight', 5)
    
    def _check_regex(self, value, settings, result):
        """Check if the header value matches the expected regex pattern"""
        pattern = settings.get('pattern', '')
        expected = [str(e).lower() for e in settings.get('expected', [])]
        not_expected = [str(n).lower() for n in settings.get('not_expected', [])]
        
        if pattern:
            # Check if pattern matches
            if re.search(pattern, value, re.IGNORECASE):
                # Check for forbidden values
                for item in not_expected:
                    if item in value:
                        result['status'] = 'fail'
                        result['issues'].append(f"Value should not contain '{item}'.")
                        result['recommendations'].append(settings.get('recommendation', ''))
                        result['score'] = 0
                        return
                
                # All good with regex match
                result['status'] = 'pass'
                result['score'] = settings.get('weight', 5)
            else:
                result['status'] = 'fail'
                result['issues'].append(f"Value doesn't match expected pattern.")
                result['recommendations'].append(settings.get('recommendation', ''))
                result['score'] = 0
            return
            
        # No pattern, check for expected values
        for item in not_expected:
            if item in value:
                result['status'] = 'fail'
                result['issues'].append(f"Value should not contain '{item}'.")
                result['recommendations'].append(settings.get('recommendation', ''))
                result['score'] = 0
                return
                
        # Check if any of the expected values are present
        found = False
        missing = []
        for item in expected:
            if item in value:
                found = True
            else:
                missing.append(item)
                
        if not found and expected:
            result['status'] = 'fail'
            expected_str = ', '.join(expected)
            result['issues'].append(f"Value should contain at least one of: {expected_str}")
            result['recommendations'].append(settings.get('recommendation', ''))
            result['score'] = 0
        else:
            # At least one expected value found
            result['status'] = 'pass' if not missing else 'warning'
            if missing:
                missing_str = ', '.join(missing)
                result['issues'].append(f"Could improve by adding: {missing_str}")
                result['recommendations'].append(settings.get('recommendation', ''))
                result['score'] = settings.get('weight', 5) * 0.75  # Partial credit
            else:
                result['score'] = settings.get('weight', 5)  # Full credit
    
    def _analyze_server_header(self, value, result):
        """Analyze the Server header for information disclosure"""
        if not value:
            result['status'] = 'pass'
            result['score'] = result['max_score']
            return
            
        # Check for Cloudflare
        if 'cloudflare' in value.lower():
            result['status'] = 'pass'
            result['score'] = result['max_score']
            result['issues'].append("Server header indicates Cloudflare CDN which is legitimate, but still reveals server information.")
            result['recommendations'].append("Using Cloudflare is good practice, but you can still customize this header for additional security.")
            return
            
        # Check for detailed version information
        version_pattern = r'[\d\.]+|/[\d\.]+|\s[\d\.]+'
        detailed_version = re.search(version_pattern, value)
        
        if detailed_version:
            result['status'] = 'warning'
            result['issues'].append("Server header reveals detailed version information, which helps attackers identify vulnerabilities.")
            result['recommendations'].append("Consider removing version details from the Server header or removing it entirely.")
            result['score'] = 0
        else:
            result['status'] = 'warning'
            result['issues'].append("Server header reveals software information, which can help attackers.")
            result['recommendations'].append("Consider removing or obfuscating the Server header.")
            result['score'] = result['max_score'] * 0.5  # Partial credit for basic info
    
    def _analyze_hsts(self, value, settings, result, source_url=None):
        """Analyze the Strict-Transport-Security header specifically"""
        if not value:
            result['status'] = 'fail'
            result['issues'].append("Empty HSTS header value.")
            result['recommendations'].append(settings.get('recommendation', ''))
            result['score'] = 0
            return
            
        # Check if using HTTP instead of HTTPS
        if source_url and source_url.startswith('http://'):
            result['status'] = 'fail'
            result['issues'].append("HSTS header sent over HTTP connection, which is ineffective. Must use HTTPS.")
            result['recommendations'].append("Switch to HTTPS before implementing HSTS.")
            result['score'] = 0
            return
            
        # Check max-age
        max_age_match = re.search(r'max-age=(\d+)', value)
        if not max_age_match:
            result['status'] = 'fail'
            result['issues'].append("Missing max-age directive in HSTS header.")
            result['recommendations'].append(settings.get('recommendation', ''))
            result['score'] = 0
            return
            
        # Check if max-age is sufficient
        max_age = int(max_age_match.group(1))
        min_age = settings.get('min_age', 15768000)  # Default 6 months
        
        if max_age < min_age:
            result['status'] = 'warning'
            result['issues'].append(f"HSTS max-age ({max_age} seconds) is less than recommended ({min_age} seconds).")
            result['recommendations'].append(f"Increase max-age to at least {min_age} seconds (about {min_age//86400} days).")
            result['score'] = result['max_score'] * 0.5  # Partial credit
            
        # Check for includeSubDomains if required
        if settings.get('require_subdomains', True) and 'includesubdomains' not in value:
            if result['status'] != 'fail':  # Don't override a fail status
                result['status'] = 'warning'
            result['issues'].append("Missing 'includeSubDomains' directive in HSTS header.")
            result['recommendations'].append("Add 'includeSubDomains' to protect all subdomains.")
            if result['score'] > result['max_score'] * 0.75:
                result['score'] = result['max_score'] * 0.75  # Reduce score but don't raise it
                
        # Check for preload
        if 'preload' not in value:
            if result['status'] != 'fail' and result['status'] != 'warning':
                result['status'] = 'info'
            result['issues'].append("Consider adding 'preload' directive for maximum protection.")
            result['recommendations'].append("Add 'preload' directive and submit your site to the HSTS preload list.")
            
        # If no issues found so far, it's a pass
        if result['status'] == 'unknown':
            result['status'] = 'pass'
            result['score'] = result['max_score']
            
    def _analyze_acao(self, value, settings, result):
        """Analyze the Access-Control-Allow-Origin header"""
        if not value:
            result['status'] = 'pass'  # Absence is secure by default
            result['score'] = result['max_score']
            return
            
        # Check for wildcard
        if value == '*':
            # Check if credentials are allowed
            credentials_header = None
            for header_key in self.normalized_headers:
                if header_key == 'access-control-allow-credentials':
                    _, credentials_header = self.normalized_headers[header_key]
                    break
            
            if credentials_header and credentials_header.lower() == 'true':
                result['status'] = 'fail'
                result['issues'].append("Wildcard ACAO '*' with credentials is a serious security risk and violates the CORS spec.")
                result['recommendations'].append("Specify exact origins instead of '*' when using credentials.")
                result['score'] = 0
                return
            else:
                result['status'] = 'warning'
                result['issues'].append("Wildcard ACAO allows any domain to access resources, which is fine for public content but risky for authenticated APIs.")
                result['recommendations'].append("Replace '*' with specific origins for authenticated APIs.")
                result['score'] = result['max_score'] * 0.5  # Partial credit
                return
            
        # Check for null
        if value.lower() == 'null':
            result['status'] = 'warning'
            result['issues'].append("'null' can be spoofed and may allow unexpected origins to access resources.")
            result['recommendations'].append("Avoid using 'null', specify exact origins instead.")
            result['score'] = result['max_score'] * 0.5
            return
            
        # Specific origins are the most secure
        result['status'] = 'pass'
        result['score'] = result['max_score']
            
    def _analyze_cors_credentials(self, value, result):
        """Analyze Access-Control-Allow-Credentials header"""
        if value and value.lower() == 'true':
            acao_header = None
            for header_key in self.normalized_headers:
                if header_key == 'access-control-allow-origin':
                    _, acao_header = self.normalized_headers[header_key]
                    break
                    
            if acao_header == '*':
                result['status'] = 'fail'
                result['issues'].append("Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: * is a security risk and violates the CORS spec.")
                result['recommendations'].append("Specify exact origins instead of '*' when using credentials.")
                result['score'] = 0
            else:
                result['status'] = 'pass'
                result['score'] = result['max_score']
        else:
            result['status'] = 'pass'
            result['score'] = result['max_score']
            
    def _analyze_cors_methods(self, value, result):
        """Analyze Access-Control-Allow-Methods header"""
        risky_methods = ['DELETE', 'PUT', 'TRACE']
        if value:
            value_upper = value.upper()
            for method in risky_methods:
                if method in value_upper:
                    result['status'] = 'warning'
                    result['issues'].append(f"CORS allows potentially dangerous HTTP method: {method}")
                    result['recommendations'].append("Restrict CORS methods to only those needed by your API.")
                    result['score'] = result['max_score'] * 0.5
                    return
                    
        result['status'] = 'pass'
        result['score'] = result['max_score']
    
    def _analyze_nel(self, value, result):
        """Analyze Network Error Logging header"""
        # Basic implementation for NEL - simply passing
        result['status'] = 'pass'
        result['score'] = result['max_score']
    
    def _analyze_reporting(self, value, result):
        """Analyze Report-To header"""
        # Basic implementation for Report-To - simply passing
        result['status'] = 'pass'
        result['score'] = result['max_score']
            
    def _analyze_cookies(self, cookies, settings, result):
        """Analyze Set-Cookie headers for security flags"""
        if not cookies:
            result['status'] = 'pass'  # No cookies is secure
            result['score'] = result['max_score']
            return result
            
        issues = []
        secure_count = 0
        httponly_count = 0
        samesite_count = 0
        secure_cookies = 0
        
        # Total cookies to check (excluding cookie attributes)
        total_cookies_to_check = 0
        
        # For each cookie, analyze its security flags
        for cookie in cookies:
            cookie_lower = cookie.lower()
            
            # Check if this is an actual cookie or just a cookie attribute
            # Skip cookie attributes like 'Path=/', 'Expires=...'
            if any(directive in cookie_lower for directive in ['path=', 'expires=', 'max-age=', 'domain=']) and \
               '=' not in cookie_lower.split(';')[0]:
                continue
                
            total_cookies_to_check += 1
            
            # Parse the cookie
            cookie_name = cookie.split('=')[0].strip() if '=' in cookie else 'unknown'
            
            # Check for session cookie (no Expires or Max-Age)
            is_session_cookie = ('expires=' not in cookie_lower and 'max-age=' not in cookie_lower)
            
            # Check for Secure flag
            if 'secure' in cookie_lower:
                secure_count += 1
            else:
                if is_session_cookie:
                    issues.append(f"Session cookie '{cookie_name}' missing Secure flag (high risk)")
                else:
                    issues.append(f"Cookie '{cookie_name}' missing Secure flag")
                
            # Check for HttpOnly flag
            if 'httponly' in cookie_lower:
                httponly_count += 1
            else:
                if is_session_cookie:
                    issues.append(f"Session cookie '{cookie_name}' missing HttpOnly flag (high risk)")
                else:
                    issues.append(f"Cookie '{cookie_name}' missing HttpOnly flag")
                
            # Check for SameSite attribute
            if 'samesite=strict' in cookie_lower or 'samesite=lax' in cookie_lower:
                samesite_count += 1
            elif 'samesite=none' in cookie_lower and 'secure' in cookie_lower:
                # This is acceptable but less preferred
                samesite_count += 0.5
            else:
                if is_session_cookie:
                    issues.append(f"Session cookie '{cookie_name}' missing or has weak SameSite attribute (high risk)")
                else:
                    issues.append(f"Cookie '{cookie_name}' missing or has weak SameSite attribute")
                
            # Count as secure if it has all three protections
            if 'secure' in cookie_lower and 'httponly' in cookie_lower and \
               ('samesite=strict' in cookie_lower or 'samesite=lax' in cookie_lower):
                secure_cookies += 1
                
        # Determine overall status based on proportion of secure cookies
        if total_cookies_to_check == 0:
            result['status'] = 'pass'
            result['score'] = result['max_score']
        elif secure_cookies == total_cookies_to_check:
            result['status'] = 'pass'
            result['score'] = result['max_score']
        elif secure_cookies >= total_cookies_to_check * 0.75:
            result['status'] = 'warning'
            result['issues'] = issues
            result['recommendations'] = [settings.get('recommendation', '')]
            result['score'] = result['max_score'] * 0.75
        else:
            result['status'] = 'fail'
            result['issues'] = issues
            result['recommendations'] = [settings.get('recommendation', '')]
            if total_cookies_to_check > 0:
                result['score'] = result['max_score'] * (secure_cookies / total_cookies_to_check)
            else:
                result['score'] = 0
            
        return result
        
    def _analyze_unknown_header(self, header, value):
        """Analyze headers that are not in the requirements list"""
        # Some headers might reveal unnecessary information
        info_disclosure_headers = ['x-powered-by', 'server', 'x-aspnet-version', 'x-aspnetmvc-version']
        
        if header.lower() in info_disclosure_headers:
            self.warnings.append(f"{header} header reveals technology information which could help attackers.")
            self.recommendations.add(f"Consider removing the {header} header to reduce information disclosure.")
            
        # Headers that might be misspelled versions of security headers
        security_header_variants = {
            'content-security': 'Content-Security-Policy',
            'x-frame': 'X-Frame-Options',
            'x-xss': 'X-XSS-Protection',
            'strict-transport': 'Strict-Transport-Security',
            'x-content-type': 'X-Content-Type-Options',
            'access-control': 'Access-Control-Allow-Origin'
        }
        
        for prefix, correct in security_header_variants.items():
            if (header.lower().startswith(prefix.lower()) and 
                header.lower() != correct.lower() and
                header.lower() not in [
                    'access-control-allow-methods', 
                    'access-control-allow-headers', 
                    'access-control-allow-credentials',
                    'access-control-max-age',
                    'access-control-expose-headers'
                ]):
                self.warnings.append(f"{header} might be a misspelled version of {correct}.")
                self.recommendations.add(f"Check if {header} should be replaced with {correct}.")
                
        # Dangerous headers to watch for
        dangerous_headers = {
            'public-key-pins': 'HPKP is deprecated and can lead to site lockout if misconfigured',
            'access-control-allow-credentials': 'Ensure this is not used with wildcard Access-Control-Allow-Origin'
        }
        
        if header.lower() in dangerous_headers:
            self.warnings.append(f"{header}: {dangerous_headers[header.lower()]}")
    
    def _detect_common_misconfigurations(self):
        """Detect common security misconfigurations across multiple headers"""
        
        # Check for inconsistent framing policies
        csp_present = self._header_exists_case_insensitive('Content-Security-Policy')
        xfo_present = self._header_exists_case_insensitive('X-Frame-Options')
        
        if csp_present and xfo_present:
            csp = self._get_header_case_insensitive('Content-Security-Policy').lower()
            xfo = self._get_header_case_insensitive('X-Frame-Options').lower()
            
            if 'frame-ancestors' in csp:
                if 'frame-ancestors none' in csp and xfo != 'deny':
                    self.warnings.append("Inconsistent framing policy: CSP frame-ancestors 'none' but X-Frame-Options is not 'DENY'")
                    self.recommendations.add("Make X-Frame-Options and CSP frame-ancestors consistent, preferably 'DENY' and 'none' respectively")
                    
                if 'frame-ancestors' in csp and 'self' in csp and xfo != 'sameorigin':
                    self.warnings.append("Inconsistent framing policy: CSP frame-ancestors 'self' but X-Frame-Options is not 'SAMEORIGIN'")
                    self.recommendations.add("Make X-Frame-Options and CSP frame-ancestors consistent")
        
        # Check for incomplete CORS configuration
        cors_headers_present = False
        for header_key in self.normalized_headers:
            if header_key.startswith('access-control-'):
                cors_headers_present = True
                break
                
        if cors_headers_present and not self._header_exists_case_insensitive('Access-Control-Allow-Origin'):
            self.warnings.append("CORS headers present but Access-Control-Allow-Origin is missing")
            self.recommendations.add("Add the Access-Control-Allow-Origin header to properly implement CORS")
            
        # Check for redundant framing protection
        if csp_present and xfo_present:
            csp = self._get_header_case_insensitive('Content-Security-Policy')
            if 'frame-ancestors' in csp:
                self.warnings.append("Both X-Frame-Options and CSP frame-ancestors are specified, modern browsers will prefer CSP")
                self.recommendations.add("You can keep both for backward compatibility, but ensure they specify the same policy")
        
        # Check for critical CORS misconfiguration
        if (self._header_exists_case_insensitive('Access-Control-Allow-Origin') and 
            self._header_exists_case_insensitive('Access-Control-Allow-Credentials')):
            
            acao = self._get_header_case_insensitive('Access-Control-Allow-Origin')
            acac = self._get_header_case_insensitive('Access-Control-Allow-Credentials')
            
            if acao == '*' and acac.lower() == 'true':
                self.critical_issues.append("Critical CORS misconfiguration: wildcard origin (*) with credentials enabled - this is a violation of the CORS spec and a security risk")
                self.recommendations.add("Never use Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: *")
    
    def print_results(self, show_headers=True, verbose=False, output_format='text', show_optional=True):
        """Print analysis results in various formats"""
        if output_format == 'json':
            self._print_json_results()
            return
            
        # Calculate pass/fail statistics
        total_headers = len(self.analyzed_results)
        passed = sum(1 for h in self.analyzed_results.values() if h['status'] == 'pass')
        warnings = sum(1 for h in self.analyzed_results.values() if h['status'] == 'warning')
        failed = sum(1 for h in self.analyzed_results.values() if h['status'] == 'fail')
        
        missing_required = sum(1 for h in self.analyzed_results.values() 
                          if h['status'] == 'missing' and not h.get('optional', False))
        missing_optional = sum(1 for h in self.analyzed_results.values() 
                          if h['status'] == 'missing' and h.get('optional', True))
        not_applicable = sum(1 for h in self.analyzed_results.values() if h['status'] == 'not_applicable')
        
        # Generate summary
        print_header("Security Headers Analysis Summary")
        print(f"Security Score: {Fore.YELLOW}{self.security_score:.1f}%{Style.RESET_ALL}")
        print(f"Headers analyzed: {total_headers}")
        print(f"Passed: {Fore.GREEN}{passed}{Style.RESET_ALL}")
        print(f"Warnings: {Fore.YELLOW}{warnings}{Style.RESET_ALL}")
        print(f"Failed: {Fore.RED}{failed}{Style.RESET_ALL}")
        print(f"Missing (Required): {Fore.RED}{missing_required}{Style.RESET_ALL}")
        
        if verbose:
            print(f"Missing (Optional): {Fore.YELLOW}{missing_optional}{Style.RESET_ALL}")
            print(f"Not Applicable: {Fore.CYAN}{not_applicable}{Style.RESET_ALL}")
        
        # Show critical issues
        if self.critical_issues:
            print_header("Critical Security Issues")
            for issue in self.critical_issues:
                print(f"{Fore.RED}{issue}{Style.RESET_ALL}")
        
        # Show headers if requested
        if show_headers:
            print_header("Headers Present in the Response")
            for original_name, value in self.original_headers.items():
                # Handle multiple header values (like Set-Cookie)
                if isinstance(value, list):
                    print(f"{Fore.GREEN}{original_name}:")
                    for val in value:
                        print(f"  {Fore.YELLOW}{val}")
                else:
                    print(f"{Fore.GREEN}{original_name}: {Fore.YELLOW}{value}")
        
        # Show analysis results
        print_header("Analysis Results")
        
        # Sort headers by status (critical failures first)
        sorted_headers = sorted(
            self.analyzed_results.items(),
            key=lambda x: (
                0 if x[1]['status'] == 'fail' and x[1]['critical'] else
                1 if x[1]['status'] == 'fail' else
                2 if x[1]['status'] == 'missing' and not x[1].get('optional', False) else
                3 if x[1]['status'] == 'warning' else
                4 if x[1]['status'] == 'missing' and x[1].get('optional', False) else
                5 if x[1]['status'] == 'not_applicable' else 6
            )
        )
        
        for header, result in sorted_headers:
            # Skip optional headers if not showing them
            if not show_optional and result.get('optional', False) and result['status'] in ['missing', 'not_applicable']:
                continue
                
            # Format output based on status
            if result['status'] == 'pass':
                status_color = Fore.GREEN
                status_text = "PASS"
            elif result['status'] == 'warning':
                status_color = Fore.YELLOW
                status_text = "WARNING"
            elif result['status'] == 'fail':
                status_color = Fore.RED
                status_text = "FAIL"
            elif result['status'] == 'missing':
                if result.get('optional', False):
                    status_color = Fore.YELLOW
                    status_text = "MISSING (OPTIONAL)"
                else:
                    status_color = Fore.RED
                    status_text = "MISSING"
            elif result['status'] == 'not_applicable':
                status_color = Fore.CYAN
                status_text = "NOT APPLICABLE"
            else:
                status_color = Fore.WHITE
                status_text = "INFO"
                
            # Print header status
            header_line = f"{Fore.GREEN}{header}: {status_color}{status_text}"
            if result['critical'] and (result['status'] == 'fail' or result['status'] == 'missing'):
                header_line += f" {Fore.RED}(CRITICAL){Style.RESET_ALL}"
            print(header_line)
            
            # Print current value
            if result['value'] is not None:
                # Handle list of values (typically for Set-Cookie)
                if isinstance(result['value'], list):
                    print(f"  {Fore.CYAN}Current value:")
                    for val in result['value']:
                        print(f"    {Fore.YELLOW}{val}")
                else:
                    print(f"  {Fore.CYAN}Current value: {Fore.YELLOW}{result['value']}")
            
            # Print issues
            if result['issues'] and (verbose or result['status'] not in ['pass', 'not_applicable']):
                for issue in result['issues']:
                    print(f"  {Fore.RED}Issue: {issue}")
            
            # Print recommendations
            if result['recommendations'] and (verbose or result['status'] not in ['pass', 'not_applicable']):
                for rec in result['recommendations']:
                    if rec:  # Skip empty recommendations
                        print(f"  {Fore.GREEN}Recommendation: {Fore.YELLOW}{rec}")
        
        # Show optional headers section
        if show_optional:
            print_header("Optional Security Headers")
            optional_headers = [h for h, r in self.analyzed_results.items() 
                              if r.get('optional', False) and r['status'] == 'missing']
            
            if optional_headers:
                for header in optional_headers:
                    result = self.analyzed_results[header]
                    
                    # Skip PRESENCE_CHECK headers in optional section 
                    # (only want headers that should be added, not ones that should be removed if present)
                    if self.required_headers.get(header, {}).get('match_type') == 'PRESENCE_CHECK':
                        continue
                        
                    info = self.required_headers.get(header, {}).get('info', '')
                    recommendation = self.required_headers.get(header, {}).get('recommendation', '')
                    print(f"{Fore.YELLOW}{header}: {info}")
                    print(f"  {Fore.GREEN}Recommendation: {Fore.CYAN}{recommendation}")
            else:
                print(f"{Fore.CYAN}No additional optional headers to recommend.{Style.RESET_ALL}")
        
        # Show general recommendations
        if self.recommendations:
            print_header("Security Recommendations")
            for i, rec in enumerate(sorted(self.recommendations), 1):
                print(f"{i}. {Fore.YELLOW}{rec}{Style.RESET_ALL}")
    
    def _print_json_results(self):
        """Print results in JSON format"""
        import json
        
        output = {
            'security_score': round(self.security_score, 1),
            'headers_analyzed': len(self.analyzed_results),
            'critical_issues': self.critical_issues,
            'warnings': self.warnings,
            'recommendations': list(self.recommendations),
            'headers': {header: {
                'status': result['status'],
                'value': result['value'],
                'issues': result['issues'],
                'recommendations': result['recommendations'],
                'score': result['score'],
                'max_score': result['max_score'],
                'critical': result['critical'],
                'optional': result.get('optional', False)
            } for header, result in self.analyzed_results.items()}
        }
        
        print(json.dumps(output, indent=2))
        
def print_header(text):
    """Prints text as an ASCII art header."""
    style = Style.BRIGHT + Fore.CYAN
    print(style + "=" * 80)
    print(style + f"{text}".center(80))
    print(style + "=" * 80)

def fetch_headers_curl_format(curl_command):
    """Extract and fetch headers from a curl command"""
    import re
    
    # Extract URL from curl command
    url_match = re.search(r'curl\s+["\']?([^"\'>\s]+)["\']?', curl_command)
    if not url_match:
        print(f"{Fore.RED}Error: Could not extract URL from curl command.")
        return None, None, None
        
    url = url_match.group(1)
    
    # Check for header options in curl command
    header_matches = re.findall(r'-H\s+["\']([^"\']+)["\']', curl_command)
    headers = {}
    
    for header in header_matches:
        if ':' in header:
            key, value = header.split(':', 1)
            headers[key.strip()] = value.strip()
    
    # Use requests to make the actual request
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response.headers, response.status_code, url
    except requests.RequestException as e:
        print(f"{Fore.RED}Error fetching headers: {str(e)}")
        return None, None, None

def main():
    parser = argparse.ArgumentParser(description='Enhanced security headers analyzer for HTTP responses.')
    parser.add_argument('--url', help='URL to fetch headers from')
    parser.add_argument('--file', help='Local file to read headers from')
    parser.add_argument('--curl', help='Analyze headers from a curl command')
    parser.add_argument('--config', help='Path to custom header requirements JSON file')
    parser.add_argument('--follow-redirects', action='store_true', help='Follow redirects when fetching headers')
    parser.add_argument('--no-verify', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('--no-headers', action='store_true', help='Don\'t show the original headers')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show verbose output')
    parser.add_argument('--output', '-o', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('--compare', help='Compare headers with another URL or file')
    parser.add_argument('--export', help='Export results to file')
    parser.add_argument('--check-csp', action='store_true', help='Perform detailed CSP analysis')
    parser.add_argument('--ignore-optional', action='store_true', help='Hide optional headers in output')
    parser.add_argument('--show-all-headers', action='store_true', help='Show all possible security headers')
    args = parser.parse_args()

    analyzer = HeaderAnalyzer(config_file=args.config)
    
    headers = None
    status_code = None
    source = None
    
    if args.url:
        headers, status_code, source = analyzer.fetch_headers(
            args.url,
            follow_redirects=args.follow_redirects,
            verify_ssl=not args.no_verify
        )
    elif args.file:
        headers, status_code, source = analyzer.read_headers_from_file(args.file)
    elif args.curl:
        headers, status_code, source = fetch_headers_curl_format(args.curl)
    else:
        print("Please provide a URL, file path, or curl command.")
        return
        
    if headers:
        analyzer.original_headers = headers
        
        analyzer.analyze_headers(headers, source, show_all=args.show_all_headers)
        
        analyzer.print_results(
            show_headers=not args.no_headers,
            verbose=args.verbose,
            output_format=args.output,
            show_optional=not args.ignore_optional
        )
        
        if args.export:
            try:
                with open(args.export, 'w') as f:
                    if args.output == 'json':
                        import json
                        json.dump({
                            'security_score': round(analyzer.security_score, 1),
                            'headers_analyzed': len(analyzer.analyzed_results),
                            'critical_issues': analyzer.critical_issues,
                            'warnings': analyzer.warnings,
                            'recommendations': list(analyzer.recommendations),
                            'headers': {header: {
                                'status': result['status'],
                                'value': result['value'],
                                'issues': result['issues'],
                                'recommendations': result['recommendations'],
                                'score': result['score'],
                                'max_score': result['max_score'],
                                'critical': result['critical'],
                                'optional': result.get('optional', False)
                            } for header, result in analyzer.analyzed_results.items()}
                        }, f, indent=2)
                    else:
                        f.write(f"Security Headers Analysis Results\n")
                        f.write(f"==============================\n\n")
                        f.write(f"Security Score: {analyzer.security_score:.1f}%\n")
                        f.write(f"Headers analyzed: {len(analyzer.analyzed_results)}\n\n")
                        
                        if analyzer.critical_issues:
                            f.write("Critical Security Issues:\n")
                            for issue in analyzer.critical_issues:
                                f.write(f"- {issue}\n")
                            f.write("\n")
                            
                        f.write("Header Analysis:\n")
                        for header, result in analyzer.analyzed_results.items():
                            if args.ignore_optional and result.get('optional', False) and result['status'] == 'missing':
                                continue
                                
                            f.write(f"* {header}: {result['status'].upper()}\n")
                            if result['issues']:
                                for issue in result['issues']:
                                    f.write(f"  - Issue: {issue}\n")
                            if result['recommendations']:
                                for rec in result['recommendations']:
                                    if rec:
                                        f.write(f"  - Recommendation: {rec}\n")
                            f.write("\n")
                            
                        if analyzer.recommendations:
                            f.write("Security Recommendations:\n")
                            for i, rec in enumerate(sorted(analyzer.recommendations), 1):
                                f.write(f"{i}. {rec}\n")
                print(f"Results exported to {args.export}")
            except Exception as e:
                print(f"Error exporting results: {str(e)}")
        
        if args.compare:
            print_header(f"Comparing with {args.compare}")
            compare_analyzer = HeaderAnalyzer(config_file=args.config)
            compare_headers = None
            
            if args.compare.startswith(('http://', 'https://')):
                compare_headers, compare_status, compare_source = compare_analyzer.fetch_headers(
                    args.compare,
                    follow_redirects=args.follow_redirects,
                    verify_ssl=not args.no_verify
                )
            else:
                compare_headers, compare_status, compare_source = compare_analyzer.read_headers_from_file(args.compare)
                
            if compare_headers:
                compare_analyzer.original_headers = compare_headers
                compare_analyzer.analyze_headers(compare_headers, compare_source, show_all=args.show_all_headers)
                
                print(f"Current score: {analyzer.security_score:.1f}% vs Compare score: {compare_analyzer.security_score:.1f}%")
                print(f"Difference: {(analyzer.security_score - compare_analyzer.security_score):.1f}%")
                
                all_headers = set(list(analyzer.analyzed_results.keys()) + list(compare_analyzer.analyzed_results.keys()))
                
                for header in sorted(all_headers):
                    current = analyzer.analyzed_results.get(header, {'status': 'missing', 'value': None, 'optional': False})
                    compare = compare_analyzer.analyzed_results.get(header, {'status': 'missing', 'value': None, 'optional': False})
                    
                    if args.ignore_optional and (current.get('optional', False) or compare.get('optional', False)):
                        continue
                    
                    if (current['status'] == compare['status'] and 
                        current['value'] == compare['value']):
                        if args.verbose:
                            print(f"{Fore.GREEN}{header}: {Fore.CYAN}Identical{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}{header}:")
                        current_status = current['status'].upper()
                        compare_status = compare['status'].upper()
                        
                        if current['status'] == 'pass':
                            current_status = f"{Fore.GREEN}{current_status}"
                        elif current['status'] == 'warning':
                            current_status = f"{Fore.YELLOW}{current_status}"
                        elif current['status'] in ['fail', 'missing']:
                            current_status = f"{Fore.RED}{current_status}"
                        else:
                            current_status = f"{Fore.CYAN}{current_status}"
                            
                        if compare['status'] == 'pass':
                            compare_status = f"{Fore.GREEN}{compare_status}"
                        elif compare['status'] == 'warning':
                            compare_status = f"{Fore.YELLOW}{compare_status}"
                        elif compare['status'] in ['fail', 'missing']:
                            compare_status = f"{Fore.RED}{compare_status}"
                        else:
                            compare_status = f"{Fore.CYAN}{compare_status}"
                        
                        print(f"  Current: {current_status}{Style.RESET_ALL} - {current['value']}")
                        print(f"  Compare: {compare_status}{Style.RESET_ALL} - {compare['value']}")
        
        if args.check_csp and analyzer._header_exists_case_insensitive('Content-Security-Policy'):
            print_header("Detailed CSP Analysis")
            csp = analyzer._get_header_case_insensitive('Content-Security-Policy')
            
            # Parse CSP directives
            directives = {}
            for part in csp.split(';'):
                part = part.strip()
                if not part:
                    continue
                    
                directive_parts = part.split(None, 1)
                if len(directive_parts) == 1:
                    directive_name = directive_parts[0]
                    directive_value = ""
                else:
                    directive_name, directive_value = directive_parts
                    
                directives[directive_name] = directive_value.split()
            
            # Check for key directives
            critical_directives = ['default-src', 'script-src', 'object-src', 'base-uri', 'frame-ancestors']
            for directive in critical_directives:
                if directive not in directives:
                    print(f"{Fore.RED}Missing critical directive: {directive}{Style.RESET_ALL}")
            
            # Check for unsafe values
            for directive, values in directives.items():
                unsafe = [v for v in values if 'unsafe' in v or v == '*' or v.startswith('data:')]
                if unsafe:
                    print(f"{Fore.YELLOW}{directive} has potentially unsafe values: {', '.join(unsafe)}{Style.RESET_ALL}")
            
            # Check for reporting configuration
            if 'report-uri' in directives:
                print(f"{Fore.GREEN}CSP reporting configured: {' '.join(directives['report-uri'])}{Style.RESET_ALL}")
            elif 'report-to' in directives:
                print(f"{Fore.GREEN}CSP reporting configured via report-to: {' '.join(directives['report-to'])}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}No CSP reporting configured. Consider adding report-uri or report-to.{Style.RESET_ALL}")
            
            # Check for nonce or hash usage
            nonce_usage = False
            hash_usage = False
            
            for directive, values in directives.items():
                for value in values:
                    if value.startswith("'nonce-"):
                        nonce_usage = True
                        print(f"{Fore.GREEN}Using nonce-based CSP for {directive}{Style.RESET_ALL}")
                    if any(value.startswith(f"'{h}-") for h in ['sha256', 'sha384', 'sha512']):
                        hash_usage = True
                        print(f"{Fore.GREEN}Using hash-based CSP for {directive}{Style.RESET_ALL}")
            
            # Check for default-src 'none'
            if 'default-src' in directives and "'none'" in directives['default-src']:
                print(f"{Fore.GREEN}CSP uses a strong default-src 'none' policy.{Style.RESET_ALL}")
            
            # Check for script-src 'self' without strict-dynamic
            if ('script-src' in directives and 
                "'self'" in directives['script-src'] and 
                not any("strict-dynamic" in v for v in directives['script-src'])):
                print(f"{Fore.YELLOW}script-src 'self' without strict-dynamic can be bypassed in some cases.{Style.RESET_ALL}")
                
            # Recommend nonce/hash if not used
            if not nonce_usage and not hash_usage:
                print(f"{Fore.YELLOW}No nonce or hash usage detected. Consider using nonces or hashes for better CSP security.{Style.RESET_ALL}")
            
            # Count unsafe values for overall evaluation
            unsafe_count = sum(1 for values in directives.values() 
                             for v in values if 'unsafe' in v or v == '*' or v.startswith('data:'))
            
            # Overall evaluation
            if unsafe_count == 0 and all(d in directives for d in critical_directives):
                print(f"{Fore.GREEN}CSP configuration looks strong.{Style.RESET_ALL}")
            elif unsafe_count > 3 or any(d not in directives for d in critical_directives):
                print(f"{Fore.RED}CSP configuration has significant weaknesses.{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}CSP configuration is moderate but could be improved.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
