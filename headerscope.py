import requests
import sys
import argparse
from colorama import Fore, Style, init
import textwrap

#Author: Vahe Demirkhanyan

init(autoreset=True)

def print_header(text):
    """Prints text as an ASCII art header."""
    style = Style.BRIGHT + Fore.CYAN
    print(style + "=" * 60)
    print(style + f"{text}".center(60))
    print(style + "=" * 60)

def fetch_headers(url):
    try:
        response = requests.get(url)
        return response.headers
    except requests.RequestException as e:
        return f"Error fetching headers from {url}: {str(e)}"

def read_headers_from_file(file_path):
    try:
        headers = {}
        with open(file_path, 'r') as file:
            for line in file:
                if ': ' in line:
                    key, value = line.strip().split(': ', 1)
                    headers[key] = value
        return headers
    except FileNotFoundError:
        return "Error: File not found."
    except Exception as e:
        return f"Error reading headers from file: {str(e)}"

def analyze_headers(headers):

    required_headers = {
        'Cache-Control': {
            'expected': ['no-store'], #'no-cache','max-age=0, must-revalidate' also ok
	    'not_expected': [],
            'match_type': 'AND',
            'info': 'Prevents the caching of the page, ensuring that sensitive information is not stored in the browser cache.'
        },
        'Clear-Site-Data': {
            'expected': ['"cache", "cookies", "storage"'],
            'not_expected': [],
            'match_type': 'AND',
            'info': 'Instructs the browser to clear all caches, cookies, and storage data related to the origin of the request.'
        },
        'Content-Security-Policy': {
            'expected': [
                "default-src 'self'; script-src 'none';",
                "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content",
                "default-src ‘self’; frame-ancestors ‘self’; form-action ‘self’",
                "default-src ‘none’; script-src ‘self’; connect-src ‘self’; img-src ‘self’; style-src ‘self’; frame-ancestors ‘self’; form-action ‘self’"
            ],
            'not_expected': ['inline'],
            'match_type': 'OR',
            'info': 'Helps prevent cross-site scripting and data injection attacks by restricting sources for scripts and other resources.'
        },
        'Cross-Origin-Embedder-Policy': {
            'expected': ['require-corp'],
            'not_expected': [],
            'match_type': 'AND',
            'info': 'Prevents the document from loading any cross-origin resources that do not explicitly grant the document permission, enhancing isolation and security.'
        },
        'Cross-Origin-Opener-Policy': {
            'expected': ['same-origin', 'same-origin-allow-popups'],
            'not_expected': [],
            'match_type': 'OR',
            'info': 'Isolates your origin, preventing other origins from sharing the same process or memory space, which protects against certain types of attacks like Spectre.'
        },
        'Cross-Origin-Resource-Policy': {
            'expected': ['same-origin', 'same-site'],
            'not_expected': [],
            'match_type': 'OR',
            'info': 'Prevents other domains from reading the content of the site, protecting against certain types of cross-origin information leaks and attacks.'
        },
        'Permissions-Policy': {
            'expected': [
                "geolocation=(), microphone=(), camera=()",
                "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), layout-animations=(self), legacy-image-formats=(self), magnetometer=(), microphone=(), midi=(), oversized-images=(self), payment=(), picture-in-picture=(), publickey-credentials-get=(), speaker-selection=(), sync-xhr=(self), unoptimized-images=(self), unsized-media=(self), usb=(), screen-wake-lock=(), web-share=(), xr-spatial-tracking=()"
            ],
            'not_expected': [],
            'match_type': 'AND',
            'info': 'Allows you to control which features and APIs can be used in the browser, reducing the risk of certain permissions being exploited by attackers.'
        },
        'Referrer-Policy': {
            'expected': ['strict-origin-when-cross-origin', 'no-referrer'],
            'not_expected': [],
            'match_type': 'OR',
            'info': 'Controls how much referrer information should be included with requests, enhancing privacy and security.'
        },
        'Strict-Transport-Security': {
            'expected': ['max-age=63072000; includeSubDomains; preload', 'max-age=31536000; includeSubDomains', 'max-age=15552000; includeSubDomains'],
            'not_expected': [],
            'match_type': 'OR',
            'info': 'Enforces secure (HTTP over SSL/TLS) connections to the server by requiring HTTPS for a specified period.'
        },
        'X-Content-Type-Options': {
            'expected': ['nosniff'],
            'not_expected': [],
            'match_type': 'AND',
            'info': 'Prevents MIME types security risk by blocking MIME type sniffing.'
        },
        'X-Frame-Options': {
            'expected': ['DENY', 'SAMEORIGIN'],
            'not_expected': [],
            'match_type': 'OR',
            'info': 'Protects against clickjacking by preventing the page from being displayed in a frame.'
        },
        'X-Permitted-Cross-Domain-Policies': {
            'expected': ['none'],
            'not_expected': [],
            'match_type': 'AND',
            'info': 'Prevents Adobe Flash and Adobe Acrobat from loading data from the domain.'
        },
        'X-XSS-Protection': {
            'expected': ['0'],
            'not_expected': [],
            'match_type': 'AND',
            'info': 'Disabling this can help avoid potential security issues in IE where this header might enable XSS attacks.'
        },
        'Set-Cookie': {
            'expected': ['Secure','HttpOnly'],
            'not_expected': [],
            'match_type': 'AND',
            'info': 'Ensures cookies are sent over HTTPS and not accessible via JavaScript.'
        },

}

    print_header("Headers Present in the Response")
    for header, value in headers.items():
        print(f"{header}: {Fore.YELLOW}{value}")

    print_header("Analysis Results")
    for header, settings in required_headers.items():
        if header in headers:
            header_values = headers[header].strip()
            missing_items = [item for item in settings['expected'] if item not in header_values]
            unwanted_items = [item for item in settings['not_expected'] if item in header_values]

            if unwanted_items:
                unwanted = ', '.join(unwanted_items)
                result = f"{Fore.GREEN}{header}: {Fore.RED + Style.BRIGHT}The header is insecure because it contains: {unwanted}"
            elif settings['match_type'] == 'AND' and missing_items:
                missing = ', '.join(missing_items)
                result = f"{Fore.GREEN}{header}: {Fore.YELLOW}The header is set but incorrectly configured. Missing: {missing}"
            elif settings['match_type'] == 'AND' and not missing_items:
                result = f"{Fore.GREEN}{header}: {Fore.GREEN + Style.BRIGHT}The header is set correctly."
            elif settings['match_type'] == 'OR' and not any(item in header_values for item in settings['expected']):
                expected = ', '.join(settings['expected'])
                result = f"{Fore.GREEN}{header}: {Fore.YELLOW}The header is set but incorrectly configured. Expected any of: {expected}"
            elif settings['match_type'] == 'OR':
                result = f"{Fore.GREEN}{header}: {Fore.GREEN + Style.BRIGHT}The header is set correctly."
        else:
            result = f"{Fore.GREEN}{header}: {Fore.RED}The header is missing. {settings['info']}"

        # Wrap the result to ensure it doesn't exceed 80 characters per line
        print(textwrap.fill(result, width=80, subsequent_indent='    '))

def main():
    parser = argparse.ArgumentParser(description='Analyze security headers from a URL or a local file.')
    parser.add_argument('--url', help='URL to fetch headers from.')
    parser.add_argument('--file', help='Local file to read headers from.')
    args = parser.parse_args()

    if args.url:
        headers = fetch_headers(args.url)
        if isinstance(headers, str):
            print(headers)
            return
    elif args.file:
        headers = read_headers_from_file(args.file)
        if isinstance(headers, str):
            print(headers)
            return
    else:
        print("Please provide a URL or a file path.")
        return

    if headers:
        analyze_headers(headers)

if __name__ == "__main__":
    main()
