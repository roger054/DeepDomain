#!/usr/bin/env python3
"""
DeepDomain v2.0 - Advanced Subdomain Enumeration Tool

Created by: Soheil Manna
GitHub: https://github.com/soheilmanna/deepdomain

Description:
    A professional-grade subdomain enumeration tool with advanced features including:
    - Multi-threaded DNS brute force
    - Certificate transparency logs integration
    - Passive intelligence gathering (OTX, Wayback Machine, Anubis, HackerTarget)
    - HTTP fingerprinting and security analysis
    - Web crawling for sensitive files and secrets
    - JavaScript/CSS asset analysis
    - CVE correlation for detected technologies
    - Professional risk assessment and reporting

Features:
    🔍 DNS Brute Force - High-speed multi-threaded subdomain discovery
    📜 Certificate Transparency - Extract subdomains from CT logs
    🌐 Passive Intelligence - Multiple API integrations for comprehensive data
    🔍 HTTP Fingerprinting - Technology detection and security analysis
    🕷️ Web Crawling - Robots.txt, sitemap.xml, and sensitive file detection
    🧠 Asset Analysis - JavaScript/CSS vulnerability scanning
    🛡️ CVE Correlation - Match technologies with known vulnerabilities
    📊 Professional Reporting - Detailed risk assessment with recommendations

License: MIT License
Contributions: Welcome! Please submit pull requests or issues on GitHub.

Requirements:
    - Python 3.6+
    - requests
    - tqdm (optional, for progress bars)
    - concurrent.futures (built-in)

Usage:
    python deepdomain.py example.com --fast       # Fast scan
    python deepdomain.py example.com --deep       # Deep scan with all features
    python deepdomain.py example.com --no-save    # Don't save results
"""

import argparse
import concurrent.futures
import json
import os
import re
import socket
import sys
import time
from datetime import datetime

import requests
import urllib3

# Disable SSL warnings for fingerprinting
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Tool information
__version__ = "2.0.0"
__author__ = "Soheil Manna"
__github__ = "https://github.com/soheilmanna/deepdomain"
__license__ = "MIT"

# Color codes for better output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_banner():
    """Print a cool banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                        DeepDomain v2.0                      ║
║              Advanced Subdomain Enumeration Tool            ║
║                                                              ║
║  🔍 DNS Brute Force  📜 Certificate Transparency            ║
║  🌐 API Integration  🔍 HTTP Fingerprinting                 ║
║                                                              ║
║  Created by: Soheil Manna                                    ║
║  Open Source - Contributions Welcome                        ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
    """
    print(banner)

def print_info(message):
    """Print info message with color"""
    print(f"{Colors.BLUE}[*]{Colors.END} {message}")

def print_success(message):
    """Print success message with color"""
    print(f"{Colors.GREEN}[+]{Colors.END} {message}")

def print_warning(message):
    """Print warning message with color"""
    print(f"{Colors.YELLOW}[!]{Colors.END} {message}")

def print_error(message):
    """Print error message with color"""
    print(f"{Colors.RED}[!]{Colors.END} {message}")

def validate_domain(domain):
    """Validate domain format"""
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return domain_pattern.match(domain) is not None




def resolve_subdomain(subdomain):
    """Resolve subdomain to IP address - only returns LIVE/VALID subdomains"""
    try:
        ip = socket.gethostbyname(subdomain)
        return subdomain, ip
    except socket.gaierror:
        # Subdomain doesn't exist/resolve - we don't return it
        return None

def validate_subdomain_live(subdomain):
    """Additional validation to check if subdomain is actually live"""
    try:
        # Try to resolve the subdomain
        ip = socket.gethostbyname(subdomain)

        # Additional check: try to connect to common ports
        import socket as sock
        for port in [80, 443]:
            try:
                s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
                s.settimeout(3)
                result = s.connect_ex((subdomain, port))
                s.close()
                if result == 0:  # Connection successful
                    return True, ip
            except:
                continue

        # Even if ports don't respond, if DNS resolves, it's live
        return True, ip
    except:
        return False, None

def generate_dynamic_subdomains(domain, generation_mode='comprehensive'):
    """Generate subdomains dynamically based on patterns and intelligence"""

    # Base prefixes for different categories
    base_prefixes = {
        'common': ['www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop', 'news'],
        'development': ['dev', 'test', 'staging', 'beta', 'alpha', 'demo', 'sandbox', 'lab'],
        'infrastructure': ['cdn', 'static', 'assets', 'img', 'media', 'files', 'backup'],
        'services': ['auth', 'login', 'sso', 'oauth', 'ldap', 'search', 'monitor'],
        'admin': ['dashboard', 'panel', 'control', 'manage', 'config', 'settings'],
        'business': ['support', 'help', 'docs', 'portal', 'app', 'mobile'],
        'database': ['db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'cache'],
        'security': ['secure', 'vpn', 'firewall', 'ssl', 'cert', 'key', 'secret'],
        'devops': ['ci', 'cd', 'jenkins', 'gitlab', 'git', 'build', 'deploy'],
        'geographic': ['us', 'eu', 'asia', 'uk', 'ca', 'au', 'jp', 'de', 'fr'],
        'numeric': [f'v{i}' for i in range(1, 6)] + [f'api{i}' for i in range(1, 4)],
        'environments': ['prod', 'production', 'live', 'stage', 'qa', 'uat']
    }

    # Generate combinations and variations
    generated_prefixes = set()

    # Add base prefixes
    for category, prefixes in base_prefixes.items():
        generated_prefixes.update(prefixes)

    # Generate combinations
    combinations = [
        # Environment + service combinations
        f"{env}-{service}" for env in ['dev', 'test', 'stage', 'prod']
        for service in ['api', 'app', 'web', 'admin', 'db']
    ]
    generated_prefixes.update(combinations)

    # Generate numbered variations
    numbered_variations = []
    for base in ['api', 'app', 'web', 'server', 'node', 'db']:
        for i in range(1, 6):
            numbered_variations.extend([f"{base}{i}", f"{base}-{i}", f"{base}0{i}"])
    generated_prefixes.update(numbered_variations)

    # Generate year-based variations
    current_year = datetime.now().year
    for year in range(current_year - 5, current_year + 2):
        generated_prefixes.update([f"app{year}", f"api{year}", f"v{year}"])

    # Generate domain-specific intelligent prefixes
    domain_parts = domain.split('.')
    if len(domain_parts) > 1:
        company_name = domain_parts[0]
        # Generate variations based on company name
        generated_prefixes.update([
            f"{company_name}-api", f"{company_name}-app", f"{company_name}-dev",
            f"my{company_name}", f"{company_name}app", f"{company_name}api"
        ])

    # Generate technology-specific prefixes
    tech_prefixes = [
        'wordpress', 'wp', 'drupal', 'joomla', 'magento', 'shopify',
        'react', 'angular', 'vue', 'node', 'express', 'django', 'flask',
        'laravel', 'symfony', 'rails', 'spring', 'tomcat', 'nginx', 'apache'
    ]
    generated_prefixes.update(tech_prefixes)

    # Generate cloud and service prefixes
    cloud_prefixes = [
        'aws', 'azure', 'gcp', 'cloud', 'k8s', 'kubernetes', 'docker',
        'grafana', 'prometheus', 'elk', 'kibana', 'jenkins', 'gitlab-ci'
    ]
    generated_prefixes.update(cloud_prefixes)

    # Filter based on generation mode
    if generation_mode == 'fast':
        # Return only most common prefixes for fast scanning
        priority_prefixes = set()
        for category in ['common', 'development', 'admin']:
            priority_prefixes.update(base_prefixes[category])
        return list(priority_prefixes)[:50]

    elif generation_mode == 'comprehensive':
        # Return all generated prefixes
        return list(generated_prefixes)

    elif generation_mode == 'targeted':
        # Return security-focused prefixes
        security_focused = set()
        for category in ['admin', 'security', 'development', 'services']:
            security_focused.update(base_prefixes[category])
        return list(security_focused)

    return list(generated_prefixes)

def dns_bruteforce(domain, wordlist_path=None, threads=50, live_only=False, generation_mode='comprehensive'):
    """Brute force subdomains using dynamic generation - only returns LIVE/VALID subdomains"""

    # Use dynamic generation by default, fallback to wordlist if provided
    if wordlist_path and os.path.exists(wordlist_path):
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print_info(f"Using custom wordlist: {len(words)} entries loaded")
        except Exception as e:
            print_error(f"Error reading wordlist: {e}")
            print_info("Falling back to dynamic generation")
            words = generate_dynamic_subdomains(domain, generation_mode)
    else:
        # Use dynamic generation
        print_info(f"Using dynamic subdomain generation (mode: {generation_mode})")
        words = generate_dynamic_subdomains(domain, generation_mode)

    print_info(f"Generated {len(words)} potential subdomain prefixes")

    # Create full subdomains
    subdomains = [f"{word}.{domain}" for word in words]

    validation_type = "Enhanced Live Validation" if live_only else "DNS Resolution"
    print_info(f"Testing {len(subdomains)} potential subdomains with {threads} threads ({validation_type})")

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Choose validation function based on live_only parameter
        validation_func = validate_subdomain_live if live_only else resolve_subdomain

        # Use tqdm for progress bar
        try:
            from tqdm import tqdm
            futures = {executor.submit(validation_func, sub): sub for sub in subdomains}

            desc = "Live Validation" if live_only else "DNS Brute Force"
            with tqdm(total=len(subdomains), desc=desc, unit="domains") as pbar:
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        if live_only:
                            is_live, ip = result
                            if is_live:
                                subdomain = futures[future]
                                found.append({'subdomain': subdomain, 'ip': ip, 'source': 'dns', 'validated': 'live'})
                                print_success(f"{subdomain} -> {ip} (LIVE)")
                        else:
                            subdomain, ip = result
                            found.append({'subdomain': subdomain, 'ip': ip, 'source': 'dns'})
                            print_success(f"{subdomain} -> {ip}")
                    pbar.update(1)
        except ImportError:
            # Fallback without progress bar
            futures = {executor.submit(validation_func, sub): sub for sub in subdomains}
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    if live_only:
                        is_live, ip = result
                        if is_live:
                            subdomain = futures[future]
                            found.append({'subdomain': subdomain, 'ip': ip, 'source': 'dns', 'validated': 'live'})
                            print_success(f"{subdomain} -> {ip} (LIVE)")
                    else:
                        subdomain, ip = result
                        found.append({'subdomain': subdomain, 'ip': ip, 'source': 'dns'})
                        print_success(f"{subdomain} -> {ip}")
                completed += 1
                if completed % 100 == 0:
                    print_info(f"Progress: {completed}/{len(subdomains)} domains tested")

    return found

def query_crtsh(domain):
    """Extract subdomains from certificate transparency logs"""
    subdomains = []
    unique_subdomains = set()

    try:
        print_info("Querying crt.sh certificate transparency logs...")
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        response = requests.get(url, timeout=15, headers={
            'User-Agent': 'DeepDomain/2.0 (Subdomain Enumeration Tool)'
        })

        if response.status_code == 200:
            try:
                data = response.json()
                print_info(f"Found {len(data)} certificates")

                for cert in data:
                    name_value = cert.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain and domain in subdomain:
                            # Clean up wildcard certificates and invalid entries
                            subdomain = subdomain.replace('*.', '')
                            subdomain = subdomain.replace('\r', '')

                            # Validate subdomain format
                            if validate_domain(subdomain) and subdomain not in unique_subdomains:
                                unique_subdomains.add(subdomain)
                                subdomains.append({'subdomain': subdomain, 'source': 'crtsh'})
                                print_success(f"crt.sh: {subdomain}")

            except json.JSONDecodeError:
                print_error("Failed to parse crt.sh JSON response")
        else:
            print_warning(f"crt.sh returned status code: {response.status_code}")

    except requests.RequestException as e:
        print_error(f"crt.sh connection error: {e}")
    except Exception as e:
        print_error(f"crt.sh unexpected error: {e}")

    print_info(f"Found {len(subdomains)} unique subdomains from crt.sh")
    return subdomains

def query_otx_api(domain, api_key=None):
    """Query AlienVault OTX for passive subdomain enumeration with public API access"""
    subdomains = []
    unique_subdomains = set()

    try:
        print_info("Querying AlienVault OTX API...")

        # Multiple OTX endpoints for comprehensive data
        endpoints = [
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/passive_dns",
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
        ]

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9'
        }

        if api_key:
            headers['X-OTX-API-KEY'] = api_key
            print_info("Using provided API key for enhanced OTX access")
        else:
            print_info("Using public OTX API access")

        total_found = 0

        for endpoint_url in endpoints:
            try:
                response = requests.get(endpoint_url, headers=headers, timeout=15)

                if response.status_code == 200:
                    try:
                        data = response.json()

                        # Handle passive DNS data
                        if 'passive_dns' in data:
                            passive_dns = data.get('passive_dns', [])
                            for record in passive_dns:
                                hostname = record.get('hostname', '').lower().strip()
                                if hostname and domain in hostname and validate_domain(hostname):
                                    if hostname not in unique_subdomains:
                                        unique_subdomains.add(hostname)
                                        subdomains.append({'subdomain': hostname, 'source': 'otx'})
                                        print_success(f"OTX: {hostname}")
                                        total_found += 1

                        # Handle URL list data
                        if 'url_list' in data:
                            url_list = data.get('url_list', [])
                            for url_data in url_list:
                                url = url_data.get('url', '')
                                if url:
                                    try:
                                        from urllib.parse import urlparse
                                        parsed = urlparse(url)
                                        hostname = parsed.hostname
                                        if hostname and domain in hostname and validate_domain(hostname):
                                            if hostname not in unique_subdomains:
                                                unique_subdomains.add(hostname)
                                                subdomains.append({'subdomain': hostname, 'source': 'otx'})
                                                print_success(f"OTX: {hostname}")
                                                total_found += 1
                                    except:
                                        continue

                    except json.JSONDecodeError:
                        continue

                elif response.status_code == 429:
                    print_warning("OTX API rate limit - continuing with other endpoints")
                    continue

            except requests.RequestException:
                continue

        # Try additional public OTX search
        try:
            search_url = f"https://otx.alienvault.com/api/v1/search/hostname?q={domain}&limit=100"
            response = requests.get(search_url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])
                for result in results:
                    hostname = result.get('hostname', '').lower().strip()
                    if hostname and domain in hostname and validate_domain(hostname):
                        if hostname not in unique_subdomains:
                            unique_subdomains.add(hostname)
                            subdomains.append({'subdomain': hostname, 'source': 'otx'})
                            print_success(f"OTX: {hostname}")
                            total_found += 1
        except:
            pass

    except Exception as e:
        print_error(f"OTX API error: {e}")

    print_info(f"Found {len(subdomains)} unique subdomains from OTX")
    return subdomains


def query_wayback_machine(domain):
    """Query Wayback Machine for historical subdomains"""
    subdomains = []

    try:
        print_info("Querying Wayback Machine archives...")

        # Wayback Machine CDX API
        url = f"http://web.archive.org/cdx/search/cdx"
        params = {
            'url': f"*.{domain}/*",
            'output': 'json',
            'fl': 'original',
            'collapse': 'urlkey',
            'limit': 10000
        }

        response = requests.get(url, params=params, timeout=15)
        if response.status_code == 200:
            data = response.json()
            unique_subdomains = set()

            for record in data[1:]:  # Skip header row
                if record and len(record) > 0:
                    original_url = record[0]
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(original_url)
                        hostname = parsed.hostname
                        if hostname and domain in hostname and hostname != domain and validate_domain(hostname):
                            unique_subdomains.add(hostname)
                            print_success(f"Wayback: {hostname}")
                    except:
                        continue

            # Convert to required format
            for subdomain in unique_subdomains:
                subdomains.append({
                    'subdomain': subdomain,
                    'source': 'wayback'
                })

            print_info(f"Found {len(unique_subdomains)} unique subdomains from Wayback Machine")

    except Exception as e:
        print_warning(f"Wayback Machine error: {e}")

    return subdomains


def query_anubis_db(domain):
    """Query Anubis subdomain database"""
    subdomains = []

    try:
        print_info("Querying Anubis subdomain database...")

        url = f"https://jldc.me/anubis/subdomains/{domain}"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            data = response.json()
            unique_subdomains = set()

            for subdomain in data:
                if subdomain and subdomain != domain and validate_domain(subdomain):
                    unique_subdomains.add(subdomain)
                    print_success(f"Anubis: {subdomain}")

            # Convert to required format
            for subdomain in unique_subdomains:
                subdomains.append({
                    'subdomain': subdomain,
                    'source': 'anubis'
                })

            print_info(f"Found {len(unique_subdomains)} unique subdomains from Anubis")

    except Exception as e:
        print_warning(f"Anubis database error: {e}")

    return subdomains


def query_hackertarget_api(domain):
    """Query HackerTarget API for subdomains"""
    subdomains = []

    try:
        print_info("Querying HackerTarget API...")

        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            lines = response.text.strip().split('\n')
            unique_subdomains = set()

            for line in lines:
                if ',' in line:
                    subdomain = line.split(',')[0].strip()
                    if subdomain and domain in subdomain and subdomain != domain and validate_domain(subdomain):
                        unique_subdomains.add(subdomain)
                        print_success(f"HackerTarget: {subdomain}")

            # Convert to required format
            for subdomain in unique_subdomains:
                subdomains.append({
                    'subdomain': subdomain,
                    'source': 'hackertarget'
                })

            print_info(f"Found {len(unique_subdomains)} unique subdomains from HackerTarget")

    except Exception as e:
        print_warning(f"HackerTarget API error: {e}")

    return subdomains


def display_professional_results(final_results, execution_time):
    """Display results in a professional, publication-ready format"""
    print(f"\n{Colors.BOLD}{'═'*80}{Colors.END}")
    print(f"{Colors.BOLD}🎯 SUBDOMAIN ENUMERATION RESULTS{Colors.END}")
    print(f"{Colors.BOLD}{'═'*80}{Colors.END}")

    if not final_results:
        print(f"{Colors.YELLOW}No subdomains discovered.{Colors.END}")
        print(f"{Colors.BOLD}{'═'*80}{Colors.END}")
        return

    # Sort by risk level for better presentation
    risk_priority = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    sorted_results = sorted(final_results, key=lambda x: (
        risk_priority.get(x.get('risk_level', x.get('risk', 'info')), 5),
        x.get('subdomain', '')
    ))

    # Calculate statistics
    risk_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    tech_stats = {}
    total_response_time = 0
    response_count = 0

    for result in sorted_results:
        # Handle both old and new risk field names
        risk = result.get('risk_level', result.get('risk', 'info'))
        if risk not in risk_stats:
            risk = 'info'  # fallback
        risk_stats[risk] += 1

        # Count technologies
        for tech in result.get('technologies', []):
            tech_stats[tech] = tech_stats.get(tech, 0) + 1

        # Response time stats
        resp_time = result.get('response_time_ms', result.get('response_time'))
        if resp_time:
            total_response_time += resp_time
            response_count += 1

    # Header with statistics
    total_subdomains = len(sorted_results)
    print(f"{Colors.CYAN}📊 Discovered {Colors.BOLD}{total_subdomains}{Colors.END}{Colors.CYAN} subdomains in {Colors.BOLD}{execution_time:.2f}s{Colors.END}")

    # Risk overview
    risk_colors = {
        'critical': Colors.MAGENTA,
        'high': Colors.RED,
        'medium': Colors.YELLOW,
        'low': Colors.GREEN,
        'info': Colors.BLUE
    }

    risk_summary = []
    for risk_level, count in risk_stats.items():
        if count > 0:
            color = risk_colors.get(risk_level, Colors.WHITE)
            risk_summary.append(f"{color}{count} {risk_level.upper()}{Colors.END}")

    if risk_summary:
        print(f"{Colors.CYAN}🛡️  Risk Distribution: {' | '.join(risk_summary)}{Colors.END}")

    print(f"{Colors.BOLD}{'─'*80}{Colors.END}")

    # Display results in professional format
    for i, result in enumerate(sorted_results, 1):
        subdomain = result.get('subdomain', 'N/A')
        ip = result.get('ip', 'N/A')
        status_code = result.get('status_code', result.get('status', ''))
        risk_level = result.get('risk_level', result.get('risk', 'info'))
        title = result.get('title', '')
        technologies = result.get('technologies', [])
        response_time = result.get('response_time_ms', result.get('response_time'))
        server = result.get('server', '')
        ports_open = result.get('ports_open', [])

        # Risk icon and color
        risk_icons = {
            'critical': '🔥',
            'high': '🔴',
            'medium': '🟡',
            'low': '🟢',
            'info': '🔵'
        }
        risk_icon = risk_icons.get(risk_level, '⚪')
        risk_color = risk_colors.get(risk_level, Colors.WHITE)

        # Main subdomain line
        print(f"{Colors.BOLD}{i:2d}.{Colors.END} {risk_icon} {Colors.BOLD}{subdomain}{Colors.END}")

        # IP and basic info line
        info_parts = []
        if ip != 'N/A':
            info_parts.append(f"{Colors.CYAN}{ip}{Colors.END}")
        if status_code:
            status_color = Colors.GREEN if str(status_code).startswith('2') else Colors.YELLOW if str(status_code).startswith('3') else Colors.RED
            info_parts.append(f"{status_color}HTTP {status_code}{Colors.END}")
        if response_time:
            info_parts.append(f"{Colors.BLUE}{response_time}ms{Colors.END}")
        if server and server != 'Unknown':
            info_parts.append(f"{Colors.MAGENTA}{server}{Colors.END}")

        if info_parts:
            print(f"    ├─ {' • '.join(info_parts)}")

        # Title line
        if title:
            title_display = title[:60] + "..." if len(title) > 60 else title
            print(f"    ├─ 📄 {Colors.WHITE}{title_display}{Colors.END}")

        # Technology line
        if technologies:
            tech_display = ', '.join(technologies[:4])
            if len(technologies) > 4:
                tech_display += f" (+{len(technologies)-4} more)"
            print(f"    ├─ 🔧 {Colors.BLUE}{tech_display}{Colors.END}")

        # Ports line
        if ports_open:
            ports_str = ', '.join(map(str, ports_open))
            print(f"    ├─ 🔌 Ports: {Colors.CYAN}{ports_str}{Colors.END}")

        # Enhanced risk assessment with detailed reasoning and recommendations
        risk_reasoning = result.get('risk_reasoning', [])
        sensitive_files = result.get('sensitive_files', {})
        js_css_analysis = result.get('js_css_analysis', {})

        print(f"    ├─ {risk_color}🛡️  Risk Level: {risk_level.upper()}{Colors.END}")

        # Show reasoning
        if risk_reasoning:
            for j, reason in enumerate(risk_reasoning[:4]):  # Show top 4 reasons
                connector = "├─" if j < len(risk_reasoning[:4]) - 1 or sensitive_files.get('sensitive_files') or js_css_analysis.get('vulnerable_libraries') else "├─"
                print(f"    {connector} {risk_color}   • {reason}{Colors.END}")

        # Show sensitive files if found
        if sensitive_files.get('sensitive_files'):
            print(f"    ├─ {Colors.RED}🚨 Sensitive Files Exposed:{Colors.END}")
            for sf in sensitive_files['sensitive_files'][:3]:
                print(f"    │     • {sf['path']} (HTTP {sf['status']})")

        # Show potential secrets
        if sensitive_files.get('potential_secrets'):
            print(f"    ├─ {Colors.MAGENTA}� Potential Secrets Found:{Colors.END}")
            for secret in sensitive_files['potential_secrets'][:2]:
                print(f"    │     • {secret['type']}: {secret['value']} in {secret['file']}")

        # Show vulnerable JS libraries
        if js_css_analysis.get('vulnerable_libraries'):
            print(f"    ├─ {Colors.YELLOW}⚠️  Vulnerable Libraries:{Colors.END}")
            for lib in js_css_analysis['vulnerable_libraries'][:2]:
                print(f"    │     • {lib['library']} {lib['version']}")

        # CVE correlation for detected technologies
        if technologies:
            cve_findings = correlate_cves_with_technologies(technologies)
            if cve_findings:
                print(f"    ├─ {Colors.RED}🔍 Associated CVEs:{Colors.END}")
                for cve in cve_findings[:3]:  # Show top 3 CVEs
                    severity_color = Colors.MAGENTA if cve['severity'] == 'CRITICAL' else Colors.RED if cve['severity'] == 'HIGH' else Colors.YELLOW
                    print(f"    │     • {severity_color}{cve['cve_id']}{Colors.END} ({cve['technology']}) - {cve['description']}")

        # Recommendations based on findings
        recommendations = []
        if risk_level == 'critical':
            recommendations.append("Immediate security review and remediation required")
        if sensitive_files.get('sensitive_files'):
            recommendations.append("Remove or protect exposed sensitive files")
        if sensitive_files.get('potential_secrets'):
            recommendations.append("Rotate exposed credentials immediately")
        if not result.get('security_headers', {}).get('X-Frame-Options'):
            recommendations.append("Implement security headers (X-Frame-Options, CSP)")

        if recommendations:
            print(f"    ├─ {Colors.CYAN}💡 Recommendations:{Colors.END}")
            for rec in recommendations[:2]:
                print(f"    │     • {rec}")

        print(f"    └─ {Colors.BLUE}📊 Analysis Complete{Colors.END}")

        # Spacing between entries
        if i < len(sorted_results):
            print()

    # Professional summary section
    print(f"\n{Colors.BOLD}{'═'*80}{Colors.END}")
    print(f"{Colors.BOLD}📈 ANALYSIS SUMMARY{Colors.END}")
    print(f"{Colors.BOLD}{'═'*80}{Colors.END}")

    # Critical findings alert
    if risk_stats['critical'] > 0:
        print(f"{Colors.MAGENTA}{Colors.BOLD}🚨 CRITICAL: {risk_stats['critical']} critical security issues found!{Colors.END}")
    if risk_stats['high'] > 0:
        print(f"{Colors.RED}{Colors.BOLD}⚠️  HIGH PRIORITY: {risk_stats['high']} high-risk subdomains require attention{Colors.END}")

    # Technology landscape
    if tech_stats:
        print(f"\n{Colors.BOLD}🔧 Technology Landscape:{Colors.END}")
        sorted_tech = sorted(tech_stats.items(), key=lambda x: x[1], reverse=True)[:6]
        tech_line = " • ".join([f"{Colors.BLUE}{tech}{Colors.END} ({count})" for tech, count in sorted_tech])
        print(f"   {tech_line}")

    # Performance metrics
    print(f"\n{Colors.BOLD}⚡ Performance Metrics:{Colors.END}")
    print(f"   • Enumeration Speed: {Colors.GREEN}{total_subdomains/execution_time:.1f} subdomains/sec{Colors.END}")
    if response_count > 0:
        avg_response = total_response_time / response_count
        print(f"   • Average Response Time: {Colors.BLUE}{avg_response:.0f}ms{Colors.END}")
    print(f"   • Total Execution Time: {Colors.BLUE}{execution_time:.2f}s{Colors.END}")

    print(f"{Colors.BOLD}{'═'*80}{Colors.END}")


def analyze_robots_and_sitemap(subdomain, scheme='https'):
    """Analyze robots.txt and sitemap.xml for additional intelligence"""
    findings = {
        'robots_txt': None,
        'sitemap_xml': None,
        'exposed_paths': [],
        'interesting_files': []
    }

    try:
        # Check robots.txt
        robots_url = f"{scheme}://{subdomain}/robots.txt"
        response = requests.get(robots_url, timeout=5, verify=False)
        if response.status_code == 200:
            findings['robots_txt'] = response.text
            # Extract disallowed paths
            for line in response.text.split('\n'):
                if line.strip().lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        findings['exposed_paths'].append(path)

        # Check sitemap.xml
        sitemap_url = f"{scheme}://{subdomain}/sitemap.xml"
        response = requests.get(sitemap_url, timeout=5, verify=False)
        if response.status_code == 200:
            findings['sitemap_xml'] = response.text
            # Extract URLs from sitemap
            import re
            urls = re.findall(r'<loc>(.*?)</loc>', response.text)
            for url in urls[:10]:  # Limit to first 10 URLs
                findings['exposed_paths'].append(url.replace(f"{scheme}://{subdomain}", ''))

    except:
        pass

    return findings


def crawl_for_sensitive_files(subdomain, scheme='https'):
    """Crawl subdomain for sensitive files and directories"""
    sensitive_paths = [
        '/.git/',
        '/.env',
        '/.DS_Store',
        '/backup/',
        '/backups/',
        '/config.php',
        '/wp-config.php',
        '/database.sql',
        '/dump.sql',
        '/phpinfo.php',
        '/info.php',
        '/test.php',
        '/admin.php',
        '/login.php',
        '/.htaccess',
        '/web.config',
        '/composer.json',
        '/package.json',
        '/yarn.lock',
        '/Gemfile',
        '/requirements.txt'
    ]

    findings = {
        'sensitive_files': [],
        'exposed_directories': [],
        'potential_secrets': []
    }

    try:
        for path in sensitive_paths:
            url = f"{scheme}://{subdomain}{path}"
            try:
                response = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                if response.status_code in [200, 403]:  # 403 might indicate file exists but is protected
                    findings['sensitive_files'].append({
                        'path': path,
                        'status': response.status_code,
                        'size': len(response.content)
                    })

                    # Look for secrets in accessible files
                    if response.status_code == 200 and len(response.content) < 50000:  # Limit size
                        content = response.text.lower()
                        secret_patterns = [
                            r'api[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9_-]+)',
                            r'secret[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9_-]+)',
                            r'password["\s]*[:=]["\s]*([a-zA-Z0-9_-]+)',
                            r'token["\s]*[:=]["\s]*([a-zA-Z0-9_-]+)',
                            r'mysql://([^"\'\\s]+)',
                            r'postgres://([^"\'\\s]+)',
                            r'mongodb://([^"\'\\s]+)'
                        ]

                        import re
                        for pattern in secret_patterns:
                            matches = re.findall(pattern, content)
                            for match in matches[:3]:  # Limit matches
                                findings['potential_secrets'].append({
                                    'type': pattern.split('[')[0],
                                    'value': match[:20] + '...' if len(match) > 20 else match,
                                    'file': path
                                })
            except:
                continue
    except:
        pass

    return findings


def analyze_js_css_assets(subdomain, scheme='https'):
    """Analyze JavaScript and CSS assets for vulnerabilities and leaks"""
    findings = {
        'js_libraries': [],
        'vulnerable_libraries': [],
        'cdn_assets': [],
        'potential_leaks': []
    }

    try:
        # Get main page to find JS/CSS assets
        response = requests.get(f"{scheme}://{subdomain}", timeout=10, verify=False)
        if response.status_code == 200:
            content = response.text

            # Extract JS and CSS files
            import re
            js_files = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', content)
            css_files = re.findall(r'<link[^>]*href=["\']([^"\']+\.css)["\']', content)

            # Analyze JS files
            for js_file in js_files[:5]:  # Limit to first 5 files
                try:
                    if js_file.startswith('//'):
                        js_file = f"{scheme}:{js_file}"
                    elif js_file.startswith('/'):
                        js_file = f"{scheme}://{subdomain}{js_file}"
                    elif not js_file.startswith('http'):
                        js_file = f"{scheme}://{subdomain}/{js_file}"

                    js_response = requests.get(js_file, timeout=5, verify=False)
                    if js_response.status_code == 200:
                        js_content = js_response.text.lower()

                        # Detect libraries
                        library_patterns = {
                            'jquery': r'jquery[.\s]*v?([0-9.]+)',
                            'angular': r'angular[.\s]*v?([0-9.]+)',
                            'react': r'react[.\s]*v?([0-9.]+)',
                            'vue': r'vue[.\s]*v?([0-9.]+)',
                            'bootstrap': r'bootstrap[.\s]*v?([0-9.]+)',
                            'lodash': r'lodash[.\s]*v?([0-9.]+)'
                        }

                        for lib, pattern in library_patterns.items():
                            matches = re.findall(pattern, js_content)
                            if matches:
                                version = matches[0]
                                findings['js_libraries'].append({
                                    'library': lib,
                                    'version': version,
                                    'file': js_file
                                })

                        # Look for potential secrets/leaks
                        leak_patterns = [
                            r'api[_-]?key["\s]*[:=]["\s]*["\']([a-zA-Z0-9_-]{10,})["\']',
                            r'secret[_-]?key["\s]*[:=]["\s]*["\']([a-zA-Z0-9_-]{10,})["\']',
                            r'access[_-]?token["\s]*[:=]["\s]*["\']([a-zA-Z0-9_-]{10,})["\']',
                            r'aws[_-]?access[_-]?key["\s]*[:=]["\s]*["\']([A-Z0-9]{20})["\']',
                            r'["\']([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})["\']'  # Internal IPs
                        ]

                        for pattern in leak_patterns:
                            matches = re.findall(pattern, js_content)
                            for match in matches[:2]:  # Limit matches
                                findings['potential_leaks'].append({
                                    'type': 'secret' if 'key' in pattern or 'token' in pattern else 'internal_ip',
                                    'value': match[:15] + '...' if len(match) > 15 else match,
                                    'file': js_file
                                })

                        # Check if CDN hosted
                        if any(cdn in js_file for cdn in ['cdn.', 'cdnjs.', 'unpkg.', 'jsdelivr.']):
                            findings['cdn_assets'].append(js_file)

                except:
                    continue

    except:
        pass

    return findings


def advanced_fingerprint_subdomain(subdomain):
    """Professional-grade HTTP fingerprinting with comprehensive technology detection"""
    result = {
        'subdomain': subdomain,
        'status_code': None,
        'title': None,
        'server': None,
        'technologies': [],
        'security_headers': {},
        'cms': None,
        'framework': None,
        'language': None,
        'risk_level': 'info',
        'risk_factors': [],
        'response_time_ms': None,
        'content_length': None,
        'ssl_info': {},
        'redirect_chain': [],
        'cookies': [],
        'ports_open': [],
        'service_banner': None
    }

    # Professional User-Agent rotation
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ]

    # Test common ports for service detection
    common_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            if sock.connect_ex((subdomain, port)) == 0:
                result['ports_open'].append(port)
            sock.close()
        except:
            continue

    # HTTP/HTTPS probing with advanced detection
    for scheme in ['https', 'http']:
        try:
            url = f"{scheme}://{subdomain}"
            start_time = time.time()

            session = requests.Session()
            session.headers.update({
                'User-Agent': user_agents[0],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })

            response = session.get(url, timeout=10, allow_redirects=True, verify=False)
            response_time = round((time.time() - start_time) * 1000, 2)

            # Basic response info
            result['status_code'] = response.status_code
            result['response_time_ms'] = response_time
            result['content_length'] = len(response.content)
            result['scheme'] = scheme

            # Extract title with better parsing
            title_patterns = [
                r'<title[^>]*>([^<]+)</title>',
                r'<title[^>]*>\s*([^<\n\r]+)\s*</title>',
            ]
            for pattern in title_patterns:
                title_match = re.search(pattern, response.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result['title'] = title_match.group(1).strip()[:150]
                    break

            # Server and security headers analysis
            headers = response.headers
            result['server'] = headers.get('Server', 'Unknown')

            # Security headers assessment
            security_headers = {
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Powered-By': headers.get('X-Powered-By'),
                'Set-Cookie': headers.get('Set-Cookie')
            }
            result['security_headers'] = {k: v for k, v in security_headers.items() if v}

            # Advanced technology detection
            content = response.text.lower()
            headers_str = str(headers).lower()

            # CMS Detection
            cms_signatures = {
                'WordPress': [
                    'wp-content', 'wp-includes', '/wp-json/', 'wordpress',
                    'wp-admin', 'wp-login.php', 'xmlrpc.php'
                ],
                'Drupal': [
                    '/sites/default/', '/modules/', '/themes/', 'drupal',
                    'x-drupal-cache', 'x-generator.*drupal'
                ],
                'Joomla': [
                    '/administrator/', '/components/', '/modules/', 'joomla',
                    '/media/jui/', '/templates/'
                ],
                'Magento': [
                    '/skin/frontend/', '/js/mage/', 'mage/cookies',
                    'var/connect/', '/media/catalog/'
                ],
                'Shopify': [
                    'shopify', 'cdn.shopify.com', 'myshopify.com',
                    'shopify-analytics'
                ]
            }

            for cms, patterns in cms_signatures.items():
                if any(re.search(pattern, content + headers_str) for pattern in patterns):
                    result['cms'] = cms
                    result['technologies'].append(cms)
                    break

            # Framework Detection
            framework_signatures = {
                'React': ['react', '__react', 'react-dom', 'reactjs'],
                'Angular': ['angular', 'ng-version', 'ng-app', '@angular'],
                'Vue.js': ['vue.js', '__vue__', 'vue-router', 'vuejs'],
                'Django': ['django', 'csrftoken', 'djangoproject'],
                'Flask': ['flask', 'werkzeug'],
                'Laravel': ['laravel', 'laravel_session'],
                'Spring': ['spring', 'jsessionid'],
                'Express': ['express', 'x-powered-by.*express'],
                'Next.js': ['next.js', '__next', '_next/'],
                'Nuxt.js': ['nuxt', '__nuxt', '_nuxt/']
            }

            for framework, patterns in framework_signatures.items():
                if any(re.search(pattern, content + headers_str) for pattern in patterns):
                    result['framework'] = framework
                    result['technologies'].append(framework)

            # Language Detection
            language_signatures = {
                'PHP': ['x-powered-by.*php', '.php', 'phpsessid'],
                'ASP.NET': ['x-aspnet-version', 'asp.net', '.aspx'],
                'Java': ['jsessionid', 'java', 'j_security_check'],
                'Python': ['python', 'django', 'flask'],
                'Ruby': ['ruby', 'rails', 'rack'],
                'Node.js': ['node.js', 'express', 'x-powered-by.*express']
            }

            for language, patterns in language_signatures.items():
                if any(re.search(pattern, content + headers_str) for pattern in patterns):
                    result['language'] = language
                    if language not in result['technologies']:
                        result['technologies'].append(language)

            # Advanced risk assessment with detailed reasoning
            result['risk_level'] = 'info'  # Default
            result['risk_factors'] = []
            result['risk_reasoning'] = []

            # Critical risk indicators
            critical_indicators = {
                'phpmyadmin': 'Database administration interface - direct DB access',
                'adminer': 'Database management tool - high privilege access',
                'jenkins': 'CI/CD system - code execution capabilities',
                'gitlab': 'Source code repository - sensitive data exposure',
                'grafana': 'Monitoring dashboard - system information disclosure',
                'kibana': 'Log analysis tool - sensitive log data access',
                'elasticsearch': 'Search engine - data exposure risk',
                'mongodb': 'Database service - direct data access',
                'redis': 'In-memory database - session/cache data exposure',
                'solr': 'Search platform - potential data extraction'
            }

            # High risk indicators
            high_indicators = {
                'admin': 'Administrative interface detected',
                'login': 'Authentication portal - credential attack target',
                'dashboard': 'Control panel interface',
                'panel': 'Management interface',
                'cpanel': 'Web hosting control panel',
                'webmail': 'Email management interface',
                'mail': 'Email service interface',
                'ftp': 'File transfer service',
                'wp-admin': 'WordPress admin panel',
                'administrator': 'Admin access point'
            }

            # Medium risk indicators
            medium_indicators = {
                'staging': 'Staging environment - may contain vulnerabilities',
                'dev': 'Development environment - debug features enabled',
                'test': 'Testing environment - security controls may be relaxed',
                'beta': 'Beta version - potentially unstable/vulnerable',
                'demo': 'Demo environment - default credentials possible',
                'api': 'API endpoint - potential data exposure',
                'swagger': 'API documentation - information disclosure',
                'docs': 'Documentation site - information gathering',
                'internal': 'Internal service - not intended for public access'
            }

            # Low risk indicators
            low_indicators = {
                'www': 'Standard web service',
                'blog': 'Blog/content site',
                'news': 'News/media site',
                'help': 'Help/support documentation',
                'support': 'Customer support portal',
                'about': 'Company information page',
                'contact': 'Contact information page',
                'home': 'Homepage/landing page'
            }

            subdomain_lower = subdomain.lower()
            content_lower = content[:2000].lower()  # Check first 2KB for performance

            # Check for critical risks
            for indicator, reason in critical_indicators.items():
                if indicator in subdomain_lower or indicator in content_lower:
                    result['risk_level'] = 'critical'
                    result['risk_factors'].append(indicator)
                    result['risk_reasoning'].append(f"CRITICAL: {reason}")

            # Check for high risks (if not already critical)
            if result['risk_level'] != 'critical':
                for indicator, reason in high_indicators.items():
                    if indicator in subdomain_lower or indicator in content_lower:
                        result['risk_level'] = 'high'
                        result['risk_factors'].append(indicator)
                        result['risk_reasoning'].append(f"HIGH: {reason}")

            # Check for medium risks (if not already critical/high)
            if result['risk_level'] not in ['critical', 'high']:
                for indicator, reason in medium_indicators.items():
                    if indicator in subdomain_lower or indicator in content_lower:
                        result['risk_level'] = 'medium'
                        result['risk_factors'].append(indicator)
                        result['risk_reasoning'].append(f"MEDIUM: {reason}")

            # Check for low risks (if still info level)
            if result['risk_level'] == 'info':
                for indicator, reason in low_indicators.items():
                    if indicator in subdomain_lower:
                        result['risk_level'] = 'low'
                        result['risk_factors'].append(indicator)
                        result['risk_reasoning'].append(f"LOW: {reason}")

            # Technology-based risk assessment
            if result['cms']:
                if result['cms'] == 'WordPress':
                    if result['risk_level'] in ['info', 'low']:
                        result['risk_level'] = 'medium'
                    result['risk_reasoning'].append(f"MEDIUM: WordPress CMS - common attack target")
                elif result['cms'] in ['Drupal', 'Joomla']:
                    if result['risk_level'] in ['info', 'low']:
                        result['risk_level'] = 'medium'
                    result['risk_reasoning'].append(f"MEDIUM: {result['cms']} CMS - requires security monitoring")

            # Security headers assessment
            security_issues = []
            if not result['security_headers'].get('X-Frame-Options'):
                security_issues.append("Missing X-Frame-Options (clickjacking risk)")
            if not result['security_headers'].get('X-Content-Type-Options'):
                security_issues.append("Missing X-Content-Type-Options (MIME sniffing risk)")
            if not result['security_headers'].get('Strict-Transport-Security') and scheme == 'https':
                security_issues.append("Missing HSTS header (downgrade attack risk)")
            if scheme == 'http' and 443 in result['ports_open']:
                security_issues.append("HTTP available when HTTPS supported (insecure transmission)")

            if security_issues:
                result['risk_reasoning'].extend([f"SECURITY: {issue}" for issue in security_issues])
                # Elevate risk if security issues found
                if result['risk_level'] == 'info':
                    result['risk_level'] = 'low'

            # SSL/TLS information for HTTPS
            if scheme == 'https':
                try:
                    import ssl
                    context = ssl.create_default_context()
                    with socket.create_connection((subdomain, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                            cert = ssock.getpeercert()
                            result['ssl_info'] = {
                                'subject': dict(x[0] for x in cert['subject']),
                                'issuer': dict(x[0] for x in cert['issuer']),
                                'version': cert['version'],
                                'serial_number': cert['serialNumber'],
                                'not_before': cert['notBefore'],
                                'not_after': cert['notAfter']
                            }
                except:
                    pass

            # Perform additional web analysis if HTTP 200
            if result['status_code'] == 200:
                # Analyze robots.txt and sitemap.xml
                robots_sitemap = analyze_robots_and_sitemap(subdomain, scheme)
                result['robots_analysis'] = robots_sitemap

                # Crawl for sensitive files
                sensitive_files = crawl_for_sensitive_files(subdomain, scheme)
                result['sensitive_files'] = sensitive_files

                # Analyze JS/CSS assets
                js_css_analysis = analyze_js_css_assets(subdomain, scheme)
                result['js_css_analysis'] = js_css_analysis

                # Update risk based on findings
                if sensitive_files['sensitive_files']:
                    if result['risk_level'] not in ['critical', 'high']:
                        result['risk_level'] = 'high'
                    result['risk_reasoning'].append(f"HIGH: Sensitive files exposed ({len(sensitive_files['sensitive_files'])} files)")

                if sensitive_files['potential_secrets']:
                    result['risk_level'] = 'critical'
                    result['risk_reasoning'].append(f"CRITICAL: Potential secrets/credentials exposed")

                if js_css_analysis['potential_leaks']:
                    if result['risk_level'] not in ['critical']:
                        result['risk_level'] = 'high'
                    result['risk_reasoning'].append(f"HIGH: Potential data leaks in JavaScript assets")

            # Success - break out of scheme loop
            break

        except requests.RequestException as e:
            if scheme == 'http':
                result['error'] = str(e)
            continue
        except Exception as e:
            result['error'] = f"Fingerprinting error: {str(e)}"
            continue

    return result


def get_cve_data_for_technology(technology, version=None):
    """Get CVE data for detected technologies"""
    cve_database = {
        'WordPress': [
            {'cve': 'CVE-2023-2745', 'severity': 'HIGH', 'description': 'SQL injection vulnerability'},
            {'cve': 'CVE-2023-1698', 'severity': 'CRITICAL', 'description': 'Remote code execution'},
            {'cve': 'CVE-2022-43497', 'severity': 'MEDIUM', 'description': 'Cross-site scripting'}
        ],
        'Drupal': [
            {'cve': 'CVE-2023-6134', 'severity': 'HIGH', 'description': 'Access bypass vulnerability'},
            {'cve': 'CVE-2023-3824', 'severity': 'CRITICAL', 'description': 'Remote code execution'},
            {'cve': 'CVE-2022-25277', 'severity': 'MEDIUM', 'description': 'Information disclosure'}
        ],
        'Joomla': [
            {'cve': 'CVE-2023-23752', 'severity': 'CRITICAL', 'description': 'Information disclosure'},
            {'cve': 'CVE-2023-40623', 'severity': 'HIGH', 'description': 'SQL injection'},
            {'cve': 'CVE-2022-23793', 'severity': 'MEDIUM', 'description': 'Cross-site scripting'}
        ],
        'Apache': [
            {'cve': 'CVE-2023-45802', 'severity': 'HIGH', 'description': 'HTTP request smuggling'},
            {'cve': 'CVE-2023-27522', 'severity': 'MEDIUM', 'description': 'Information disclosure'},
            {'cve': 'CVE-2022-37436', 'severity': 'HIGH', 'description': 'Path traversal'}
        ],
        'Nginx': [
            {'cve': 'CVE-2023-44487', 'severity': 'HIGH', 'description': 'HTTP/2 rapid reset attack'},
            {'cve': 'CVE-2022-41741', 'severity': 'MEDIUM', 'description': 'Memory disclosure'},
            {'cve': 'CVE-2021-23017', 'severity': 'HIGH', 'description': 'DNS resolver vulnerability'}
        ],
        'PHP': [
            {'cve': 'CVE-2023-3823', 'severity': 'HIGH', 'description': 'XML external entity injection'},
            {'cve': 'CVE-2023-0662', 'severity': 'MEDIUM', 'description': 'DoS via hash collision'},
            {'cve': 'CVE-2022-31630', 'severity': 'HIGH', 'description': 'Buffer overflow'}
        ],
        'React': [
            {'cve': 'CVE-2023-26116', 'severity': 'MEDIUM', 'description': 'XSS in development mode'},
            {'cve': 'CVE-2022-24999', 'severity': 'LOW', 'description': 'Prototype pollution'},
            {'cve': 'CVE-2021-44906', 'severity': 'MEDIUM', 'description': 'Minimist prototype pollution'}
        ],
        'Angular': [
            {'cve': 'CVE-2023-26118', 'severity': 'MEDIUM', 'description': 'Regular expression DoS'},
            {'cve': 'CVE-2022-25844', 'severity': 'HIGH', 'description': 'Angular expression injection'},
            {'cve': 'CVE-2021-44906', 'severity': 'MEDIUM', 'description': 'Dependency vulnerability'}
        ],
        'jQuery': [
            {'cve': 'CVE-2020-11023', 'severity': 'MEDIUM', 'description': 'XSS via HTML manipulation'},
            {'cve': 'CVE-2020-11022', 'severity': 'MEDIUM', 'description': 'XSS in htmlPrefilter'},
            {'cve': 'CVE-2019-11358', 'severity': 'MEDIUM', 'description': 'Prototype pollution'}
        ]
    }

    return cve_database.get(technology, [])


def correlate_cves_with_technologies(technologies):
    """Correlate detected technologies with known CVEs"""
    cve_findings = []

    for tech in technologies:
        cves = get_cve_data_for_technology(tech)
        if cves:
            # Get top 3 most severe CVEs
            sorted_cves = sorted(cves, key=lambda x: {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x['severity'], 0), reverse=True)
            for cve in sorted_cves[:3]:
                cve_findings.append({
                    'technology': tech,
                    'cve_id': cve['cve'],
                    'severity': cve['severity'],
                    'description': cve['description']
                })

    return cve_findings


def save_results(results, domain, output_dir='output'):
    """Save results to multiple formats"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print_info(f"Created output directory: {output_dir}")

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_filename = f"{domain}_{timestamp}"

    # JSON output (detailed)
    json_file = os.path.join(output_dir, f"{base_filename}.json")
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump({
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'total_subdomains': len(results),
            'results': results
        }, f, indent=2, ensure_ascii=False)

    # TXT output (human readable)
    txt_file = os.path.join(output_dir, f"{base_filename}.txt")
    with open(txt_file, 'w', encoding='utf-8') as f:
        f.write(f"DeepDomain v2.0 - Subdomain Enumeration Results\n")
        f.write(f"Domain: {domain}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Subdomains Found: {len(results)}\n")
        f.write("=" * 60 + "\n\n")

        # Group by risk level
        high_risk = [r for r in results if r.get('risk') == 'high']
        medium_risk = [r for r in results if r.get('risk') == 'medium']
        low_risk = [r for r in results if r.get('risk') == 'low']

        if high_risk:
            f.write(f"🔴 HIGH RISK SUBDOMAINS ({len(high_risk)}):\n")
            f.write("-" * 40 + "\n")
            for result in high_risk:
                f.write(f"  {result['subdomain']}\n")
                if 'ip' in result:
                    f.write(f"    IP: {result['ip']}\n")
                if 'status' in result and result['status']:
                    f.write(f"    HTTP Status: {result['status']}\n")
                if 'title' in result and result['title']:
                    f.write(f"    Title: {result['title']}\n")
                if 'technologies' in result and result['technologies']:
                    f.write(f"    Technologies: {', '.join(result['technologies'])}\n")
                f.write(f"    Source: {result['source']}\n\n")

        if medium_risk:
            f.write(f"🟡 MEDIUM RISK SUBDOMAINS ({len(medium_risk)}):\n")
            f.write("-" * 40 + "\n")
            for result in medium_risk:
                f.write(f"  {result['subdomain']}\n")
                if 'ip' in result:
                    f.write(f"    IP: {result['ip']}\n")
                if 'status' in result and result['status']:
                    f.write(f"    HTTP Status: {result['status']}\n")
                f.write(f"    Source: {result['source']}\n\n")

        if low_risk:
            f.write(f"🟢 LOW RISK SUBDOMAINS ({len(low_risk)}):\n")
            f.write("-" * 40 + "\n")
            for result in low_risk:
                f.write(f"  {result['subdomain']}")
                if 'ip' in result:
                    f.write(f" -> {result['ip']}")
                f.write(f" ({result['source']})\n")

    # CSV output (for spreadsheet analysis)
    csv_file = os.path.join(output_dir, f"{base_filename}.csv")
    with open(csv_file, 'w', encoding='utf-8') as f:
        f.write("Subdomain,IP,Status,Title,Server,Risk,Technologies,Source,Response_Time\n")
        for result in results:
            subdomain = result.get('subdomain', '')
            ip = result.get('ip', '')
            status = result.get('status', '')
            title = (result.get('title') or '').replace(',', ';').replace('\n', ' ')
            server = result.get('server', '')
            risk = result.get('risk', '')
            technologies = ';'.join(result.get('technologies', []))
            source = result.get('source', '')
            response_time = result.get('response_time', '')

            f.write(f'"{subdomain}","{ip}","{status}","{title}","{server}","{risk}","{technologies}","{source}","{response_time}"\n')

    # Simple list output (just subdomains)
    list_file = os.path.join(output_dir, f"{base_filename}_list.txt")
    with open(list_file, 'w', encoding='utf-8') as f:
        for result in sorted(results, key=lambda x: x['subdomain']):
            f.write(f"{result['subdomain']}\n")

    print_success(f"Results saved to:")
    print(f"  📄 Detailed report: {txt_file}")
    print(f"  📊 JSON data: {json_file}")
    print(f"  📈 CSV data: {csv_file}")
    print(f"  📝 Simple list: {list_file}")

    return {
        'json': json_file,
        'txt': txt_file,
        'csv': csv_file,
        'list': list_file
    }

def create_parser():
    """Create simple, user-friendly argument parser"""

    description = f"""
{Colors.BOLD}DeepDomain v{__version__} - Advanced Subdomain Enumeration Tool{Colors.END}

{Colors.BOLD}QUICK START:{Colors.END}
  python deepdomain.py example.com              # Basic scan
  python deepdomain.py example.com --fast       # Fast scan
  python deepdomain.py example.com --deep       # Deep scan
  python deepdomain.py example.com --no-save    # Don't save results

{Colors.BOLD}Created by:{Colors.END} {__author__}
{Colors.BOLD}GitHub:{Colors.END} {__github__}
{Colors.BOLD}License:{Colors.END} {__license__}
    """

    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Required
    parser.add_argument('domain', help='Target domain (e.g., example.com)')

    # Simple scan modes
    parser.add_argument('--fast', action='store_true',
                       help='Fast scan (DNS only, 22 prefixes)')
    parser.add_argument('--deep', action='store_true',
                       help='Deep scan (all techniques, 252+ prefixes)')

    # Simple options
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('--no-save', action='store_true',
                       help='Don\'t save results to files')
    parser.add_argument('-o', '--output', default='output',
                       help='Output directory (default: output)')
    parser.add_argument('--version', action='version',
                       version=f'DeepDomain v{__version__} by {__author__}')

    # Advanced options (hidden in simple help)
    parser.add_argument('--live-only', action='store_true',
                       help=argparse.SUPPRESS)  # Hidden
    parser.add_argument('--api-key', help=argparse.SUPPRESS)  # Hidden
    parser.add_argument('-w', '--wordlist', help=argparse.SUPPRESS)  # Hidden

    return parser

def main():
    # Print banner
    print_banner()

    # Parse arguments
    parser = create_parser()
    args = parser.parse_args()

    # Validate domain
    if not validate_domain(args.domain):
        print_error(f"Invalid domain format: {args.domain}")
        print_info("Please provide a valid domain (e.g., example.com)")
        sys.exit(1)

    # Set scan mode based on simple arguments
    if args.fast:
        # Fast mode: DNS only, fast generation
        use_dns = True
        use_crtsh = False
        use_api = False
        use_fingerprint = False
        generation_mode = 'fast'
    elif args.deep:
        # Deep mode: All techniques, comprehensive generation
        use_dns = True
        use_crtsh = True
        use_api = True
        use_fingerprint = True
        generation_mode = 'comprehensive'
    else:
        # Default mode: DNS + API, comprehensive generation
        use_dns = True
        use_crtsh = True
        use_api = True
        use_fingerprint = False
        generation_mode = 'comprehensive'

    domain = args.domain
    all_results = []
    start_time = time.time()

    # Show scan mode
    mode_text = "Fast scan" if args.fast else "Deep scan" if args.deep else "Standard scan"
    print_info(f"{mode_text} for {Colors.BOLD}{domain}{Colors.END}")

    # DNS brute forcing with dynamic generation
    if use_dns:
        print(f"\n{Colors.CYAN}{'='*50}{Colors.END}")
        validation_mode = "LIVE VALIDATION" if args.live_only else "DNS ENUMERATION"
        print(f"{Colors.CYAN}{Colors.BOLD}🔍 {validation_mode}{Colors.END}")
        print(f"{Colors.CYAN}{'='*50}{Colors.END}")

        # Use custom wordlist if provided, otherwise use dynamic generation
        wordlist_path = args.wordlist if hasattr(args, 'wordlist') and args.wordlist else None
        dns_results = dns_bruteforce(domain, wordlist_path, args.threads, args.live_only, generation_mode)
        all_results.extend(dns_results)
        result_type = "live subdomains" if args.live_only else "subdomains"
        print_info(f"Found {len(dns_results)} {result_type}")

    # Certificate transparency
    if use_crtsh:
        print(f"\n{Colors.MAGENTA}{'='*50}{Colors.END}")
        print(f"{Colors.MAGENTA}{Colors.BOLD}📜 CERTIFICATE LOGS{Colors.END}")
        print(f"{Colors.MAGENTA}{'='*50}{Colors.END}")
        crtsh_results = query_crtsh(domain)
        all_results.extend(crtsh_results)
        print_info(f"Found {len(crtsh_results)} subdomains")

    # Passive Intelligence Sources
    if use_api:
        print(f"\n{Colors.YELLOW}{'='*50}{Colors.END}")
        print(f"{Colors.YELLOW}{Colors.BOLD}🌐 PASSIVE INTELLIGENCE{Colors.END}")
        print(f"{Colors.YELLOW}{'='*50}{Colors.END}")

        # OTX API
        otx_results = query_otx_api(domain, args.api_key)
        all_results.extend(otx_results)

        # Wayback Machine
        wayback_results = query_wayback_machine(domain)
        all_results.extend(wayback_results)

        # Anubis Database
        anubis_results = query_anubis_db(domain)
        all_results.extend(anubis_results)

        # HackerTarget API
        hackertarget_results = query_hackertarget_api(domain)
        all_results.extend(hackertarget_results)

        total_passive = len(otx_results) + len(wayback_results) + len(anubis_results) + len(hackertarget_results)
        print_info(f"Found {total_passive} subdomains from passive intelligence sources")

    # Remove duplicates and merge sources
    print_info("Removing duplicates and merging sources...")
    unique_subdomains = {}
    for result in all_results:
        subdomain = result['subdomain']
        if subdomain not in unique_subdomains:
            unique_subdomains[subdomain] = result
        else:
            # Merge sources
            existing = unique_subdomains[subdomain]
            if 'source' in existing and 'source' in result:
                sources = existing['source'].split(',') if ',' in existing['source'] else [existing['source']]
                if result['source'] not in sources:
                    sources.append(result['source'])
                    existing['source'] = ','.join(sources)
            # Preserve IP if available
            if 'ip' in result and 'ip' not in existing:
                existing['ip'] = result['ip']

    final_results = list(unique_subdomains.values())
    print_info(f"Found {len(final_results)} unique subdomains after deduplication")

    # HTTP fingerprinting
    if use_fingerprint and final_results:
        print(f"\n{Colors.GREEN}{'='*50}{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}🔍 HTTP FINGERPRINTING{Colors.END}")
        print(f"{Colors.GREEN}{'='*50}{Colors.END}")
        print_info(f"Checking {len(final_results)} subdomains...")

        fingerprinted = []

        try:
            from tqdm import tqdm
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(advanced_fingerprint_subdomain, result['subdomain']): result for result in final_results}

                with tqdm(total=len(final_results), desc="Fingerprinting", unit="domains") as pbar:
                    for future in concurrent.futures.as_completed(futures):
                        original_result = futures[future]
                        fingerprint_result = future.result()

                        # Merge results
                        merged = {**original_result, **fingerprint_result}
                        fingerprinted.append(merged)
                        pbar.update(1)
        except ImportError:
            # Fallback without progress bar
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(advanced_fingerprint_subdomain, result['subdomain']): result for result in final_results}

                for future in concurrent.futures.as_completed(futures):
                    original_result = futures[future]
                    fingerprint_result = future.result()

                    # Merge results
                    merged = {**original_result, **fingerprint_result}
                    fingerprinted.append(merged)

        final_results = fingerprinted

    # Calculate execution time
    execution_time = time.time() - start_time

    # Display professional results
    display_professional_results(final_results, execution_time)

    # Handle saving results
    if final_results:
        if args.no_save:
            print_info("Results not saved (--no-save specified)")
        else:
            # Default behavior: save results
            print(f"\n{Colors.BOLD}💾 SAVING RESULTS{Colors.END}")
            save_results(final_results, domain, args.output)

        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ Enumeration completed successfully!{Colors.END}")
    else:
        print_warning("No subdomains found. Try:")
        print_info("• Using a different wordlist with --wordlist")
        print_info("• Checking if the domain is valid and accessible")
        print_info("• Using an API key with --api-key for better results")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!]{Colors.END} Enumeration interrupted by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)
