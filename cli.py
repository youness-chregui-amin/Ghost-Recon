import os
import sys
from branding import print_logo, print_mode_menu
from utils import setup_logger, ctext
from data_sources import virustotal, wayback, github, shodan, censys, dnsdb, crtsh, dnsdumpster, viewdns, hunterio, threatfox, amass, subfinder, dns_bruteforce, sublist3r
from analyzers import js_analyzer, github_analyzer
from ai_engine import predict_subdomains, classify_subdomain, extract_secrets_from_text
from storage import save_encrypted_json
import logging
from attack_mode import run_attack_mode
import time
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.text import Text


def get_api_key(env_var, prompt_name):
    key = os.environ.get(env_var)
    if not key:
        try:
            key = input(f"Enter {prompt_name} API key: ")
        except KeyboardInterrupt:
            print("\n[!] Aborted.")
            exit(1)
    return key


def print_feature_menu(features, title="Feature Selection"):
    """Print a numbered menu of features with selection status"""
    console = Console()
    print(f"\n{ctext(title, 'cyan')}")
    print(ctext("=" * 50, 'cyan'))
    
    for i, (name, desc, enabled) in enumerate(features, 1):
        status = ctext("✓", 'green') if enabled else ctext("✗", 'red')
        print(f"{ctext(f'[{i}]', 'yellow')} {name:<20} {status}  {ctext(desc, 'white')}")
    
    print(ctext("=" * 50, 'cyan'))
    print(ctext("Enter numbers separated by commas (e.g., 1,3,5) or 'all' for everything", 'magenta'))
    print(ctext("Press Enter to continue with current selection", 'magenta'))


def get_user_selection(features, prompt_text="Select features"):
    """Get user selection for features"""
    while True:
        try:
            selection = input(f"\n{prompt_text}: ").strip().lower()
            
            if not selection:  # User pressed Enter, continue with current selection
                return
            
            if selection == 'all':
                for i in range(len(features)):
                    features[i] = (features[i][0], features[i][1], True)
                print(ctext("✓ All features enabled", 'green'))
                return
            
            # Parse comma-separated numbers
            selected_indices = [int(x.strip()) - 1 for x in selection.split(',')]
            
            # Validate indices
            for idx in selected_indices:
                if idx < 0 or idx >= len(features):
                    print(ctext(f"Invalid selection: {idx + 1}", 'red'))
                    continue
            
            # Toggle selected features
            for idx in selected_indices:
                name, desc, enabled = features[idx]
                features[idx] = (name, desc, not enabled)
                status = "enabled" if not enabled else "disabled"
                print(ctext(f"✓ {name} {status}", 'green'))
            
            # Show updated menu
            print_feature_menu(features)
            
        except ValueError:
            print(ctext("Invalid input. Please enter numbers separated by commas.", 'red'))
        except KeyboardInterrupt:
            print("\n[!] Aborted.")
            exit(1)


def osint_feature_menu():
    """Interactive OSINT feature selection menu"""
    features = [
        ("crt.sh Subdomains", "Certificate transparency subdomains", True),
        ("Sublist3r", "Subdomain enumeration via Sublist3r", True),
        ("Subfinder", "Subdomain enumeration via Subfinder", False),
        ("Amass (Passive)", "Subdomain enumeration via Amass (passive mode)", False),
        ("DNS Brute-force", "Brute-force subdomains using DNS (dnspython)", False),
        ("VirusTotal", "VirusTotal subdomain enumeration", False),
        ("Wayback Machine", "Archived JavaScript analysis", True),
        ("DNSDumpster", "DNS records and subdomains", True),
        ("ViewDNS.info", "Whois and reverse IP lookup", True),
        ("Hunter.io", "Email address discovery", True),
        ("ThreatFox", "Malware indicators", True),
        ("AI Analysis", "AI-powered subdomain prediction", False),
        ("GitHub Recon", "GitHub repository scanning", False),
        ("Shodan", "Internet-wide device search", False),
        ("Censys", "Network infrastructure data", False)
    ]
    
    print_feature_menu(features, "OSINT Mode - Feature Selection")
    get_user_selection(features, "Select OSINT features")
    return features


def attack_feature_menu():
    """Interactive Attack Mode feature selection menu"""
    features = [
        ("Endpoint Probing", "Probe common sensitive endpoints", True),
        ("Proxy Rotation", "Rotate through proxy list", False),
        ("Cookie Injection", "Inject custom cookies", False),
        ("Header Injection", "Inject custom headers", False),
        ("Session Export", "Export full session data", False),
        ("Stealth Mode", "Random delays and user agents", True),
        ("Error Analysis", "Analyze error responses", True),
        ("Secret Detection", "Extract secrets from responses", True),
        ("JavaScript Analysis", "Analyze JS files for secrets", True)
    ]
    
    print_feature_menu(features, "Attack Mode - Feature Selection")
    get_user_selection(features, "Select Attack features")
    return features


def get_scan_config(mode):
    """Get scan configuration from user"""
    console = Console()
    
    print(ctext(f"\n{'='*60}", 'cyan'))
    print(ctext(f"GhostRecon {mode.upper()} Mode Configuration", 'cyan'))
    print(ctext(f"{'='*60}", 'cyan'))
    
    # Get target domain
    while True:
        domain = input(f"\n{ctext('Target domain', 'yellow')} (e.g., example.com): ").strip()
        if domain and '.' in domain:
            break
        print(ctext("Please enter a valid domain name.", 'red'))
    
    # Get output file
    output_file = input(f"{ctext('Output file', 'yellow')} (default: results.json): ").strip()
    if not output_file:
        output_file = "results.json"
    
    # Get password
    password = os.environ.get('GHOSTRECON_PASSWORD')
    if not password:
        password = input(f"{ctext('Encryption password', 'yellow')}: ").strip()
        if not password:
            print(ctext("Password is required for encrypted storage.", 'red'))
            exit(1)
    
    # OSINT Mode: DNS Brute-force wordlist
    dns_wordlist = None
    if mode == "OSINT":
        print(ctext("\n[DNS Brute-force] You can provide a custom wordlist file (one subdomain per line). Leave blank to use the default list.", 'cyan'))
        wordlist_path = input(f"{ctext('DNS Brute-force wordlist file', 'yellow')} (optional): ").strip()
        if wordlist_path:
            try:
                with open(wordlist_path, 'r') as f:
                    dns_wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except Exception as e:
                print(ctext(f"[!] Could not read wordlist: {e}", 'red'))
                dns_wordlist = None
    
    # Additional Attack Mode options
    attack_options = {}
    if mode == "Attack":
        print(ctext("\nAttack Mode Options:", 'red'))
        
        proxy = input(f"{ctext('Proxy URL', 'yellow')} (optional, e.g., http://127.0.0.1:8080): ").strip()
        if proxy:
            attack_options['proxy'] = proxy
        
        proxy_list = input(f"{ctext('Proxy list file', 'yellow')} (optional): ").strip()
        if proxy_list:
            attack_options['proxy_list'] = proxy_list
        
        cookies = input(f"{ctext('Cookies', 'yellow')} (optional, e.g., name=value; foo=bar): ").strip()
        if cookies:
            attack_options['cookie'] = cookies
        
        cookie_file = input(f"{ctext('Cookie file', 'yellow')} (optional): ").strip()
        if cookie_file:
            attack_options['cookie_file'] = cookie_file
        
        headers = input(f"{ctext('Headers', 'yellow')} (optional, e.g., X-Forwarded-For: 1.2.3.4): ").strip()
        if headers:
            attack_options['header'] = [headers]
        
        header_file = input(f"{ctext('Header file', 'yellow')} (optional): ").strip()
        if header_file:
            attack_options['header_file'] = header_file
        
        save_session = input(f"{ctext('Save session to file', 'yellow')} (optional): ").strip()
        if save_session:
            attack_options['save_session'] = save_session
    
    config = {
        'domain': domain,
        'output': output_file,
        'password': password,
        **attack_options
    }
    if mode == "OSINT":
        config['dns_wordlist'] = dns_wordlist
    return config


def osint_mode_interactive(config, features):
    """Run OSINT mode with selected features"""
    console = Console()
    domain = config['domain']
    output_file = config['output']
    password = config['password']
    
    # Check which features are enabled
    enabled_features = [f[0] for f in features if f[2]]
    
    logging.info(ctext(f"Target: {domain}", 'green'))
    logging.info(ctext(f"Enabled features: {', '.join(enabled_features)}", 'yellow'))
    logging.info(ctext(f"Output File: {output_file}", 'cyan'))
    
    results = {
        'domain': domain, 
        'subdomains': set(), 
        'endpoints': set(), 
        'urls': set(), 
        'secrets': set(), 
        'ips': set(), 
        'emails': set(), 
        'whois': {}, 
        'reverse_ip': [], 
        'malware_indicators': []
    }
    
    start_time = time.time()
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        # crt.sh
        if "crt.sh Subdomains" in enabled_features:
            task1 = progress.add_task("[cyan]Fetching subdomains from crt.sh...", total=None)
            crtsh_subs = crtsh.get_subdomains(domain)
            results['subdomains'].update(crtsh_subs)
            progress.update(task1, completed=1)
        # Sublist3r
        if "Sublist3r" in enabled_features:
            task_sub = progress.add_task("[green]Enumerating subdomains with Sublist3r...", total=None)
            try:
                sublist3r_subs = sublist3r.get_subdomains(domain)
                results['subdomains'].update(sublist3r_subs)
            except Exception as e:
                logging.warning(f"[Sublist3r] Error: {e}")
            progress.update(task_sub, completed=1)
        # Subfinder
        if "Subfinder" in enabled_features:
            task_sf = progress.add_task("[blue]Enumerating subdomains with Subfinder...", total=None)
            try:
                subfinder_subs = subfinder.get_subdomains(domain)
                results['subdomains'].update(subfinder_subs)
            except Exception as e:
                logging.warning(f"[Subfinder] Error: {e}")
            progress.update(task_sf, completed=1)
        # Amass (Passive)
        if "Amass (Passive)" in enabled_features:
            task_amass = progress.add_task("[magenta]Enumerating subdomains with Amass (passive)...", total=None)
            try:
                amass_subs = amass.get_subdomains(domain)
                results['subdomains'].update(amass_subs)
            except Exception as e:
                logging.warning(f"[Amass] Error: {e}")
            progress.update(task_amass, completed=1)
        # DNS Brute-force
        if "DNS Brute-force" in enabled_features:
            task_dns = progress.add_task("[yellow]Brute-forcing DNS for subdomains...", total=None)
            try:
                dns_wordlist = config.get('dns_wordlist')
                if dns_wordlist:
                    dns_brute_subs = dns_bruteforce.get_subdomains(domain, wordlist=dns_wordlist)
                else:
                    dns_brute_subs = dns_bruteforce.get_subdomains(domain)
                results['subdomains'].update(dns_brute_subs)
            except Exception as e:
                logging.warning(f"[DNS Brute-force] Error: {e}")
            progress.update(task_dns, completed=1)
        # VirusTotal
        if "VirusTotal" in enabled_features:
            task_vt = progress.add_task("[blue]Fetching subdomains from VirusTotal...", total=None)
            try:
                vt_subs = virustotal.get_subdomains(domain)
                results['subdomains'].update(vt_subs)
            except Exception as e:
                logging.warning(f"[VirusTotal] Error: {e}")
            progress.update(task_vt, completed=1)
        # Wayback Machine
        if "Wayback Machine" in enabled_features:
            task2 = progress.add_task("[magenta]Fetching archived JS from Wayback...", total=None)
            wb_urls = wayback.get_archived_urls(domain) or []
            js_files = [u for u in wb_urls if u.endswith('.js')]
            endpoints, urls, secrets = set(), set(), set()
            for js_url in js_files[:10]:
                try:
                    import requests
                    resp = requests.get(js_url, timeout=10)
                    if resp.status_code == 200:
                        analysis = js_analyzer.analyze_js(resp.text)
                        endpoints.update(analysis['endpoints'])
                        urls.update(analysis['urls'])
                        secrets.update(analysis['secrets'])
                except Exception as e:
                    logging.warning(f"[Wayback JS] Error fetching {js_url}: {e}")
            results['endpoints'].update(endpoints)
            results['urls'].update(urls)
            results['secrets'].update(secrets)
            progress.update(task2, completed=1)
        
        # DNSDumpster
        if "DNSDumpster" in enabled_features:
            task3 = progress.add_task("[yellow]Scraping DNSDumpster...", total=None)
            dd_subs, dd_ips = dnsdumpster.get_dnsdumpster_data(domain)
            results['subdomains'].update(dd_subs)
            results['ips'].update(dd_ips)
            progress.update(task3, completed=1)
        
        # ViewDNS.info
        if "ViewDNS.info" in enabled_features:
            task4 = progress.add_task("[green]Scraping ViewDNS.info (Whois/Reverse IP)...", total=None)
            results['whois'] = viewdns.get_whois(domain)
            results['reverse_ip'] = viewdns.get_reverse_ip(domain)
            progress.update(task4, completed=1)
        
        # Hunter.io
        if "Hunter.io" in enabled_features:
            task5 = progress.add_task("[blue]Scraping Hunter.io for emails...", total=None)
            results['emails'].update(hunterio.get_emails(domain))
            progress.update(task5, completed=1)
        
        # ThreatFox
        if "ThreatFox" in enabled_features:
            task6 = progress.add_task("[red]Fetching ThreatFox indicators...", total=None)
            results['malware_indicators'] = threatfox.get_indicators()
            progress.update(task6, completed=1)
    
    # AI Engine (optional)
    if "AI Analysis" in enabled_features:
        ai_pred = predict_subdomains(results['subdomains'], domain)
        if ai_pred:
            results['subdomains'].update(ai_pred)
        # Extract secrets from all text
        all_text = '\n'.join(list(results['endpoints']) + list(results['urls']))
        results['secrets'].update(extract_secrets_from_text(all_text))
    
    # Convert sets to lists for JSON
    for k in results:
        if isinstance(results[k], set):
            results[k] = list(results[k])
    
    # Save encrypted
    try:
        save_encrypted_json(results, output_file, password)
        logging.info(ctext(f"Results saved to {output_file} (encrypted)", 'green'))
    except Exception as e:
        logging.error(ctext(f"[!] Error saving results: {e}", 'red'))
    
    # Print beautiful summary table
    elapsed = time.time() - start_time
    table = Table(title=f"GhostRecon OSINT Results for {domain}", show_lines=True, style="bold cyan")
    table.add_column("Category", style="bold magenta")
    table.add_column("Findings", style="bold green")
    table.add_row("Subdomains", str(len(results['subdomains'])))
    table.add_row("Endpoints", str(len(results['endpoints'])))
    table.add_row("URLs", str(len(results['urls'])))
    table.add_row("IPs", str(len(results['ips'])))
    table.add_row("Emails", str(len(results['emails'])))
    table.add_row("Secrets", str(len(results['secrets'])))
    table.add_row("Malware Indicators", str(len(results['malware_indicators'])))
    table.add_row("Whois Info", "Yes" if results['whois'] else "No")
    table.add_row("Reverse IP Domains", str(len(results['reverse_ip'])))
    console.print(table)
    console.print(f"[bold green]Results exported to: {output_file}")
    console.print(f"[bold yellow]Total time: {elapsed:.1f} seconds")


def main():
    setup_logger()
    console = Console()
    
    while True:
        print_logo()
        print_mode_menu()
        mode = input("Select mode: ").strip() or "1"
        
        if mode == "1":  # OSINT Mode
            print(ctext("\n[OSINT Mode] Starting passive reconnaissance...", 'cyan'))
            features = osint_feature_menu()
            config = get_scan_config("OSINT")
            osint_mode_interactive(config, features)
            
        elif mode == "2":  # Attack Mode
            print(ctext("\n[Attack Mode] Starting stealth reconnaissance...", 'red'))
            features = attack_feature_menu()
            config = get_scan_config("Attack")
            
            # Create a mock args object for attack_mode compatibility
            class MockArgs:
                def __init__(self, config):
                    for key, value in config.items():
                        setattr(self, key, value)
            
            args = MockArgs(config)
            run_attack_mode(args)
            
        else:
            print(ctext("Invalid selection. Please choose 1 or 2.", 'red'))
            continue
        
        # Ask if user wants to run another scan
        try:
            if Confirm.ask("\nRun another scan?", default=False):
                continue
            else:
                print(ctext("\nThank you for using GhostRecon! 👻", 'green'))
                break
        except:
            # Fallback if rich.prompt is not available
            another = input("\nRun another scan? (y/N): ").strip().lower()
            if another in ['y', 'yes']:
                continue
            else:
                print(ctext("\nThank you for using GhostRecon! 👻", 'green'))
                break


if __name__ == '__main__':
    import requests
    main() 