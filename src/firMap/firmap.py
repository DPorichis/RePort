import argparse
from blackbox.blackbox import blackbox_scan

def main():
    parser = argparse.ArgumentParser(description="Nmap scan with options")
    
    parser.add_argument('-black', action='store_true', help="Flag to run black scan")
    parser.add_argument('ip', type=str, help="Target IP to scan")

    args = parser.parse_args()

    if args.black:
        blackbox_scan(args.ip)
    
if __name__ == "__main__":
    main()