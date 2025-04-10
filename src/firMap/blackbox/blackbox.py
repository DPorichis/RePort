from engines import *
from scan import *
import subprocess

def run_nmap(target, options=''):
    command = ['nmap'] + options.split() + [target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}"

# Example usage
if __name__ == "__main__":
    engine = NmapEngine()
    target_ip = "8.8.8.8"
    print(engine.help())
    output = engine.scan(IP=target_ip)
    print(output)