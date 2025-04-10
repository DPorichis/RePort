from blackbox.engines import *
from blackbox.scan import *
import subprocess

# Example usage
def blackbox_scan(target_ip="8.8.8.8"):
    engine = NmapEngine()
    # print(engine.help())
    output = engine.scan(ip=target_ip)
    print(output)