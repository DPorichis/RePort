import os
import re
import sys
import subprocess
import hashlib
from firMap.utils import Logger

log = Logger("Graybox Monitor")
class GrayBoxScan:
    def __init__(self, firmware='', fs='', ip_address=None, brand='unknown'):
        self.black_verification = None
        self.ip_address = ip_address
        self.firware_path = firmware
        self.filesystem_path = fs
        self.brand = brand
        self.md5_hash = self.io_md5(self.firware_path)

        self.logs = ""
        self.bind_calls = []
        self.critical_processes = {}
        self.ports = {}

    def io_md5(self, target):
        """
        Performs MD5 with a block size of 64kb.
        """
        blocksize = 65536
        hasher = hashlib.md5()

        with open(target, 'rb') as ifp:
            buf = ifp.read(blocksize)
            while buf:
                hasher.update(buf)
                buf = ifp.read(blocksize)
            return hasher.hexdigest()


class CriticalBinary:
    def compute_sha256(self):
        try:
            with open(self.path, 'rb') as f:
                sha256 = hashlib.sha256()
                while chunk := f.read(8192):
                    sha256.update(chunk)
                return sha256.hexdigest()
        except FileNotFoundError:
            log.message("error", f"File \"{self.path}\" was not found, SHA will not be calculated", "binary profiler")
            return 'BNF'
        except Exception as e:
            log.message("warn", "An exception occured, SHA will not be calculated (Exception: {e})", "binary profiler")
            return 'EXP'
        
    # TODO: Check the SHA against DBs
    def version_lookup(self):
        return "unknown"
    
    # TODO: Perform Strings search inside the binary to extract version    
    def version_extraction(self):
        command = ["strings", self.path]
        artifacts = []
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            # print(result.stdout)s
            version_pattern = re.compile(r'\s*\d+(\.\d+)+', re.IGNORECASE)
            compiler_pattern = re.compile(r'gcc: \((.*?)\)\s*(\d+[\.\d+]*)', re.IGNORECASE)
            for line in result.stdout.splitlines():
                    # Find compiler information
                    match = compiler_pattern.search(line)
                    if match:
                        item = {"version": match.group(2), "module": "GCC " + match.group(1), "context": line}
                        artifacts.append(item)
                        continue
                    # Try to derive version of the program
                    match = version_pattern.search(line)
                    if match:
                        # Based on manual analysis these tags are not correlated to version
                        if any(word in line for word in ["%", "OK", "HTTP", "CGI"]):
                            continue
                        item = {"version": match.group(), "module": "", "context": line}
                        module_pattern = re.compile(r'(\S+)[,\s]*v\s*\d+[\.\d+]*', re.IGNORECASE)
                        match = module_pattern.search(line)
                        if match:
                            item["module"] = match.group(1)
                        name = os.path.basename(self.path)
                        if name in line:
                            item["module"] = name
                        artifacts.append(item)
                        continue
        except subprocess.CalledProcessError as e:
            return []
        
        return artifacts



    def __init__(self, path='', name='', cert=10, ports=[]):
        self.path = path
        self.name = name
        if(name == ''):
            self.name = os.path.basename(path)
        self.cert = cert
        self.sha = self.compute_sha256()
        self.version_extracted = []
        self.version_found = "unknown"
        if self.path != "":
            self.version_extracted = self.version_extraction()
            self.version_found = self.version_lookup()
        self.ports = ports
        return
    
    def print(self, identation=""):
        label = ""
        label += f"--- {self.name}'s Label ---\n"
        label += f"- Path: {self.path}\n"
        label += f"- Cert: {self.cert}\n"
        label += f"- SHA256: {self.sha}\n"
        label += f"- Possible versions: {self.version_found}\n"
        label += f"- Ports opened: {self.ports}\n"
        log.output(label)

    def owner_print(self, identation="| |"):
        label = ""
        label += identation + f"-<{self.name}>\n"
        label += identation + f" |-Path: {self.path}\n"
        label += identation + f" |-Cert: {self.cert}\n"
        label += identation + f" |-SHA256: {self.sha}\n"
        label += identation + f" |-Possible versions: {self.version_found}\n"
        return label