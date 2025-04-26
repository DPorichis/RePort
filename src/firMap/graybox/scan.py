import os
import sys
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

    def retrieve_version(self):
        # TODO: Check the SHA against DBs

        # TODO: Perform Strings search inside the binary to extract version
        return

    def __init__(self, path='', name='', cert=10, ports=[]):
        self.path = path
        self.name = name
        if(name == ''):
            self.name = os.path.basename(path)
        self.cert = cert
        self.sha = self.compute_sha256()
        self.version = [{"version":'unknown', "source":'initial', "cert":'0'}]
        self.ports = ports
        return
    
    def print(self, identation=""):
        label = ""
        label += f"--- {self.name}'s Label ---\n"
        label += f"- Path: {self.path}\n"
        label += f"- Cert: {self.cert}\n"
        label += f"- SHA256: {self.sha}\n"
        label += f"- Possible versions: {self.version}\n"
        label += f"- Ports opened: {self.ports}\n"
        log.output(label)

    def owner_print(self, identation="| |"):
        label = ""
        label += identation + f"-<{self.name}>\n"
        label += identation + f" |-Path: {self.path}\n"
        label += identation + f" |-Cert: {self.cert}\n"
        label += identation + f" |-SHA256: {self.sha}\n"
        label += identation + f" |-Possible versions: {self.version}\n"
        return label