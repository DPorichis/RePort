import os
import sys
import hashlib

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
        self.critical_processes = set()
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
            print(f'[!] Graybox Monitor (binary profiler): File \"{self.path}\" was not found, SHA will not be calculated', file=sys.stderr)
            return 'BNF'
        except Exception as e:
            print(f'[!] Graybox Monitor (binary profiler): An exception occured, SHA will not be calculated (Exception: {e})', file=sys.stderr)
            return 'EXP'

    def retrieve_version(self):
        # TODO: Check the SHA against DBs

        # TODO: Perform Strings search inside the binary to extract version
        return

    def __init__(self, path='', cert=10):
        self.path = path
        self.name = os.path.basename(path)
        self.cert = cert
        self.sha = self.compute_sha256()
        self.version = [{"version":'unknown', "source":'initial', "cert":'0'}]
        return
    
    def print(self):
        print(f"--- {self.name}'s Label ---")
        print(f"- Path: {self.path}")
        print(f"- Cert: {self.cert}")
        print(f"- SHA256: {self.sha}")
        print(f"- Possible versions: {self.version}")