from abc import ABC, abstractmethod
import xml.etree.ElementTree as ET
from firMap.graybox.scan import *
from ..utils import Logger
import subprocess
import psycopg2
import tarfile
import shutil
import sys
import os
import re

log = Logger("Graybox Monitor")

class EmulationEngines(ABC):
    """
    Base class for emulation engines (like FirmUp, FirmINC or custom tools).
    """
    # Key = user option, value = actual flag for the engine
    flag_mapping = {"default": " "}

    def __init__(self, reportStruct=None, firmware='', ip=''):
        if(reportStruct == None):
            self.reportStruct = GrayBoxScan(firmware=firmware, ip_address='')
            self.emulationProc = None

    @abstractmethod
    def name(self):
        """
        Return the name of the mapping engine (e.g. 'nmap', 'custom_engine')
        """
        pass

    def help(self):
        """
        Return the name of the mapping engine (e.g. 'nmap', 'custom_engine')
        """
        output = f"Engine Name: {self.name()} \nSupported Options:\n"
        for option, flag in self.flag_mapping.items():
            output += f"   {option}: \'{flag}\'\n"
        return output

    @abstractmethod
    def analysis(self, scan_result):
        """
        Analyse the logs created by the check() call.
        """
        pass

    @abstractmethod
    def emulate(self, ip, options):
        """
        Spawns an interactive emulation instance on the given ip. 
        This emulation needs to be terminated via the terminate() function.
        """
        pass

    @abstractmethod
    def terminate(self):
        """
        Quits interactive emulation opened by emulate()
        """
        pass
    
    @abstractmethod
    def check(self, options):
        """
        Performs a booting emulation and exits afterwards. Used to retrive the filesystem and syscall logs.
        """
        pass

    def find_binaries_by_name(self, process_name, path_to_fs):
        """
        Looks up the process name and associates it with possible binaries.
        """
        matches = []
        for dirpath, _, filenames in os.walk(path_to_fs):
            for filename in filenames:
                if filename == process_name:
                    full_path = os.path.join(dirpath, filename)
                    if os.access(full_path, os.X_OK):
                        matches.append(full_path)
        return matches

    def binary_profiling(self, path, name='', ports=[], cert=10):
        """
        Performs binary analysis on a given target, and returns a CriticalBinary instance with its"
        """
        binary = CriticalBinary(path, name, cert, ports)
        return binary

    def verification(self):
        """
        Performs blackbox verification on the emulated target
        """
        blackbox = NmapEngine(ip=self.reportStruct.ip_address)        
        blackbox.scan()

        for port in blackbox.reportStruct.ports.keys():
            if port in self.reportStruct.ports.keys():
                self.reportStruct.ports[port]['verification'] = blackbox.reportStruct.ports[port]
            else:
                self.reportStruct.ports[port] = {"owner":"Unkwown", 'verification': blackbox.reportStruct.ports[port]}

        return

def list_all_engines():
    print("Available engines:")
    for engine_cls in EmulationEngines.__subclasses__():
        engine = engine_cls()
        print(f" - {engine.name()} [modes available: {', '.join(engine.flag_mapping.keys())}]")

def get_engine_by_name(name, firmware=''):
    for engine_cls in EmulationEngines.__subclasses__():
        engine = engine_cls(firmware=firmware)
        if engine.name().lower() == name.lower():
            return engine
    return None


# FirmAE

class FirmAE(EmulationEngines):

    # PATH_TO_FIRMAE = "/home/dimitris/Documents/thesis/FirmAE/"
    PATH_TO_FIRMAE = "/home/porichis/dit-thesis/engines/FirmaInc/"
    flag_mapping = {"advanced": "-sV", "default": " "}

    DATABASE_NAME = os.getenv("FIRMAE_DB_NAME", "firmware")
    DATABASE_USR = os.getenv("FIRMAE_DB_USER", "firmadyne")
    DATABASE_PSW = os.getenv("FIRMAE_DB_PSW", "firmadyne")
    
    DATABASE_HOST = os.getenv("FIRMAE_DB_HOST", "localhost")
    DATABASE_PORT = os.getenv("FIRMAE_DB_PORT", "5432")

    def name(self):
        return "FirmAE"
    
    def connect_to_db(self):
        try:
            conn = psycopg2.connect(
                dbname=self.DATABASE_NAME,
                user=self.DATABASE_USR,
                password=self.DATABASE_PSW,
                host=self.DATABASE_HOST,
                port=self.DATABASE_PORT
            )
            return conn
        except Exception as e:
            log.log_message("error", f"Database connection failed: {e}", "FirmAE")
            return None

    def analysis(self):
        bind_pattern = r'\[\s*(\d+\.\d+)\]\s+firmadyne:\s+inet_bind\[PID:\s+\d+\s+\((.*?)\)\]:\s+proto:(.*?),\s+port:(\d+)'
        # close_pattern = r'\[\s*(\d+\.\d+)\]\s+firmadyne:\s+inet_bind\[PID:\s+\d+\s+\((.*?)\)\]:\s+proto:(.*?),\s+port:(\d+)'

        input_file = self.reportStruct.logs + 'qemu.final.serial.log'

        reverse_port_mapping = {}
        with open(input_file, 'r') as file:
            for line in file:
                # Search for bind systemcalls
                match = re.search(bind_pattern, line)
                if match:
                    self.reportStruct.bind_calls.append({
                        'timestamp': match.group(1),
                        'process_name': match.group(2),
                        'protocol': match.group(3),
                        'port': int(match.group(4))
                    })
                    self.reportStruct.critical_processes.add(match.group(2))
                    port = int(match.group(4))
                    if port in self.reportStruct.ports.keys():
                        self.reportStruct.ports[port]['owners'].append(match.group(2))
                    else:
                        self.reportStruct.ports[port] = {'owners':[match.group(2)], 'verification': None}
                    proc = match.group(2)
                    if proc in reverse_port_mapping.keys():
                        reverse_port_mapping[proc].add(port)
                    else:
                        reverse_port_mapping[proc] = set()
                        reverse_port_mapping[proc].add(port)

                # Search for close syscalls on file descriptors that we care about
                # (Not supported by FirmAE)

        for entry in self.reportStruct.bind_calls:
            print(entry)
        
        # Decompress the file system for analysis
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cache_dir = os.path.join(script_dir, "cache")
        os.makedirs(cache_dir, exist_ok=True)

        with tarfile.open(self.reportStruct.filesystem_path, "r:gz") as tar:
            tar.extractall(path=cache_dir)

        print(f"Extracted zip to {cache_dir}")

        # Perform process profiling for all critical processes
        for proc in self.reportStruct.critical_processes:
            possible_targets = self.find_binaries_by_name(proc, cache_dir)
            if(len(possible_targets) == 0):
                possible_targets = ['']
            cert = 10/len(possible_targets)
            for target in possible_targets:
                binary_label = self.binary_profiling(target, proc, list(reverse_port_mapping[proc]))
                binary_label.print()

        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)

        return
        
    def check(self):
        print(os.path.abspath(self.reportStruct.firware_path))
        command = ["sudo", "-E", "./run.sh", "-c", self.reportStruct.brand, os.path.abspath(self.reportStruct.firware_path)]
        try:
            log.log_message("info", "Elavated permissions are required, enter sudo password if prompted", "FirmAE")
            result = subprocess.run(command, cwd=self.PATH_TO_FIRMAE, text=True, check=True)
        except subprocess.CalledProcessError as e:
            return f"Error: {e.stderr}"
        
        db = self.connect_to_db()
        if db:
            with db.cursor() as cur:
                cur.execute("SELECT id FROM image WHERE hash=%s;", (str(self.reportStruct.md5_hash),))
                result = cur.fetchone()
                if result is not None:
                    image_id = result[0]
                    self.reportStruct.filesystem_path = self.PATH_TO_FIRMAE + "images/" + str(image_id) + ".tar.gz"
                    self.reportStruct.logs = self.PATH_TO_FIRMAE + "scratch/" + str(image_id) + "/"
                else:
                    log.log_message("error", "FirmAE failed miserably.", "FirmAE")
            db.close()

        self.analysis()
        return
        
    def emulate(self, ip, options):
        return

    def terminate(self):
        return

if __name__ == "__main__":
    # firmware_path = "/home/dimitris/Documents/thesis/FirmAE/DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip"
    firmware_path = "/home/porichis/dit-thesis/DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip"
    engine = FirmAE(firmware=firmware_path)
    print(engine.reportStruct.firware_path)
    engine.check()