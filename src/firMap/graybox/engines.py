from abc import ABC, abstractmethod
import xml.etree.ElementTree as ET
from scan import *
import subprocess
import psycopg2
import sys
import os
import re

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

    def find_binaries_by_name(self, process_name):
        """
        Looks up the process name and associates it with possible binaries.
        """
        matches = []
        for dirpath, _, filenames in os.walk(self.reportStruct.filesystem_path):
            for filename in filenames:
                if filename == process_name:
                    full_path = os.path.join(dirpath, filename)
                    if os.access(full_path, os.X_OK):
                        matches.append(full_path)
        return matches

    def binary_profiling(self, path, ports=[], cert=10):
        """
        Performs binary analysis on a given target, and returns a CriticalBinary instance with its"
        """
        binary = CriticalBinary(path, cert)
        return

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

def get_engine_by_name(name):
    for engine_cls in EmulationEngines.__subclasses__():
        engine = engine_cls()
        if engine.name().lower() == name.lower():
            return engine
    return None


# FirmAE

class FirmAE(EmulationEngines):

    PATH_TO_FIRMAE = "/home/dimitris/Documents/thesis/FirmAE/"
    flag_mapping = {"advanced": "-sV", "default": " "}

    DATABASE_NAME = os.getenv("FIRMAE_DB_NAME", "default_db")
    DATABASE_USR = os.getenv("FIRMAE_DB_USER", "default_user")
    DATABASE_PSW = os.getenv("FIRMAE_DB_PSW", "")
    
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
            print(f"[!] Graybox Monitor (FirmAE): Database connection failed: {e}")
            return None

    def analysis(self, input_file):
        bind_pattern = r'\[\s*(\d+\.\d+)\]\s+firmadyne:\s+inet_bind\[PID:\s+\d+\s+\((.*?)\)\]:\s+proto:(.*?),\s+port:(\d+)'
        # close_pattern = r'\[\s*(\d+\.\d+)\]\s+firmadyne:\s+inet_bind\[PID:\s+\d+\s+\((.*?)\)\]:\s+proto:(.*?),\s+port:(\d+)'

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
                    if self.reportStruct.ports[port]:
                        self.reportStruct.ports[port]['owners'].append(match.group(2))
                    else:
                        self.reportStruct.ports[port] = {'owners':[match.group(2)], 'verification': None}

                # Search for close syscalls on file descriptors that we care about
                # (Not supported by FirmAE)

        for entry in self.reportStruct.bind_calls:
            print(entry)

        # Perform process profiling for all critical processes
        for proc in self.reportStruct.critical_processes:
            possible_targets = self.find_binaries_by_name(proc)
            cert = 10/len(possible_targets)
            for target in possible_targets:
                binary_label = self.binary_profiling(target, [])

        return
        
    def check(self):
        print(os.path.abspath(self.reportStruct.firware_path))
        command = ["sudo", "./run.sh", "-c", self.reportStruct.brand, os.path.abspath(self.reportStruct.firware_path)]
        try:
            print("[i] Graybox Monitor (FirmAE): Elavated permissions are required, enter sudo password if prompted", file=sys.stderr)
            result = subprocess.run(command, cwd=self.PATH_TO_FIRMAE, text=True, check=True)
        except subprocess.CalledProcessError as e:
            return f"Error: {e.stderr}"
        
        db = self.connect_to_db()
        if db:
            with db.cursor() as cur:
                cur.execute("SELECT * FROM some_table LIMIT 5;")
                rows = cur.fetchall()
                for row in rows:
                    print(row)
            db.close()

        
    def emulate(self, ip, options):
        return

    def terminate(self):
        return

if __name__ == "__main__":
    firmware_path = "/home/dimitris/Documents/thesis/FirmAE/DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip"
    engine = FirmAE(firmware=firmware_path)
    print(engine.reportStruct.firware_path)
    engine.check()