from abc import ABC, abstractmethod
import xml.etree.ElementTree as ET
from firMap.graybox.scan import *
from ..utils import Logger
from firMap.blackbox.engines import NmapEngine
import subprocess
import psycopg2
import tarfile
import threading
import shutil
import signal
import time
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
    def emulate(self):
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
        blackbox.scan(self.reportStruct.ip_address, "advanced")
        for port in blackbox.reportStruct.ports.keys():
            if port in self.reportStruct.ports.keys():
                self.reportStruct.ports[port]['verification'] = blackbox.reportStruct.ports[port]
            else:
                self.reportStruct.ports[port] = {"owner":"Unkwown", 'verification': blackbox.reportStruct.ports[port]}
        return

def list_all_engines():
    log.output("Available engines:")
    for engine_cls in EmulationEngines.__subclasses__():
        engine = engine_cls()
        log.output(f" - {engine.name()} [modes available: {', '.join(engine.flag_mapping.keys())}]")

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

    def __init__(self, reportStruct=None, firmware='', ip='192.168.0.1'):
        if(reportStruct == None):
            self.reportStruct = GrayBoxScan(firmware=firmware, ip_address=ip)
            self.emulationProc = None

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
            log.message("error", f"Database connection failed: {e}", "FirmAE")
            return None
        
    class PortActivity:
        def __init__(self):
            self.critical_processes = set()
            self.process_activity = {}
            self.open_ports = {}
            self.port_history = []

            self.close_cache = []
            self.close_cache_users = 0

        def new_bind(self, timestamp, pid, fd, port, process_name):
            if pid not in self.process_activity.keys():
                self.process_activity[pid] = {}
            
            self.process_activity[pid][fd] = {'port': port, 'timestamp': timestamp}
            self.critical_processes.add(process_name)

            if port not in self.open_ports.keys():
                self.open_ports[port] = {'owner': (process_name, pid), "access": [pid], "start": timestamp} 
            else:
                old = self.open_ports[port]
                log.message("warn", f"Port {port} overidden from an other process ({self.open_ports[port]["owner"][0]} -> {process_name})")
                self.port_history.append((port, old["owner"][0], old["owner"][1], old["start"], timestamp))
                
                self.open_ports[port] = {'owner': (process_name, pid), "access": [(process_name, pid)]}
        
        def new_close(self, timestamp, pid, fd):
            if pid in self.process_activity.keys():
                if fd in self.process_activity[pid].keys():
                    port = self.process_activity[pid][fd]["port"]
                    self.open_ports[port]["access"].remove(pid)
                    if len(self.open_ports[port]["access"]) == 0:
                        old = self.open_ports[port]
                        self.port_history.append((port, old["owner"][0], old["owner"][1], old["start"], timestamp))
                        del self.open_ports[port]
                    del self.process_activity[pid][fd]

            # If we are waiting for PID info of a fork, cache this close
            if self.close_cache_users != 0:
                self.close_cache_users -= 1

        def new_exit(self, timestamp, pid):
            if pid in self.process_activity.keys():
                for fd in self.process_activity[pid].keys():
                    port = self.process_activity[pid][fd]["port"]
                    del self.process_activity[pid][fd]
                    del self.open_ports[port]
                    
                    self.open_ports[port]["access"].remove(pid)
                    if len(self.open_ports[port]["access"]) == 0:
                        old = self.open_ports[port]
                        self.port_history.append((port, old["owner"][0], old["owner"][1], old["start"], timestamp))
                        del self.open_ports[port]
                    del self.process_activity[pid][fd]

            # If we are waiting for PID info of a fork, cache this close
            if self.close_cache_users != 0:
                self.close_cache_users -= 1

        def inherit_from_fork(self, pid, child_pid):
            if pid not in self.process_activity.keys():
                self.process_activity[pid] = {}

            if child_pid not in self.process_activity.keys():
                self.process_activity[child_pid] = {}

            for fd in self.process_activity[pid].keys():
                self.process_activity[child_pid][fd] = self.process_activity[child_pid][fd]

            for closure in close_activity_cache:
                if closure[0] == child_pid:
                    if closure[1] in self.process_activity[child_pid].keys():
                        del self.process_activity[child_pid][fd]

            for fd in self.process_activity[child_pid].keys():
                port = self.process_activity[child_pid][fd]
                self.open_ports[port]["access"].add(child_pid)
            
            pid_queue -= 1
            if pid_queue == 0:
                close_activity_cache = []


    def analysis(self):

        # Pattern for retriving fork calls:
        # 1 - Timestamp | 2 - PID | 3 - Process Name | 4 - Clone Flags | 5 - Stack Size
        fork_pattern = r"\[\s*(\d+\.\d+)\]\s+firmadyne:\s+do_fork\[PID:\s*(\d+)\s+\(([^)]+)\)\]:\s+clone_flags:0x([0-9a-fA-F]+),\s+stack_size:0x([0-9a-fA-F]+)"
        
        # Pattern for retriving fork return values:
        # 1 - Timestamp | 2 - PID | 3 - Process Name | 4 - Child PID
        fork_ret_pattern = r"\[\s*(\d+\.\d+)\]\s+firmadyne:\s+do_fork_ret\[PID:\s*(\d+)\s+\(([^)]+)\)\]\s*=\s*(\d+)"
        
        # Pattern for retriving bind calls:
        # 1 - Timestamp | 2 - PID | 3 - Process Name | 4 - fd | 5 - Family | 6 - Port
        bind_pattern = r"\[\s*(\d+\.\d+)\]\s+firmadyne:\s+sys_bind\[PID:\s*(\d+)\s+\(([^)]+)\)\]:\s+fd:(\d+)\s+family:(\d+)\s+port:\s*(\d+)"
        
        # Pattern for retriving bind return values:
        # 1 - Timestamp | 2 - PID | 3 - Process Name | 4 - Return Code
        bind_ret_pattern = r"\[\s*(\d+\.\d+)\]\s+firmadyne:\s+sys_bind_ret\[PID:\s*(\d+)\s+\(([^)]+)\)\]\s*=\s*(\d+)"
        
        # Patterns for retriving ipv4 and ipv6 bind calls:
        # 1 - Timestamp | 2 - PID | 3 - Process Name | 4 - Proto | 5 - Port
        inet4_bind_pattern = r'\[\s*(\d+\.\d+)\]\s+firmadyne:\s+inet_bind\[PID:\s+\d+\s+\((.*?)\)\]:\s+proto:(.*?),\s+port:(\d+)'
        inet6_bind_pattern = r'\[\s*(\d+\.\d+)\]\s+firmadyne:\s+inet6_bind\[PID:\s+\d+\s+\((.*?)\)\]:\s+proto:(.*?),\s+port:(\d+)'
        
        # Pattern for retriving close calls:
        # 1 - Timestamp | 2 - PID | 3 - Process Name | 4 - fd
        close_pattern = r'\[\s*(\d+\.\d+)\]\s+firmadyne:\s+close\[PID:\s*(\d+)\s+\(([^)]+)\)\]:\s+fd:(\d+)'

        input_file = self.reportStruct.logs + 'qemu.final.serial.log'

        process_activity = {}
        open_ports = {}

        closed_ports = []

        critical_processes = set()
        reverse_port_mapping = {}

        close_activity_cache = []
        pid_queue = 0

        with open(input_file, 'r') as file:
            for line in file:
                # Search for bind systemcalls
                match = re.search(bind_pattern, line)
                if match:
                    print(match)
                    timestamp = float(match.group(1))
                    pid = int(match.group(2))
                    fd = int(match.group(4))                    
                    family = int(match.group(5))
                    print(family)
                    port = int(match.group(6))
                    if(family == 2 or family == 10):
                        if pid not in process_activity.keys():
                            process_activity[pid] = {}
                        self.reportStruct.bind_calls.append({
                            'timestamp': timestamp,
                            'pid': pid,
                            'process_name': match.group(3),
                            'family': family,
                            'port': port
                        })
                        process_activity[pid][fd] = {'port': port, 'timestamp': timestamp}
                        critical_processes.add(match.group(3))
                        if port in self.reportStruct.ports.keys():
                            self.reportStruct.ports[port]['owners'].add(match.group(3))
                        else:
                            self.reportStruct.ports[port] = {'owners':{match.group(3)}, 'verification': []}
                        proc = match.group(3)
                        if proc in reverse_port_mapping.keys():
                            reverse_port_mapping[proc][port] = {"start": timestamp}
                        else:
                            reverse_port_mapping[proc] = {}
                            reverse_port_mapping[proc][port] = {"start": timestamp}
                
                # Search for fork patterns on PIDs with open ports
                match = re.search(fork_pattern, line)
                if match:
                    timestamp = float(match.group(1))
                    pid = int(match.group(2))
                    fd = int(match.group(4))
                    if pid in process_activity.keys():
                        if fd in process_activity[pid].keys():

                            # Check more lines here #
                            port = process_activity[pid][fd]["port"]
                            reverse_port_mapping[match.group(3)][port]["end"] = timestamp
                            closed_ports.append(f"{match.group(3)}: Port {port} open from {reverse_port_mapping[match.group(3)][port]["start"]} until {reverse_port_mapping[match.group(3)][port]["end"]}")
                            (f"Port {port}")
                            del process_activity[pid][fd]

                # Search for fork return patterns to assign activity
                match = re.search(fork_ret_pattern, line)
                if match:
                    timestamp = float(match.group(1))
                    pid = int(match.group(2))
                    childpid = int(match.group(4))
                    
                    if pid not in process_activity.keys():
                        process_activity[pid] = {}

                    if childpid not in process_activity.keys():
                        process_activity[childpid] = {}

                    for fd in process_activity[pid].keys():
                        process_activity[childpid][fd] = process_activity[childpid][fd]

                    for closure in close_activity_cache:
                        if closure[0] == childpid:
                            if closure[1] in process_activity[childpid].keys():
                               del process_activity[childpid][fd]

                    for fd in process_activity[childpid].keys():
                        port = process_activity[childpid][fd]
                        open_ports[port]["access"].add(childpid)
                    
                    pid_queue -= 1
                    if pid_queue == 0:
                        close_activity_cache = []


                    if pid in process_activity.keys():
                        if fd in process_activity[pid].keys():

                            port = process_activity[pid][fd]["port"]
                            reverse_port_mapping[match.group(3)][port]["end"] = timestamp
                            closed_ports.append(f"{match.group(3)}: Port {port} open from {reverse_port_mapping[match.group(3)][port]["start"]} until {reverse_port_mapping[match.group(3)][port]["end"]}")
                            (f"Port {port}")
                            del process_activity[pid][fd]

                # Search for close syscalls on file descriptors that we care about
                match = re.search(close_pattern, line)
                if match:
                    timestamp = float(match.group(1))
                    pid = int(match.group(2))
                    fd = int(match.group(4))
                    if pid in process_activity.keys():
                        if fd in process_activity[pid].keys():
                            port = process_activity[pid][fd]["port"]
                            reverse_port_mapping[match.group(3)][port]["end"] = timestamp
                            open_ports[port]["access"].remove(pid)
                            
                            closed_ports.append(f"{match.group(3)}: Port {port} open from {reverse_port_mapping[match.group(3)][port]["start"]} until {reverse_port_mapping[match.group(3)][port]["end"]}")
                            (f"Port {port}")
                            del process_activity[pid][fd]

                    # If we are waiting for PID info of a fork, cache this close
                    if pid_queue != 0:
                        close_activity_cache.append((pid,fd))

        for entry in self.reportStruct.bind_calls:
            log.output(entry)
        
        # Decompress the file system for analysis
        # script_dir = os.path.dirname(os.path.abspath(__file__))
        # cache_dir = os.path.join(script_dir, "cache")
        # os.makedirs(cache_dir, exist_ok=True)

        # with tarfile.open(self.reportStruct.filesystem_path, "r:gz") as tar:
        #     tar.extractall(path=cache_dir)

        # Perform process profiling for all critical processes
        for proc in critical_processes:
            possible_targets = []
            # possible_targets = self.find_binaries_by_name(proc, cache_dir)
            if(len(possible_targets) == 0):
                possible_targets = ['']
            cert = 10/len(possible_targets)
            for target in possible_targets:
                binary_label = self.binary_profiling(target, proc, list(reverse_port_mapping[proc]))
                binary_label.print()
                self.reportStruct.critical_processes[proc] = binary_label

        # if os.path.exists(cache_dir):
        #     shutil.rmtree(cache_dir)
        for item in closed_ports:
            print(item)

        return
        
    def check(self):
        command = ["sudo", "-E", "./run.sh", "-c", self.reportStruct.brand, os.path.abspath(self.reportStruct.firware_path)]
        try:
            log.message("info", "Elavated permissions are required, enter sudo password if prompted", "FirmAE")
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
                    log.message("error", "FirmAE failed miserably.", "FirmAE")
            db.close()

        self.analysis()
        return
        
    def emulate(self):

        def check_ready(process, target, result_flag):
            for line in process.stdout:
                print(line)
                if target in line:
                    result_flag['running'] = True
                    break
                if "RTNETLINK answers: File exists" in line:
                    log.message("warn", f"Tap Device setup failed, (tap1_0 already exists)", "FirmAE -run")
                    break

        command = ["sudo", "-E", "./run.sh", "--run", self.reportStruct.brand, os.path.abspath(self.reportStruct.firware_path)]
        # Start the process
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=self.PATH_TO_FIRMAE,
            text=True,
            bufsize=1
        )

        target_text = self.reportStruct.ip_address + " true true"
        result = {'running': False}

        # Start a thread to read output
        reader_thread = threading.Thread(target=check_ready, args=(process, target_text, result))
        reader_thread.start()

        timeout_seconds = 180
        reader_thread.join(timeout_seconds)

        if reader_thread.is_alive():
            log.message("warn", f"Emulation Timeout reached ({timeout_seconds} s). Firmware emulation exiting...")
            process.terminate()
            reader_thread.join()

        if result['running']:
            log.message("info", f"Firmware emulation open at IP {self.reportStruct.ip_address}.", "FirmAE -run")
        else:
            log.message("error", f"Firmware emulation failed.", "FirmAE -run")

        self.emulationProc = process
        return

    def terminate(self):
        
        if self.emulationProc.poll() is not None:
            log.message("warn", f"Emulation exited unexpectedly with return code {self.emulationProc.returncode}")
        else:
            os.kill(self.emulationProc.pid, signal.SIGINT)
            try:
                self.emulationProc.wait(timeout=20)
                log.message("info", f"Firmware emulation exited cleanly.", "FirmAE -run")
            except subprocess.TimeoutExpired:
                print("warn", "Firmware emulation did not exit peacefully, proccess forced killed." "FirmAE -run")
                self.emulationProc.kill()
        return
    
    def result_output(self):
        for port in self.reportStruct.ports.keys():
            output = f"[Port {port}]\n" + f"|-(Possible Owner)\n" 
            for own in self.reportStruct.ports[port]["owners"]:
                output += self.reportStruct.critical_processes[own].owner_print()
            if len(self.reportStruct.ports[port]["verification"]) != 0:
                output += f"-- Verified\n="
            else:
                output += f"-- Not Verified\n="
            log.output(output)


if __name__ == "__main__":
    # firmware_path = "/home/dimitris/Documents/thesis/FirmAE/DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip"
    firmware_path = "/home/porichis/dit-thesis/DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip"
    engine = FirmAE(firmware=firmware_path)
    engine.check()