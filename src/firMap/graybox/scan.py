import os
import re
import sys
import subprocess
import hashlib
from firMap.utils import Logger
from datetime import datetime

log = Logger("Graybox Monitor")
class GrayBoxScan:
    def __init__(self, firmware='', fs='', ip_address=None, brand='unknown'):
        
        #### Important Paths ####
        self.firware_path = firmware
        self.filesystem_path = fs
        self.report_folder = os.path.basename(firmware) + "-" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        # Find base directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(script_dir)))

        # Make the reports folder if it doesn't exist already
        os.makedirs(os.path.join(base_dir, "reports"), exist_ok=True)

        # Create the report folder for this analysis
        self.report_path = os.path.join(os.path.join(os.path.join(base_dir, "reports")), self.report_folder)
        os.makedirs(self.report_path, exist_ok=True)

        # Blackbox Verification Information
        self.black_verification = None
        self.ip_address = ip_address
    
        # Firmware ID
        self.md5_hash = self.io_md5(self.firware_path)
        self.brand = brand

        # Port Logs
        self.port_activity = PortActivity()

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
        
class PortActivity:
    def __init__(self):
        self.critical_processes = set()
        self.process_activity = {}
        self.open_ports = {}
        self.ports_used = set()
        self.port_history = {}
        
        self.close_cache = []
        self.close_cache_users = 0

    def new_bind(self, timestamp, pid, fd, port, process_name, family, type):
        if pid not in self.process_activity.keys():
            self.process_activity[pid] = {}
        
        self.process_activity[pid][fd] = {'port': port, 'timestamp': timestamp, 'family': family, 'type': type}
        self.critical_processes.add(process_name)

        if port not in self.open_ports.keys():
            self.ports_used.add(port)
            self.open_ports[port] = {'owner': (process_name, pid), "access": {pid}, "access_history": {pid}, "start": timestamp} 
        else:
            # if self.open_ports[port]["owner"][1] != pid:    
                old = self.open_ports[port]
                log.message("warn", f"Port {port} overidden from an other process ({self.open_ports[port]["owner"][0]} -> {process_name})")
                if port not in self.port_history.keys():
                    self.port_history[port] = {"instances": [{"owner": (old["owner"][0], old["owner"][1]),
                                                            "times": (old["start"], timestamp),
                                                            "access_history": old["access_history"]
                                                            }]}
                else:
                    self.port_history[port]["instances"].append({"owner": (old["owner"][0], old["owner"][1]),
                                                            "times": (old["start"], timestamp),
                                                            "access_history": old["access_history"]
                                                            })

                self.open_ports[port] = {'owner': (process_name, pid), "access": {pid}, "access_history": {pid}, "start": timestamp}
    
    def update_port_info(self, pid, fd=-1, port=-1):
        return

    def new_close(self, timestamp, pid, fd):
        if pid in self.process_activity.keys():
            if fd in self.process_activity[pid].keys():
                port = self.process_activity[pid][fd]["port"]
                if port not in self.open_ports.keys():
                    log.message("error", "Jim did something wrong", "Jim")
                    del self.process_activity[pid][fd]
                    return
                self.open_ports[port]["access"].remove(pid)
                if len(self.open_ports[port]["access"]) == 0:
                    old = self.open_ports[port]
                    if port not in self.port_history.keys():
                        self.port_history[port] = {"instances": [{"owner": (old["owner"][0], old["owner"][1]),
                                                                "times": (old["start"], timestamp),
                                                                "access_history": old["access_history"]
                                                                }]}
                    else:
                        self.port_history[port]["instances"].append({"owner": (old["owner"][0], old["owner"][1]),
                                                                "times": (old["start"], timestamp),
                                                                "access_history": old["access_history"]
                                                                })
                    
                    log.message("warn", f"{port} deleted due to closure of last", "Jim")
                    del self.open_ports[port]
                del self.process_activity[pid][fd]

        # If we are waiting for PID info of a fork, cache this close
        if self.close_cache_users != 0:
            self.close_cache.append((pid, fd))

    def new_exit(self, timestamp, pid):
        if pid in self.process_activity.keys():
            for fd in self.process_activity[pid].keys():
                # Update the port that this PID no longer has access to this port
                port = self.process_activity[pid][fd]["port"]
                if port not in self.open_ports.keys():
                    log.message("error", "Jim did something wrong", "Jim")
                    continue
                if pid in self.open_ports[port]["access"]:
                    self.open_ports[port]["access"].remove(pid)

                # Check if all accessors of the port have closed their fd
                if len(self.open_ports[port]["access"]) == 0:
                    old = self.open_ports[port]
                    if port not in self.port_history.keys():
                        self.port_history[port] = {"instances": [{"owner": (old["owner"][0], old["owner"][1]),
                                                                "times": (old["start"], timestamp),
                                                                "access_history": old["access_history"]
                                                                }]}
                    else:
                        self.port_history[port]["instances"].append({"owner": (old["owner"][0], old["owner"][1]),
                                                                "times": (old["start"], timestamp),
                                                                "access_history": old["access_history"]
                                                                })                    
                    log.message("warn", f"{port} deleted", "Jim")
                    del self.open_ports[port]
                
            # Delete this instance
            del self.process_activity[pid]
    
    def new_fork(self):
        self.close_cache_users += 1

    def inherit_from_fork(self, pid, child_pid):
        if pid not in self.process_activity.keys():
            self.process_activity[pid] = {}

        if child_pid not in self.process_activity.keys():
            self.process_activity[child_pid] = {}

        for fd in self.process_activity[pid].keys():
            self.process_activity[child_pid][fd] = self.process_activity[pid][fd]

        for closure in self.close_cache:
            if closure[0] == child_pid:
                if closure[1] in self.process_activity[child_pid].keys():
                    del self.process_activity[child_pid][closure[1]]

        for fd in self.process_activity[child_pid].keys():
            port = self.process_activity[child_pid][fd]["port"]
            self.open_ports[port]["access"].add(child_pid)
            self.open_ports[port]["access_history"].add(child_pid)
        
        self.close_cache_users -= 1
        if self.close_cache_users == 0:
            self.close_cache = []

    def end(self):
        for port in self.open_ports.keys():
            old = self.open_ports[port]
            if port not in self.port_history.keys():
                self.port_history[port] = {"instances": [{"owner": (old["owner"][0], old["owner"][1]),
                                                        "times": (old["start"], "END"),
                                                        "access_history": old["access_history"]
                                                        }]}
            else:
                self.port_history[port]["instances"].append({"owner": (old["owner"][0], old["owner"][1]),
                                                        "times": (old["start"], "END"),
                                                        "access_history": old["access_history"]
                                                        })
                        

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