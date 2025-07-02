import os
import re
import sys
import subprocess
import hashlib
from RePort.utils import Logger
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

        # Blackbox confirmation Information
        self.black_confirmation = None
        self.ip_address = ip_address
    
        # Firmware ID
        if self.firware_path != '':
            self.md5_hash = self.io_md5(self.firware_path)
        else:
            self.md_hash = "NoFile"
        self.brand = brand

        # Port Logs
        self.port_activity = PortActivity()

        self.result = "Success"

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
        # Set of all PIDs that have access to ports
        self.critical_processes = set()

        # Dictionary tracking the PIDs activity over ports
        self.process_activity = {}

        # Dictionary tracking what ports are at use at any given time and by whom
        self.open_ports = {}

        # Set of all ports utilized by the firmware
        self.ports_used = set()

        # Detailed dictionary of all actions on ports
        self.port_history = {}

        # PID to Ports mapping        
        self.pid_to_ports = {}

        # PID to binary executables mapping
        self.pid_to_binary = {}

        # Path to Ports and CVE mapping
        self.binary_report = {}

        # Cache for updating the state
        self.close_cache = []
        self.close_cache_users = 0

    def new_bind(self, timestamp:float, pid:int, fd:int, port:int, process_name:str, family:str, type:str, random=False):
        if pid not in self.process_activity.keys():
            self.process_activity[pid] = {}
        
        self.process_activity[pid][fd] = {'port': port, 'timestamp': timestamp, 'family': family, 'type': type, "random": random}
        self.critical_processes.add(int(pid))
        port_tag = (family, type)
        
        if port not in self.open_ports.keys():
            self.ports_used.add(port)    
            self.open_ports[port] = {port_tag: {'owner': (process_name, pid), "access": {pid}, "access_history": {pid}, "start": timestamp, "family": family, "type": type, "random": random}} 
        else:
            if port_tag in self.open_ports[port].keys():
                old = self.open_ports[port][port_tag]
                if port not in self.port_history.keys():
                    self.port_history[port] = {"instances": [{"owner": (old["owner"][0], old["owner"][1]),
                                                            "times": (old["start"], timestamp),
                                                            "access_history": old["access_history"],
                                                            "family": old["family"], "type": old["type"],
                                                            "random": old["random"]
                                                            }],
                                                "confirmation": None
                                                }
                else:
                    self.port_history[port]["instances"].append({"owner": (old["owner"][0], old["owner"][1]),
                                                            "times": (old["start"], timestamp),
                                                            "access_history": old["access_history"],
                                                            "family": old["family"], "type": old["type"],
                                                            "random": old["random"]
                                                            })

            self.open_ports[port][port_tag] = {'owner': (process_name, pid), "access": {pid}, "access_history": {pid}, "start": timestamp, "family": family, "type": type, "random": random}
    
    def update_port_info(self, pid, fd=-1, port=-1):
        return

    def new_close(self, timestamp, pid, fd):
        if pid in self.process_activity.keys():
            if fd in self.process_activity[pid].keys():
                port = self.process_activity[pid][fd]["port"]
                port_tag = (self.process_activity[pid][fd]["family"], self.process_activity[pid][fd]["type"])
                if port not in self.open_ports.keys() or port_tag not in self.open_ports[port].keys():
                    log.message("error", "Jim did something wrong", "Jim")
                    del self.process_activity[pid][fd]
                    return
                self.open_ports[port][port_tag]["access"].remove(pid)
                if len(self.open_ports[port][port_tag]["access"]) == 0:
                    old = self.open_ports[port][port_tag]
                    if port not in self.port_history.keys():
                        self.port_history[port] = {"instances": [{"owner": (old["owner"][0], old["owner"][1]),
                                                                "times": (old["start"], timestamp),
                                                                "access_history": old["access_history"],
                                                                "family": old["family"], "type": old["type"],
                                                                "random": old["random"]
                                                                }],
                                                    "confirmation": None
                                                    }
                    else:
                        self.port_history[port]["instances"].append({"owner": (old["owner"][0], old["owner"][1]),
                                                                "times": (old["start"], timestamp),
                                                                "access_history": old["access_history"],
                                                                "family": old["family"], "type": old["type"],
                                                                "random": old["random"]
                                                                })
                    
                    # log.message("warn", f"{port} deleted due to closure of last", "Jim")
                    del self.open_ports[port][port_tag]
                del self.process_activity[pid][fd]

        # If we are waiting for PID info of a fork, cache this close
        if self.close_cache_users != 0:
            self.close_cache.append((pid, fd))

    def new_exit(self, timestamp, pid):
        if pid in self.process_activity.keys():
            for fd in self.process_activity[pid].keys():
                # Update the port that this PID no longer has access to this port
                port = self.process_activity[pid][fd]["port"]
                port_tag = (self.process_activity[pid][fd]["family"], self.process_activity[pid][fd]["type"])
                if port not in self.open_ports.keys() or port_tag not in self.open_ports[port].keys():
                    log.message("error", "Jim did something wrong on exit", "Jim")
                    continue
                if pid in self.open_ports[port][port_tag]["access"]:
                    self.open_ports[port][port_tag]["access"].remove(pid)

                if len(self.open_ports[port][port_tag]["access"]) == 0:
                    old = self.open_ports[port][port_tag]
                    if port not in self.port_history.keys():
                        self.port_history[port] = {"instances": [{"owner": (old["owner"][0], old["owner"][1]),
                                                                "times": (old["start"], timestamp),
                                                                "access_history": old["access_history"],
                                                                "family": old["family"], "type": old["type"],
                                                                "random": old["random"]
                                                                }],
                                                    "confirmation": None
                                                    }
                    else:
                        self.port_history[port]["instances"].append({"owner": (old["owner"][0], old["owner"][1]),
                                                                "times": (old["start"], timestamp),
                                                                "access_history": old["access_history"],
                                                                "family": old["family"], "type": old["type"],
                                                                "random": old["random"]
                                                                })
                    # log.message("warn", f"{port} deleted due to closure of last", "Jim")
                    del self.open_ports[port][port_tag]
                
            # Delete this instance
            del self.process_activity[pid]
    
    def new_fork(self):
        self.close_cache_users += 1

    def inherit_from_fork(self, pid, child_pid):
        if pid not in self.process_activity.keys():
            self.process_activity[pid] = {}

        if child_pid not in self.process_activity.keys():
            self.process_activity[child_pid] = {}

        if pid in self.critical_processes:
            self.critical_processes.add(int(child_pid))

        for fd in self.process_activity[pid].keys():
            self.process_activity[child_pid][fd] = self.process_activity[pid][fd]

        for closure in self.close_cache:
            if closure[0] == child_pid:
                if closure[1] in self.process_activity[child_pid].keys():
                    del self.process_activity[child_pid][closure[1]]

        for fd in self.process_activity[child_pid].keys():
            port = self.process_activity[child_pid][fd]["port"]
            port_tag = (self.process_activity[pid][fd]["family"], self.process_activity[pid][fd]["type"])
            self.open_ports[port][port_tag]["access"].add(child_pid)
            self.open_ports[port][port_tag]["access_history"].add(child_pid)
        
        self.close_cache_users -= 1
        if self.close_cache_users == 0:
            self.close_cache = []

    def end(self):
        for port in self.open_ports.keys():
            for port_tag in self.open_ports[port].keys():
                old = self.open_ports[port][port_tag]
                if port not in self.port_history.keys():
                    self.port_history[port] = {"instances": [{"owner": (old["owner"][0], old["owner"][1]),
                                                            "times": (old["start"], "END"),
                                                            "access_history": old["access_history"],
                                                            "family": old["family"], "type": old["type"],
                                                            "random": old["random"]
                                                            }],
                                                "confirmation": None
                                                }
                else:
                    self.port_history[port]["instances"].append({"owner": (old["owner"][0], old["owner"][1]),
                                                            "times": (old["start"], "END"),
                                                            "access_history": old["access_history"],
                                                            "family": old["family"], "type": old["type"],
                                                            "random": old["random"]
                                                            })

        for port in self.port_history.keys():
            for instance in self.port_history[port]["instances"]:
                for pid in instance["access_history"]:
                    port_label = (port, instance["family"], instance["type"])
                    if pid not in self.pid_to_ports.keys():
                        self.pid_to_ports[pid] = {"access": set(),
                                            "owns": set()}
                    self.pid_to_ports[pid]["access"].add(port_label)
                self.pid_to_ports[instance["owner"][1]]["owns"].add(port_label)

    def corelate_execve(self, pid, item):
        if pid not in self.pid_to_binary.keys():
            self.pid_to_binary[pid] = [item]
        else:
            exists = False
            for other in self.pid_to_binary[pid]:
                if item[1] == other[1] and item[2] == other[2]:
                    exists = True
                    break
            if not exists:
                self.pid_to_binary[pid].append(item)
        
        if item[1] != "Unknown":
            if item[1] not in self.binary_report.keys():
                self.binary_report[item[1]] = {"pids": set(),
                                            "owns": set(),
                                            "access": set(),
                                            "CVEs": []}
            self.binary_report[item[1]]["pids"].add(pid)


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

    def dynamic_linked_libraries(self):
        
        command = f"readelf -d '{self.path}' | grep NEEDED | awk -F'[][]' '{{print $2}}'"
        artifacts = []
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                artifacts.append((line.strip(), "Primary"))
        except subprocess.CalledProcessError:
            return []
        
        return artifacts


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
        self.libraries = []
        if self.path != "":
            self.version_extracted = self.version_extraction()
            self.version_found = self.version_lookup()
            self.libraries = self.dynamic_linked_libraries()
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
        label += f"- Libraries: {self.libraries}\n"
        log.output(label)

    def owner_print(self, identation="| |"):
        label = ""
        label += identation + f"-<{self.name}>\n"
        label += identation + f" |-Path: {self.path}\n"
        label += identation + f" |-Cert: {self.cert}\n"
        label += identation + f" |-SHA256: {self.sha}\n"
        label += identation + f" |-Possible versions: {self.version_found}\n"
        return label