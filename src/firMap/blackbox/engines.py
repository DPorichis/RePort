from abc import ABC, abstractmethod
import subprocess
import sys
import xml.etree.ElementTree as ET
from firMap.blackbox.scan import *
from firMap.utils import Logger

log = Logger("Blackbox Monitor")

class MappingEngine(ABC):
    """
    Base class for network mapping engines (like Nmap or custom tools).
    """
    
    # Key = user option, value = actual flag for the engine
    flag_mapping = {"default": " "}

    def __init__(self, reportStruct=None, ip=''):
        if(reportStruct == None):
            self.reportStruct = BlackBoxScan(ip)

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
    def parser(self, scan_result):
        """
        Parser for the execution of a scan, converting the run results to a BlackBoxScan instance inside the class.
        """
        pass

    @abstractmethod
    def scan(self, ip, options):
        """
        Run a scan on the given target IP.
        """
        pass

def list_all_engines():
    log.output("Available engines:")
    for engine_cls in MappingEngine.__subclasses__():
        engine = engine_cls()
        log.output(f" - {engine.name()} [modes available: {', '.join(engine.flag_mapping.keys())}]")

def get_engine_by_name(name):
    for engine_cls in MappingEngine.__subclasses__():
        engine = engine_cls()
        if engine.name().lower() == name.lower():
            return engine
    return None


# Nmap

class NmapEngine(MappingEngine):

    flag_mapping = {"advanced": "-sV", "default": " "}

    def name(self):
        return "nmap"

    def parser(self, scan_result):

        # Find all <port> elements
        root = ET.fromstring(scan_result)
        for port_tag in root.findall('.//port'):
            protocol = port_tag.get('protocol')
            port = port_tag.get('portid')

            state_tag = port_tag.find('state')
            service_tag = port_tag.find('service')

            state = state_tag.get('state') 
            service = service_tag.get('name')
            conf = service_tag.get('conf')
            log.output(f"Protocol: {protocol}, Port ID: {port}, State: {state}, Service: {service} [confidence {conf}]")
            self.reportStruct.add_port(port=int(port), protocol=protocol, service=service, state=state, conf=int(conf), engine=self.name())
        
        return self.reportStruct

    def scan(self, ip=None, options='default'):
        export_to_xml = '-oX -'
        command = ['nmap'] + export_to_xml.split()
        mapped_option = self.flag_mapping.get(options)
        if mapped_option:
            command += mapped_option.split()
        else:
            log.message("warn", f"Unknown option: {options}. Using default scan.", file=sys.stderr)
        if ip == None:
            ip = self.reportStruct.ip_address
        command += [ip]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return self.parser(result.stdout)
        except subprocess.CalledProcessError as e:
            return f"Error: {e.stderr}"
