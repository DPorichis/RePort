from abc import ABC, abstractmethod
import subprocess
import xml.etree.ElementTree as ET
from blackbox.scan import *

class MappingEngine(ABC):
    """
    Base class for network mapping engines (like Nmap or custom tools).
    """
    
    # Key = user option, value = actual flag for the engine
    flag_mapping = {}

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
            output += f"   {option}: {flag}\n"
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

class NmapEngine(MappingEngine):

    flag_mapping = {"advanced": "-kati_cool"}

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
            print(f"Protocol: {protocol}, Port ID: {port}, State: {state}, Service: {service}")
            self.reportStruct.add_port(int(port), protocol, service, state, self.name())
        

        return self.reportStruct

    def scan(self, ip=None, options='-oX -'):
        if ip == None:
            ip = self.reportStruct.ip_address
        command = ['nmap'] + options.split() + [ip]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return self.parser(result.stdout)
        except subprocess.CalledProcessError as e:
            return f"Error: {e.stderr}"
