from abc import ABC, abstractmethod
import subprocess

class MappingEngine(ABC):
    """
    Base class for network mapping engines (like Nmap or custom tools).
    """
    
    # Key = user option, value = actual flag for the engine
    flag_mapping = {}

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
        Parser for the execution of a scan, converting the run results to a BlackBoxScan instance.
        """
        pass

    @abstractmethod
    def scan(self, IP, options):
        """
        Run a scan on the given target IP.
        """
        pass

class NmapEngine(MappingEngine):

    flag_mapping = {"advanced": "-kati_cool"}

    def name(self):
        return "nmap"

    def parser(self, scan_result):
        return "mmmmm parser!!!"

    def scan(self, IP, options=''):
        command = ['nmap'] + options.split() + [IP]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return self.parser(result.stdout)
        except subprocess.CalledProcessError as e:
            return f"Error: {e.stderr}"
