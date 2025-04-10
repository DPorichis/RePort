"""Class for storing relevant data from BlackBoxScans"""
class BlackBoxScan:
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.ports = {} # key = port_number, value = list of dicts with details

    def add_port(self, port, protocol="Unknown", service="Unknown", state="Unknown", engine="Not Specified"):
        if self.ports.get(port) is not None:
            self.ports[port].append({
                "protocol": protocol,
                "service": service,
                "state": state,
                "source": engine 
                })
        else:
            self.ports[port] = [{
                "protocol": protocol,
                "service": service,
                "state": state,
                "source": engine 
            }]