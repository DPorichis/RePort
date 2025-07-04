# from RePort.graybox.scan import GrayBoxScan
# from RePort.graybox.engines import EmulationEngines

from jinja2 import Template
import json
import sys
import os
class Logger:

    def __init__ (self, monitor = 'RePort Monitor', log_file=None, output_file=None):
        self.monitor = monitor
        self.file = None
        self.log_file = log_file
        self.output_file = output_file

    def message(self, type='info', message="This is a message", module=""):
        output = self.monitor
        if module != "":
            output += " (" + module + ")"
        output += ": " + message
        if (type=="info"):
            output = "[i] " + output
            print(f'\033[1;34m{output}\033[0m', file=sys.stderr)
        elif (type=="warn"):
            output = "[-] " + output
            print(f'\033[1;38;5;208m{output}\033[0m', file=sys.stderr)
        elif (type=="error"):
            output = "[!] " + output
            print(f'\033[1;31m{output}\033[0m', file=sys.stderr)
        
        # Log to the file, when given
        if(self.log_file is not None):
            with open(self.log_file, "a") as f:
                print(output, file=f)

    def output(self, message):
        print(message)
        # Log to the file, when given
        if(self.output_file is not None):
            with open(self.log_file, "a") as f:
                print(message, file=f)

    def generate_graybox_report(engine, graybox):
        
        port_activity = []

        for port in graybox.port_activity.port_history.keys():
            activity_list = []
            random_flag = False
            for instance in graybox.port_activity.port_history[port]["instances"]:
                item = {}
                item["binded_by"] = f"{instance["owner"][0]} ({instance["owner"][1]})"
                item["timeframe"] = f"{instance["times"][0]} - {instance["times"][1]}"
                item["type"] = instance["type"]
                item["family"] = instance["family"]
                if instance["random"] == True:
                    item["random"] = "random"
                else:   
                    item["random"] = "false"
                random_flag = instance["random"] or random_flag
                item["subproc"] = ""
                for proc in instance["access_history"]:
                    item["subproc"] += f" {proc} "
                activity_list.append(item)
            port_report = {}
            if random_flag == True:
                port_report["random"] = "random"
            else:   
                port_report["random"] = "false"
            port_report["port"] = port
            port_report["noi"] = len(activity_list)
            if "confirmation" in graybox.port_activity.port_history[port].keys() and graybox.port_activity.port_history[port]["confirmation"] is not None:
                print(graybox.port_activity.port_history[port]["confirmation"])
                port_report["confirmed"] = "true"    
            elif "END" not in activity_list[-1]["timeframe"]:
                port_report["confirmed"] = "NA"
            elif activity_list[-1]["type"] != "TCP":
                port_report["confirmed"] = "Unsupported"
            else:
                port_report["confirmed"] = "false"
            port_report["lpu"] = activity_list[-1]["type"]
            port_report["activity"] = activity_list
            port_activity.append(port_report)
                
        proc_activity = []
        for binary in graybox.port_activity.binary_report.keys():
            item = {}
            item["binary"] = os.path.basename(binary)
            item["path"] = binary
            item["noa"] = len(graybox.port_activity.binary_report[binary]["access"])
            item["noo"] = len(graybox.port_activity.binary_report[binary]["owns"])
            item["nop"] = len(graybox.port_activity.binary_report[binary]["pids"])
            item["noc"] = len(graybox.port_activity.binary_report[binary]["CVEs"])
            
            if item["noa"] == 0 and item["noo"] == 0:
                continue

            if item["noa"] == 0:
                item["access"] = "-"
            else:
                item["access"] = "" 
                for port in graybox.port_activity.binary_report[binary]["access"]:
                    item["access"] += f" {port} "
            
            if item["noo"] == 0:
                item["owns"] = "-"
            else:
                item["owns"] = "" 
                for port in graybox.port_activity.binary_report[binary]["owns"]:
                    item["owns"] += f" {port} "
            
            if item["nop"] == 0:
                item["pids"] = "-"
            else:
                item["pids"] = "" 
                for port in graybox.port_activity.binary_report[binary]["pids"]:
                    item["pids"] += f" {port} "

            if len(graybox.port_activity.binary_report[binary]["label"].libraries) == 0:
                item["libraries"] = "No Dynamically Linked Libraries"
            else:
                item["libraries"] = ""
                for lib in graybox.port_activity.binary_report[binary]["label"].libraries:
                    item["libraries"] += f" {lib} "
            proc_activity.append(item)
        
        cve_report = []
        for binary in graybox.port_activity.binary_report.keys():
            item = {}
            item["binary"] = os.path.basename(binary)
            item["path"] = binary
            item["noa"] = len(graybox.port_activity.binary_report[binary]["access"])
            item["noo"] = len(graybox.port_activity.binary_report[binary]["owns"])
            item["nop"] = len(graybox.port_activity.binary_report[binary]["pids"])
            item["noc"] = len(graybox.port_activity.binary_report[binary]["CVEs"])
            
            if item["noc"] == 0:
                continue
            
            activity_list = []
            for cve in graybox.port_activity.binary_report[binary]["CVEs"]:
                instance = {}
                instance["id"] = cve["cve_code"]
                instance["link"] = cve["url"]
                instance["rating"] = cve["sevirity"]
                instance["desc"] = cve["desc"]
                activity_list.append(instance)

            item["cves"] = activity_list
            cve_report.append(item)

        if graybox.black_confirmation is None:
            confirmation_engine = "Disabled"
        else:
            confirmation_engine = graybox.black_confirmation.name()


        # Example input data
        data = {
            "firmware_name": os.path.basename(graybox.firware_path),
            "mode": "Graybox Analysis",
            "md5_hash": graybox.md5_hash,
            "blackbox_engine": confirmation_engine,
            "result": graybox.result,
            "graybox_engine": engine.name(),
            "report_folder": os.path.basename(graybox.report_path),
            "cve_lookup": "Grype",
            "port_activity": port_activity,
            "proc_activity": proc_activity,
            "cve_report": cve_report
        }

        template_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "template.html")
        )

        report_path = os.path.join(graybox.report_path, "RePort.html")

        # Load the HTML template
        with open(template_path) as f:
            template_html = f.read()

        # Render template
        template = Template(template_html)
        rendered_html = template.render(data)

        # Output to file
        with open(report_path, "w") as f:
            f.write(rendered_html)

        print(f"Report generated as {report_path}'")