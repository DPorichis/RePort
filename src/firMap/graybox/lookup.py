from firMap.graybox.engines import *
from firMap.graybox.scan import *
import json

PATH_TO_GRYPE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "engines", "grype")
)

log = Logger("Graybox Monitor")

class CveLookup:
    # Enrich the given report struct with the CVEs found
    def run_grype_on_directory(grayboxscan:GrayBoxScan):

        fs_path = os.path.join(grayboxscan.report_path, "fs")

        if not os.path.isdir(fs_path):
            raise ValueError(f"Provided path is not a directory: {fs_path}")

        # Build the grype command (using 'dir:' to scan a directory)
        command = [PATH_TO_GRYPE, f"dir:{fs_path}", "-o", "json"]

        try:
            # Run the command and capture output
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            json_output = result.stdout

            grype_output = os.path.join(grayboxscan.report_path, "grype_report.json")
            with open(grype_output, "w") as f:
                f.write(json_output)
            print(f"Results saved to {grype_output}")
            
            grype_data = json.loads(json_output)

            for match in grype_data["matches"]:
                item = {}
                item["artifact"] = match["artifact"]["name"] + " " + match["artifact"]["version"]
                item["cve_code"] = match["vulnerability"]["id"]
                item["sevirity"] = match["vulnerability"]["severity"]
                item["url"] = match["vulnerability"]["dataSource"]
                item["desc"] = match["vulnerability"]["description"]

                for location in match["artifact"]["locations"]:
                    path_to_binary = location["path"].lstrip("/")
                    path = os.path.join(fs_path, path_to_binary)
                    if path not in grayboxscan.port_activity.binary_report.keys():
                        grayboxscan.port_activity.binary_report[path] = {"pids": set(),
                                                                        "access": set(),
                                                                        "owns": set(),
                                                                        "CVEs": []}
                    grayboxscan.port_activity.binary_report[path]["CVEs"].append(item)
            return json_output

        except subprocess.CalledProcessError as e:
            print(f"Error running Grype: {e.stderr}", file=sys.stderr)
            sys.exit(1)
    
    def print_cve(cve_list:list):
        label = ""
        label += f"- {len(cve_list)} CVEs found\n"
        for item in cve_list:
            label += f"  -{item["cve_code"]} - {item["sevirity"]} - {item["url"]}\n"
        log.output(label)
        
