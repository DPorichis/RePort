import subprocess
import argparse
import json
import os
import re

def extract_firmware(file_path):
    folder_name = f"temp_{os.path.basename(file_path)}"  # Get just the filename
    os.makedirs(folder_name, exist_ok=True)  # Creates folder if it doesn't exist
    
    # Run Binwalk on the given firmware
    try:
        result = subprocess.run(["binwalk", "-eM", "-l", f"./{folder_name}/structure.json", "-d", f"./{folder_name}/extractions", file_path], check=True)
    except FileNotFoundError:
        print("Error: binwalk is not installed.")
        return
    except Exception as e:
        print(f"Binwalk produced the following errors: {e}")
        return
        
    # Read the json file containing its parts
    with open(f"./{folder_name}/structure.json", "r") as file:
        data = json.load(file)
    # print(data)


    # Extract files that weren't extracted
    for execution in data:
        for file in execution["Analysis"]["file_map"]:
            
            dir_path = execution["Analysis"]["file_path"]

            extract_path = f"{dir_path}.extracted"

            name = file["name"]        
            offset = file["offset"]
            size = file["size"]

            hex_string = f"{offset:X}"

            if os.path.exists(extract_path) and hex_string not in os.listdir(extract_path):
                os.makedirs(f"{extract_path}/{hex_string}", exist_ok=True)  # Creates folder if it doesn't exist
                result = subprocess.run(["dd", f"if={file_path}", f"of={extract_path}/{hex_string}/{name}", "bs=1", f"skip={offset}", f"count={size}"], check=True)
                
                # Perform specific actions based on the type of the file
                # if(name == "pe"):
                #     with open(f"{extract_path}/{hex_string}/dis.txt", "w") as d:
                #         result = subprocess.run(["objdump", "-D", f"{extract_path}/{hex_string}/{name}"], stdout=d, check=True)


def scan_config_files(file_list):
    
    # Regex for storing number with 2-5 digits
    port_regex = re.compile(r'(?<!\d)(\d{2,5})(?!\d)')
    
    # List for storing our artifacts
    possible_ports = []
    
    for file in file_list:
        try:
            with open(file, 'r', errors='ignore') as f:
                for line in f:
                    # Find numbers that can be ports
                    artifacts = port_regex.findall(line)
                    # And store them with their context for analysis
                    for item in artifacts:
                        possible_ports.append({"port": item, "context": line, "file": os.path.basename(file)})
        except Exception as e:
            print(f"Error while reading {file}: {e}")
    
    # Possible_ports now has all instances of 2-5 digit numbers with their context and file
    print(f"Possible ports: {possible_ports}")
    # TODO: Possible use of LLMs to access likelyhood of the given number being an actual port

    # Implementation for now:

    # Check if context has any reference to the word PORT
    ports = set()

    for item in possible_ports:
        if "port" in item["context"].lower():    
            ports.add(item["port"])

    return ports

def scan_elf_files(file_list):

    # Decompile each file and try to extract arguments passed to the network functions
    # ~~ Jim is experimenting with angr, he will paste something great here (Just you wait) ~~

    return



def scan_ports(json_path):

    with open(json_path, "r") as file:
        data = json.load(file)
    # print(data)

    elf_files = []
    config_files = []
    for item in data:
        # If it is a final text file
        if len(item["Analysis"]["file_map"]) == 0:
            # Check if it has a conf extension
            if(item["Analysis"]["file_path"].endswith(".conf")):
                config_files.append(item["Analysis"]["file_path"])
        # For files with relevant desc
        elif len(item["Analysis"]["file_map"]) == 1:
            # Check for elf files
            if(item["Analysis"]["file_map"][0]["name"] == "elf"):
                try:
                    result = subprocess.run(['readelf', '-s', item["Analysis"]["file_path"]], capture_output=True, text=True)
                    # That have network related calls imported in them
                    if any(word in result.stdout for word in ['bind', 'listen', 'accept', 'socket']):
                        elf_files.append(item["Analysis"]["file_path"])
                except Exception as e:
                    print(f"Re auto xalase {file}: {e}")
    
    print("--- Key Files Found ---")
    print(f"Network related ELF files: {len(elf_files)}")
    print(f"Configuration files: {len(config_files)}")
    print("-----------------------")

    config_ports = scan_config_files(config_files)
    print(f"Ports found in the config files: {config_ports}")

    scan_elf_files(elf_files)

    return



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Port analysis on a given binary file.")
    parser.add_argument("file", help="Path to the binary file")
    args = parser.parse_args()
    
    extract_firmware(args.file)
    export_json = f"./temp_{os.path.basename(args.file)}/structure.json"
    # print(export_json)

    scan_ports(export_json)


