from angr.sim_type import SimStruct, SimTypeShort, SimTypeInt
import subprocess
import argparse
import claripy
import angr
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
    # TODO: Possible use of LLMs to access likelyhood of the given number being an actual port

    # Implementation for now:

    # Check if context has any reference to the word PORT
    ports = set()

    for item in possible_ports:
        if "port" in item["context"].lower():    
            ports.add(item["port"])

    return ports

def scan_elf_files(file_list):
    for file in file_list:

        BINARY_PATH = file
        print(f"Scanning: {BINARY_PATH}")
        project = angr.Project(BINARY_PATH, auto_load_libs=False)

        # Create the CFG
        cfg = project.analyses.CFGFast()


        # Check the architecture to figure out first argument passing
        if project.arch.name == "AMD64":
            arg_register = "rdi"  # First argument in AMD x64
            port_register = "rsi" # Second argument
        elif project.arch.name == "X86":
            arg_register = "eax"  # First argument in x86
            port_register = "ebx"  # Second argument (stack)
        elif project.arch.name.startswith("ARM"):
            if project.arch.name == "AArch64":  # 64-bit ARM
                arg_register = "x0"  # First argument
                port_register = "x1"  # Second argument
            else:  # AArch32 (32-bit ARM)
                arg_register = "r0"  # First argument 
                port_register = "r1"  # Second argument        
        else:
            print(f"Unsupported architecture [for now >:)]: {project.arch.name}")
            continue

        # Get addresses of relevant functions
        htons_addr = project.loader.main_object.plt.get("htons", None)
        bind_addr = project.loader.main_object.plt.get("bind", None)

        if not htons_addr:
            print("htons() not found in PLT, skipping")
        else:
            # Track calls to htons()
            call_sites = []
            for func in cfg.kb.functions.values():
                for block in func.blocks:
                    if htons_addr in block.instruction_addrs:
                        call_sites.append(block.addr)

            if not call_sites:
                print("No direct calls to htons() found, skipping")
            else:
                print(f"htons() calls found at: {[hex(addr) for addr in call_sites]}")
                # for addr in call_sites:
                #     # Static Execution try, (not working)
                #     state = project.factory.entry_state()
                #     simgr = project.factory.simgr(state)
                    
                #     # Try reaching the htons function
                #     simgr.explore(find=addr)

                #     if(simgr.found):
                #         print(f"Breakpoint reached.")
                #         call_state = simgr.found[0]
                        
                #         # Get port argument
                #         port_values = state.solver.eval(call_state.regs.__getattr__(arg_register))
                #         port_host_order = port_values  # htons() converts host -> network, so use directly

                #         print(f"Possible Ports: {port_host_order}")

                # If we have results from htons, don't go after binds
                continue

        if not bind_addr:
            print("bind() not found in PLT, skipping")
            continue
        else:
            # Track calls to bind()
            call_sites = []
            for func in cfg.kb.functions.values():
                for block in func.blocks:
                    if bind_addr in block.instruction_addrs:
                        call_sites.append(block.addr)

            if not call_sites:
                print("No direct calls to bind() found, skipping")
            else:
                print(f"bind() calls found at: {[hex(addr) for addr in call_sites]}")

                # Simulate the sockaddr struct
                sockaddr_struct = SimStruct(
                    {
                        "sin_family": SimTypeShort(),   # 2 bytes for IPvX flag
                        "sin_port": SimTypeShort(),     # 2 bytes for the port number
                        "sin_addr": SimTypeInt(),       # !! Protocol Specific (Not currently used, just ignore) !!
                    },
                    name="sockaddr",
                )

                # ports = set()
                # for addr in call_sites:
                #     # Static Execution try, (not working)
                #     state = project.factory.entry_state()
                #     simgr = project.factory.simgr(state)

                #     simgr.explore(find=addr)

                #     if simgr.found:
                #         found_state = simgr.found[0]                        
                #         sockaddr_ptr = state.solver.eval(found_state.regs.__getattr__(arg_register))

                #         sockaddr_data = found_state.memory.load(sockaddr_ptr, sockaddr_struct.size)
                #         sin_port = found_state.solver.eval(found_state.memory.load(sockaddr_ptr + 2, 2))  # sin_port is at offset 2

                #         # Swap for correct endianness
                #         sin_port = ((sin_port & 0xFF) << 8) | (sin_port >> 8)
                #         ports.add(sin_port)

                # print(f"Opened ports: {sorted(ports)}" if ports else "No open ports found.")
    
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
                    # That have htons used htons in them
                    if any(word in result.stdout for word in ['htons', 'bind']):
                        elf_files.append(item["Analysis"]["file_path"])
                except Exception as e:
                    print(f"Re auto xalase {file}: {e}")
    
    print("--- Key Files Found ---")
    print(f"Network related ELF files: {len(elf_files)}")
    print(f"Configuration files: {len(config_files)}")
    print("-----------------------")

    config_ports = scan_config_files(config_files)
    print(f"Ports found in the config files: {config_ports}")

    # scan_elf_files(elf_files)

    return



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run binwalk on a given binary file.")
    parser.add_argument("file", help="Path to the binary file")
    args = parser.parse_args()
    
    extract_firmware(args.file)
    export_json = f"./temp_{os.path.basename(args.file)}/structure.json"
    # print(export_json)

    scan_ports(export_json)


