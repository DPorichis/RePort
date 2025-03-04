import subprocess
import argparse
import json
import os

def extract_firmware(file_path):
    folder_name = f"temp_{os.path.basename(file_path)}"  # Get just the filename
    os.makedirs(folder_name, exist_ok=True)  # Creates folder if it doesn't exist
    
    # Run Binwalk on the given firmware
    try:
        result = subprocess.run(["binwalk", "-eM", "-v", "-l", f"./{folder_name}/structure.json", "-d", f"./{folder_name}/extractions", file_path], check=True)
    except FileNotFoundError:
        print("Error: binwalk is not installed.")
        return
    except Exception as e:
        print(f"Binwalk produced the following errors: {e}")
        return
        
    # Read the json file containing its parts
    with open(f"./{folder_name}/structure.json", "r") as file:
        data = json.load(file)
    print(data)


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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run binwalk on a given binary file.")
    parser.add_argument("file", help="Path to the binary file")
    args = parser.parse_args()
    
    extract_firmware(args.file)
