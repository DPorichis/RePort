import argparse
from firMap.blackbox.blackbox import blackbox
from firMap.graybox.graybox import graybox

def main():
    parser = argparse.ArgumentParser(description="FirMap ~ Automatically Mapping the Attack Surface of System")
    
    scan_type_group = parser.add_mutually_exclusive_group()
    scan_type_group.add_argument('-black', action='store_true', help="Run Blackbox scan")
    scan_type_group.add_argument('-gray', action='store_true', help="Run Graybox scan")

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('-ip', type=str, help="Target IP to be scanned")
    input_group.add_argument('-firmware', type=str, help="Path to the firmware to be scanned")

    parser.add_argument('-le', action='store_true', help="Lists all engines available for the specified scan type")
    parser.add_argument('-cleanup', action='store_true', help="Removes all logs created by the specified engine, reseting functionality")
    parser.add_argument('-network-fix', action='store_true', help="Resets network that may have been left hanging")
    parser.add_argument('-engine', type=str, help="Selects engine to be used")
    parser.add_argument('-engine-mode', type=str, metavar='MODE', help="Selects on which mode the engine will be run")
    parser.add_argument('-engine-help', type=str, metavar='ENGINE', help="Prints the help text of the specified ENGINE")

    args = parser.parse_args()

    if args.black or not args.gray:
        blackbox(args)
    else:
        graybox(args)
        return

if __name__ == "__main__":
    main()