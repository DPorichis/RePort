from firMap.graybox.engines import *
from firMap.graybox.scan import *
from ..utils import Logger
import sys
import subprocess

log = Logger("Graybox Monitor")

# Example usage
def graybox(args):
    if args.le:
        list_all_engines()
        return
    
    if args.engine_help:
        help_engine = get_engine_by_name(args.engine_help)
        if help_engine is None:
            log.log_message("info", f"No engine named '{args.engine}' was found - See available engines by using the -le flag", "-engine-help")
            return
        else:
            print(help_engine.help())
    
    if args.firmware is None:

        log.log_message("info", "No firmware path given, demo will be run")
        firmware = "/home/porichis/dit-thesis/DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip"
    else:
        firmware = args.firmware


    
    engine = FirmAE(firmware=firmware)
    if args.engine is not None:
        engine = get_engine_by_name(args.engine, firmware=firmware)
        if engine is None:
            log.log_message("info", f"No engine named '{args.engine}' was found - See available engines by using the -le flag", "-engine-help")
            return
    else:
        log.log_message("info", "No Engine specified, FirmAE will be used")
        
    opt = 'default'
    if args.engine_mode:
        opt = args.engine_mode3

    output = engine.check()
    print(output)


def blackbox_help():
    print("Jim didn't write the help page :(")
    return