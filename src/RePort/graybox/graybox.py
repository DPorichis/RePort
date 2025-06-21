from RePort.graybox.engines import *
from RePort.graybox.scan import *
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
            log.message("info", f"No engine named '{args.engine}' was found - See available engines by using the -le flag", "-engine-help")
            return
        else:
            log.output(help_engine.help())
    
    if args.firmware is None:

        log.message("info", "No firmware path given, demo will be run")
        firmware = "/home/porichis/dit-thesis/DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip"
    else:
        firmware = args.firmware


    
    engine = FirmAE(firmware=firmware)
    if args.engine is not None:
        engine = get_engine_by_name(args.engine, firmware=firmware)
        if engine is None:
            log.message("info", f"No engine named '{args.engine}' was found - See available engines by using the -le flag", "-engine-help")
            return
    else:
        log.message("info", "No Engine specified, FirmAE will be used")
        
    opt = 'default'
    if args.engine_mode:
        opt = args.engine_mode3

    if args.cleanup:
        log.message("warn", "Performing Engine Cleanup", engine.name())
        engine.clean_up()
        return

    if args.network_fix:
        log.message("warn", "Performing Network Fix", engine.name())
        engine.network_fix()
        return

    log.message("info", "Initial systemcall tracking started")
    output = engine.check()

    log.message("info", "Emulated port verification started")
    engine.emulate()
    log.message("info", "Nmap analysis on given target started")
    engine.verification()
    engine.terminate()
    engine.result_output()

    Logger.generate_graybox_report(engine, engine.reportStruct)

    log.output(output)


def blackbox_help():
    log.output("Jim didn't write the help page :(")
    return


def graybox_install():
    install_all_engines()
    return