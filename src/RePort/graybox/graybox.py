from RePort.graybox.engines import *
from RePort.graybox.scan import *
from ..utils import Logger
import sys
import subprocess

log = Logger("Graybox Monitor")

DEMO_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip")


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
        firmware = DEMO_PATH
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

    # try:
    log.message("info", "Initial systemcall tracking started")
    output = engine.check()

        # log.message("info", "Emulated port confirmation started")
        # engine.emulate()
        # log.message("info", "Nmap analysis on given target started")
        # engine.confirmation()
        # engine.terminate()
    #     engine.result_output()
    # except Exception as e:
    #     log.message("error", f"An error occurred during the scan: {e}", engine.name())
    #     engine.reportStruct.result = "Failed"
    
    Logger.generate_graybox_report(engine, engine.reportStruct)

    log.output(f"Scan completed with result: {engine.reportStruct.result}")

    # Calculate stats    
    port_count = len(engine.reportStruct.port_activity.port_history)
    instances_count = 0

    for port in engine.reportStruct.port_activity.port_history.keys():
        instances_count += len(engine.reportStruct.port_activity.port_history[port]["instances"])
    

    cve_count = 0
    outward_count = 0
    binaries_with_cves = 0
    outward_count_with_cves = 0


    for binary in engine.reportStruct.port_activity.binary_report.keys():
        ccount = len(engine.reportStruct.port_activity.binary_report[binary]["CVEs"])
        ocount = len(engine.reportStruct.port_activity.binary_report[binary]["access"])
        if ccount > 0:
            binaries_with_cves += 1
            cve_count += ccount
        
        if ocount > 0:
            outward_count += 1
            if ccount > 0:
                outward_count_with_cves += 1
        
    log.output(f"Graybox Scan Summary:")
    log.output(f"{port_count} ports found, with {instances_count} instances")
    log.output(f"{outward_count} Outward Facing Binaries found")
    log.output(f"{cve_count} CVEs across {binaries_with_cves} binaries")    
    log.output(f"Outward Facing Binaries with CVEs: {outward_count_with_cves}")
    

    log.output(output)


def blackbox_help():
    log.output("Jim didn't write the help page :(")
    return


def graybox_install():
    install_all_engines()
    return