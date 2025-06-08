from RePort.blackbox.engines import *
from RePort.blackbox.scan import *
from RePort.utils import Logger
import sys
import subprocess

log = Logger("Blackbox Monitor")

# Example usage
def blackbox(args):
    if args.le:
        list_all_engines()
        return
    
    if args.engine_help:
        help_engine = get_engine_by_name(args.engine_help)
        if help_engine is None:
            log.message("error", "No engine named '{args.engine}' was found - See available engines by using the -le flag", "-engine-help")
            return
        else:
            log.output(help_engine.help())
    
    engine = NmapEngine()
    if args.engine is not None:
        engine = get_engine_by_name(args.engine)
        if engine is None:
            log.message("error", "No engine named '{args.engine}' was found - See available engines by using the -le flag", "-engine-help")
            return
    else:
        log.message("info", "No Engine specified, Nmap will be used")

    if args.ip is None:
        log.message("info", "No IP specified, will use 8.8.8.8 instead")
        ip = "8.8.8.8"
    else:
        ip = args.ip

    opt = 'default'
    if args.engine_mode:
        opt = args.engine_mode

    output = engine.scan(ip=ip, options=opt)
    log.output(output)


def blackbox_help():
    log.output("Jim didn't write the help page :(")
    return