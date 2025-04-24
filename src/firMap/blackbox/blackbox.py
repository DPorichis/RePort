from firMap.blackbox.engines import *
from firMap.blackbox.scan import *
import sys
import subprocess

# Example usage
def blackbox(args):
    if args.le:
        list_all_engines()
        return
    
    if args.engine_help:
        help_engine = get_engine_by_name(args.engine_help)
        if help_engine is None:
            print(f"[!] Blackbox Monitor (-engine-help): No engine named '{args.engine}' was found - See available engines by using the -le flag", file=sys.stderr)
            return
        else:
            print(help_engine.help())
    
    engine = NmapEngine()
    if args.engine is not None:
        engine = get_engine_by_name(args.engine)
        if engine is None:
            print(f"[!] Blackbox Monitor: No engine named '{args.engine}' was found - See available engines by using the -le flag", file=sys.stderr)
            return
    else:
        print("[i] Blackbox Monitor: No Engine specified, Nmap will be used", file=sys.stderr)

    if args.ip is None:
        print("[i] Blackbox Monitor: No IP specified, will use 8.8.8.8 instead", file=sys.stderr)
        ip = "8.8.8.8"
    else:
        ip = args.ip

    opt = 'default'
    if args.engine_mode:
        opt = args.engine_mode

    output = engine.scan(ip=ip, options=opt)
    print(output)


def blackbox_help():
    print("Jim didn't write the help page :(")
    return