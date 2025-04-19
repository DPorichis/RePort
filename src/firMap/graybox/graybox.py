from graybox.engines import *
from graybox.scan import *
import sys
import subprocess

# Example usage
def graybox(args):
    if args.le:
        list_all_engines()
        return
    
    if args.engine_help:
        help_engine = get_engine_by_name(args.engine_help)
        if help_engine is None:
            print(f"[!] Graybox Monitor (-engine-help): No engine named '{args.engine}' was found - See available engines by using the -le flag", file=sys.stderr)
            return
        else:
            print(help_engine.help())
    
    engine = FirmAE()
    if args.engine is not None:
        engine = get_engine_by_name(args.engine)
        if engine is None:
            print(f"[!] Graybox Monitor: No engine named '{args.engine}' was found - See available engines by using the -le flag", file=sys.stderr)
            return
    else:
        print("[i] Graybox Monitor: No Engine specified, FirmAE will be used", file=sys.stderr)

    if args.firmware is None:
        print("[i] Graybox Monitor: No firmware path given, demo will be run", file=sys.stderr)
        firmware = "Den exw demo :("
    else:
        firmware = args.firmware

    opt = 'default'
    if args.engine_mode:
        opt = args.engine_mode

    output = engine.scan(firmware=firmware, options=opt)
    print(output)


def blackbox_help():
    print("Jim didn't write the help page :(")
    return