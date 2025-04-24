import sys

class Logger:

    def __init__ (self, monitor = 'FirMap Monitor', file=None):
        self.monitor = monitor
        self.file=None

    def log_message(self, type='info', message="This is a message", module=""):
        output = self.monitor
        if module != "":
            output += " (" + module + ")"
        output += ": " + message
        if (type=="info"):
            print(f'\033[1;34m[i] {output}\033[0m', file=sys.stderr)
        elif (type=="warn"):
            print(f'\033[1;38;5;208m[-] {output}\033[0m', file=sys.stderr)
        elif (type=="error"):
            print(f'\033[1;31m[!] {output}\033[0m', file=sys.stderr)