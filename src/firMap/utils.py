import sys

class Logger:

    def __init__ (self, monitor = 'FirMap Monitor', log_file=None, output_file=None):
        self.monitor = monitor
        self.file = None
        self.log_file = log_file
        self.output_file = output_file

    def message(self, type='info', message="This is a message", module=""):
        output = self.monitor
        if module != "":
            output += " (" + module + ")"
        output += ": " + message
        if (type=="info"):
            output = "[i] " + output
            print(f'\033[1;34m{output}\033[0m', file=sys.stderr)
        elif (type=="warn"):
            output = "[-] " + output
            print(f'\033[1;38;5;208m{output}\033[0m', file=sys.stderr)
        elif (type=="error"):
            output = "[!] " + output
            print(f'\033[1;31m{output}\033[0m', file=sys.stderr)
        
        # Log to the file, when given
        if(self.log_file is not None):
            with open(self.log_file, "a") as f:
                print(output, file=f)


    def output(self, message):
        print(message)
        # Log to the file, when given
        if(self.output_file is not None):
            with open(self.log_file, "a") as f:
                print(message, file=f)