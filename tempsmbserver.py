# TempSMB offers an easy-to-use way to run a non-blocking SimpleSMBServer in an object-oriented pythonic manner.
# It adds a context manager offering a temporary share and cleans up after itself.
# Additionally, it offers an object-oriented approach to handle the temporary incoming and outgoing files inside the temporary share
# written by dotPY


import multiprocessing
import os
import shutil
import tempfile
import time

from impacket.smbserver import SimpleSMBServer


class TempSMB:
    def __init__(self, local_ip, share_name="legit", smb2=False):
        self.share_name = share_name
        self.local_ip = local_ip
        self.smb_dir = tempfile.mkdtemp()
        self.server = SimpleSMBServer(listenAddress=self.local_ip)
        self.server.setLogFile("")
        self.server.setSMB2Support(smb2)

        self._smb_files = {}
        self._server_process = None

    def __enter__(self):
        return self._enter()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._exit()

    def __getitem__(self, item):
        return self._smb_files[item]

    def __setitem__(self, key, value):
        self._smb_files[key] = value

    def start(self):
        self._enter()

    def stop(self):
        self._exit()

    def _enter(self):
        self.server.addShare(self.share_name, self.smb_dir)
        self._non_blocking()
        return self

    def _exit(self):
        try:
            self._stop_non_blocking()
        except AttributeError:
            print("Server already dead?")
        finally:
            shutil.rmtree(self.smb_dir)

    def _non_blocking(self):
        self._server_process = multiprocessing.Process(target=self.server.start)
        self._server_process.start()

    def _stop_non_blocking(self):
        self._server_process.terminate()
        self._server_process.join()
        self._server_process.close()
        self.server.stop()

    def create_temp_file(self, content, friendly_name=None, ext=""):
        smb_file = SMBFile(self, ext=ext, friendly_name=friendly_name)
        content = content if isinstance(content, bytes) else content.encode()
        with open(smb_file.local_path, "wb") as file:
            file.write(content)
        self.add_to_collection(smb_file)
        return smb_file

    def create_temp_file_from_file(self, existing_file, friendly_name=None):
        ext = os.path.splitext(existing_file)[-1]
        smb_file = SMBFile(self, ext=ext, friendly_name=friendly_name)
        shutil.copy(existing_file, smb_file.local_path)
        self.add_to_collection(smb_file)
        return smb_file

    def future_file(self, ext="", friendly_name=None):
        smb_file = SMBFile(self, ext=ext, friendly_name=friendly_name)
        self.add_to_collection(smb_file)
        return smb_file

    def connection_string(self):
        if self.local_ip == "0.0.0.0":
            print("0.0.0.0 wont work on remote!")
        return f"//{self.local_ip}/{self.share_name}/"

    def add_to_collection(self, smb_file):
        self[smb_file.friendly_name] = smb_file


class SMBFile:
    def __init__(self, smb_server_object, ext="", friendly_name=None):
        self.local_path = tempfile.mktemp(dir=smb_server_object.smb_dir, suffix=ext)
        self.base_name = os.path.basename(self.local_path)
        self.friendly_name = friendly_name if friendly_name else self.base_name
        self.remote_path = os.path.join(smb_server_object.connection_string(), self.base_name)
        self.remote_path_backslashes = self.remote_path.replace("/", "\\")
        self.remote_path_backslashes_double = self.remote_path.replace("/", "\\\\")

    def exists(self):
        return os.path.exists(self.local_path)

    def size(self):
        if self.exists():
            return os.stat(self.local_path).st_size
        return 0

    def await_me(self, timeout=None):
        start = time.time()
        previous_size = 0
        while not self.exists() or previous_size != self.size():
            previous_size = self.size()
            time.sleep(1)
            if timeout and time.time() - start > timeout:
                print("TIMED OUT - FILE WAS NOT FOUND!")
                return False
        return True

    def print(self, cringe_utf_16=False):
        with open(self.local_path, "rb") as file:
            content = file.read()
            if cringe_utf_16:
                content = content.replace(b"\xff\xfe", b"")
                content = content.replace(b"\x00", b"")
            print(content.decode())
