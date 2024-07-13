import logging

from impacket.examples.secretsdump import LocalOperations, SAMHashes, LSASecrets


def dump(sam, system, security):
    logging.getLogger().setLevel(logging.INFO)

    local_ops = LocalOperations(system)
    boot_key = local_ops.getBootKey()
    sam_hashes = SAMHashes(sam, boot_key)
    lsa_secrets = LSASecrets(security, boot_key)
    print("="*10+"SAM"+"="*10)
    sam_hashes.dump()
    print("=" * 10 + "CHACHED CREDS" + "=" * 10)
    lsa_secrets.dumpCachedHashes()
    print("=" * 10 + "SECRETS" + "=" * 10)
    lsa_secrets.dumpSecrets()

    sam_hashes.finish()
    lsa_secrets.finish()
