from pytss import tspi_defines
import pytss
from pytss import *
import pytss.tspi_exceptions as tspi_exceptions
from pytss.tspi_defines import *

srkSecret   = bytearray([0] * 20)
ownerSecret = bytearray([0] * 20)

def take_ownership():
    """Take ownership of a TPM
    :param context: The TSS context to use
    :returns: True on ownership being taken, False if the TPM is already owned
    """
    context=TspiContext()
    context.connect()
    tpm = context.get_tpm_object()
    tpmpolicy = tpm.get_policy_object(TSS_POLICY_USAGE)
    tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, srkSecret)

    srk = context.create_rsa_key(TSS_KEY_TSP_SRK | TSS_KEY_AUTHORIZATION)
    srkpolicy = srk.get_policy_object(TSS_POLICY_USAGE)
    srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, ownerSecret)

    try:
        tpm.take_ownership(srk)
    except tspi_exceptions.TPM_E_DISABLED_CMD:
        return False

    return True
