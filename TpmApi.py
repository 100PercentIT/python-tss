from pytss import tspi_defines
import pytss
from pytss import *
import pytss.tspi_exceptions as tspi_exceptions
import uuid
from pytss.tspi_defines import *
import binascii

srk_uuid    = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
keyFlags    =  TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE
srkSecret   = bytearray([0] * 20)
ownerSecret = bytearray([0] * 20)

def idxToUUID(idx):
    return uuid.UUID('{'+str(idx).zfill(8)+'-0000-0000-0000-000000000001}')

def getSrkKey(context):
    srk= context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)
    srkpolicy = srk.get_policy_object(TSS_POLICY_USAGE)
    srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, srkSecret)
    return srk

def getMasterkeyNumberArray():
    return [77, 65, 83, 84, 69, 82, 75, 69, 89]

def getMasterkeyNumberArrayOne():
    return [77, 65, 83, 84, 69, 82, 75, 69, 89,49]

def clearKeys(context):
    try:
        k1 = context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM,old_uuid)
        k1.unregisterKey()
        k2 = context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM,new_uuid)
        k2.unregisterKey()
    except:
        pass

def get_current_key(idx):
    context=TspiContext()
    context.connect()
    srk = getSrkKey(context)
    k= context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM,idxToUUID(idx))
    return k

def get_new_key_and_replace_current(idx,first_run=False):

    context=TspiContext()
    context.connect()
    srk = getSrkKey(context)

    if first_run==True:
        k=context.create_wrap_key(keyFlags,srk.get_handle())
        k.load_key()
        k.registerKey(idxToUUID(idx),srk_uuid)
        return k
    else:
        kOld=context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM,idxToUUID(idx))
        kNew=context.create_wrap_key(keyFlags,srk.get_handle())
        kOld.unregisterKey()
        kNew.registerKey(idxToUUID(idx),srk_uuid)
        kNew.load_key()
        return kNew

def get_registered_keys():

    context=TspiContext()
    context.connect()
    keys=context.list_keys()
    keys.remove(str(srk_uuid))
    indexes=[]
    for k in keys:
      #cut away leading 0
      indexes.append(str(int(k.split("-")[0])))
    return indexes

def is_key_registered_to_idx(idx):
    return str(idx) in get_registered_keys()

def get_status():
    context=TspiContext()
    context.connect()
    take_ownership(context)
    srk = getSrkKey(context)
    tpm = context.get_tpm_object()
    versionInfo = binascii.b2a_qp(tpm.get_capability(tss_lib.TSS_TPMCAP_VERSION_VAL,0)).decode("ascii").split("=")
    chipVer=".".join(versionInfo[2:7])
    specLvl=versionInfo[7]
    vendor=versionInfo[8]
    statusStr=""
    statusStr+=("ChipVersion={},SpecLevel={},SpecRevision={},Vendor={}".format(chipVer,specLvl,vendor[0:2],vendor[2:]))     
    tpmver=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_VERSION,0)).decode("ascii")
    manufactInfo=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROP_MANUFACTURER,tss_lib.TSS_TCSCAP_PROP_MANUFACTURER_STR)).decode("ascii")
    statusStr+=(",TPMVer={},ManufacturInfo={}".format(tpmver,manufactInfo)) 

    maxkeyslots = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,tss_lib.TSS_TPMCAP_PROP_SLOTS)).decode("ascii")
    maxKeys=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,tss_lib.TSS_TPMCAP_PROP_MAXKEYS)).decode("ascii")
    maxSess=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,tss_lib.TSS_TPMCAP_PROP_MAXSESSIONS)).decode("ascii")
    maxContexts=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,tss_lib.TSS_TPMCAP_PROP_MAXCONTEXTS)).decode("ascii")
    maxInputBuffer=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,tss_lib.TSS_TPMCAP_PROP_INPUTBUFFERSIZE)).decode("ascii")
    maxNVavail=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,tss_lib.TSS_TPMCAP_PROP_MAXNVAVAILABLE)).decode("ascii")
    statusStr+=(",KeySlots={},MaxKeys={},MaxSess={},MaxContexts={},InputBufferSize={},MaxNVSpace={}".format(maxkeyslots,maxKeys,maxSess,maxContexts,maxInputBuffer,maxNVavail))
    
    #nvIndices=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_NV_LIST,0)).decode("ascii")
    algsrsa=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG,tss_lib.TSS_ALG_RSA)).decode("ascii")
    algsdes=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG,tss_lib.TSS_ALG_DES)).decode("ascii")
    algs3des=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG,tss_lib.TSS_ALG_3DES)).decode("ascii")
    algssha=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG,tss_lib.TSS_ALG_SHA)).decode("ascii")
    #algssha256=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG,tss_lib.TSS_ALG_SHA256)).decode("ascii")
    algshmac=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG,tss_lib.TSS_ALG_HMAC)).decode("ascii")
    algsaes128=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG,tss_lib.TSS_ALG_AES128)).decode("ascii")
    algsmgf1=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG,tss_lib.TSS_ALG_MGF1)).decode("ascii")
    algsaes192=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG,tss_lib.TSS_ALG_AES192)).decode("ascii")
    algsaes256=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG,tss_lib.TSS_ALG_AES256)).decode("ascii")
    algsxor=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG,tss_lib.TSS_ALG_XOR)).decode("ascii")
    algsaes=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_ALG,tss_lib.TSS_ALG_AES)).decode("ascii")
    statusStr+=(",RSA={},DES={},3DES={},SHA-1={},HMAC={},AES128={},MGF1={},AES192={},AES256={},XOR={},AES={}".format(algsrsa,algsdes,algs3des,algssha,algshmac,algsaes128,algsmgf1,algsaes192,algsaes256,algsxor,algsaes))
    flags=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_FLAG,0)).decode("ascii")
    statusStr+=(",Flags={}".format(flags))
    statusStr+=",RegisteredKeys={}".format(get_registered_keys(context))
    return statusStr
