from pytss import tspi_defines
import pytss
from pytss import *
import pytss.tspi_exceptions as tspi_exceptions
import uuid
from pytss.tspi_defines import *
import binascii

import os.path
import struct

#from tspi_defines import *
#import interface
#from interface import tss_lib
#help(pytss)
srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
old_uuid = uuid.UUID('{10000000-0000-0000-0000-000000000001}')
new_uuid = uuid.UUID('{20000000-0000-0000-0000-000000000001}')
masterKeyFilePath= "masterkey"

keyFlags =  TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE

srkSecret = bytearray([0] * 20)
def idxToUUID(idx):
    return uuid.UUID('{'+str(idx).zfill(8)+'-0000-0000-0000-000000000001}')

def take_ownership(context):
    """Take ownership of a TPM
    :param context: The TSS context to use
    :returns: True on ownership being taken, False if the TPM is already owned
    """

    tpm = context.get_tpm_object()
    tpmpolicy = tpm.get_policy_object(TSS_POLICY_USAGE)
    tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, srkSecret)

    srk = context.create_rsa_key(TSS_KEY_TSP_SRK | TSS_KEY_AUTHORIZATION)
    srkpolicy = srk.get_policy_object(TSS_POLICY_USAGE)
    srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, srkSecret)

    try:
        tpm.take_ownership(srk)
    except tspi_exceptions.TPM_E_DISABLED_CMD:
        return False

    return True

def getSrkKey(context):
    srk= context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)
    srkpolicy = srk.get_policy_object(TSS_POLICY_USAGE)
    srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, srkSecret)
    return srk

def getMasterkeyNumberArray():
    #return "MASTERKEY"
    return [77, 65, 83, 84, 69, 82, 75, 69, 89]
def getMasterkeyNumberArrayOne():
    #return "MASTERKEY1"
    return [77, 65, 83, 84, 69, 82, 75, 69, 89,49]
def clearKeys(context):
    try:
        k1 = context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM,old_uuid)
        k1.unregisterKey()
        k2 = context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM,new_uuid)
        k2.unregisterKey()
    except:
        pass

def get_current_key(idx,context=None):
    if context is None:
      context=TspiContext()
      context.connect()
    take_ownership(context)
    srk = getSrkKey(context)
    k= context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM,idxToUUID(idx))
    return k

def get_new_key_and_replace_current(idx,context=None,first_run=False):
    if context is None:
      context=TspiContext()
      context.connect()
    take_ownership(context)
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

'''
#define TSS_TPMCAP_PROP_MAXNVAVAILABLE      (0x2d)
#define TSS_TPMCAP_PROP_INPUTBUFFERSIZE     (0x2e)
'''
def get_registered_keys(context=None):
    if context is None:
      context=TspiContext()
      context.connect()
    take_ownership(context)
    keys=context.list_keys()
    keys.remove(str(srk_uuid))
    indexes=[]
    #print("ks:{}".format(keys))
    for k in keys:
      #cut away leading 0
      indexes.append(str(int(k.split("-")[0])))
    #print(indexes)
    return indexes
def is_key_registered_to_idx(idx):
    return str(idx) in get_registered_keys()
def get_status():
    context=TspiContext()
    context.connect()
    take_ownership(context)
    srk = getSrkKey(context)
    tpm = context.get_tpm_object()
    #get_new_key_and_replace_current(10,context,True)
    versionInfo = binascii.b2a_qp(tpm.get_capability(tss_lib.TSS_TPMCAP_VERSION_VAL,0)).decode("ascii").split("=")
    #print(versionInfo)
    #chipVer=binascii.hexlify(versionInfo[5:6]).decode("utf-8")
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

    #print("{}".format(nvIndices))

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
    return statusStr
def demo():
    print("Hi from Python-TPM interface!")
    print("establishing connection to TPM")
    context=TspiContext()
    context.connect()
    take_ownership(context)
    srk = getSrkKey(context)
    tpm = context.get_tpm_object()
    #get_new_key_and_replace_current(10,context,True)
    versionInfo = binascii.b2a_qp(tpm.get_capability(tss_lib.TSS_TPMCAP_VERSION_VAL,0)).decode("ascii").split("=")
    #print(versionInfo)
    #chipVer=binascii.hexlify(versionInfo[5:6]).decode("utf-8")
    chipVer=".".join(versionInfo[2:7])
    specLvl=versionInfo[7]
    vendor=versionInfo[8]
    print("ChipVersion={},SpecLevel={},SpecRevision={},Vendor={}".format(chipVer,specLvl,vendor[0:2],vendor[2:]))     
    tpmver=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_VERSION,0)).decode("ascii")
    manufactInfo=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROP_MANUFACTURER,tss_lib.TSS_TCSCAP_PROP_MANUFACTURER_STR)).decode("ascii")
    print("TPMVer={},ManufacturInfo={}".format(tpmver,manufactInfo)) 

    maxkeyslots = binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,tss_lib.TSS_TPMCAP_PROP_SLOTS)).decode("ascii")
    maxKeys=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,tss_lib.TSS_TPMCAP_PROP_MAXKEYS)).decode("ascii")
    maxSess=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,tss_lib.TSS_TPMCAP_PROP_MAXSESSIONS)).decode("ascii")
    maxContexts=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,tss_lib.TSS_TPMCAP_PROP_MAXCONTEXTS)).decode("ascii")
    maxInputBuffer=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,tss_lib.TSS_TPMCAP_PROP_INPUTBUFFERSIZE)).decode("ascii")
    maxNVavail=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,tss_lib.TSS_TPMCAP_PROP_MAXNVAVAILABLE)).decode("ascii")
    print("KeySlots={},MaxKeys={},MaxSess={},MaxContexts={},InputBufferSize={},MaxNVSpace={}".format(maxkeyslots,maxKeys,maxSess,maxContexts,maxInputBuffer,maxNVavail))
    
    #nvIndices=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_NV_LIST,0)).decode("ascii")

    #print("{}".format(nvIndices))

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
    print("algs: rsa={},des={},3des={},sha={},hmac={},aes128={},mgf1={},aes192={},aes256={},xor={},aes={}".format(algsrsa,algsdes,algs3des,algssha,algshmac,algsaes128,algsmgf1,algsaes192,algsaes256,algsxor,algsaes))
    flags=binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_FLAG,0)).decode("ascii")
    print("Flags={}".format(flags))

    #print("version info {}".format(binascii.hexlify(tpm.get_capability(tss_lib.TSS_TPMCAP_VERSION_VAL,[tss_lib.TSS_TPMCAP_PROP_SLOTS]))))

    #print("version info {}".format())
    #print("version info {}".format((tpm.get_capability(tss_lib.TSS_TPMCAP_VERSION_VAL,[tss_lib.TSS_TPMCAP_PROP_SLOTS]))[2:6]))
    

    #keyslots = tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,[tss_lib.TSS_TPMCAP_PROP_MAXNVAVAILABLE])
    #keyslots = tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,[tss_lib.TSS_TPMCAP_PROP_INPUTBUFFERSIZE])
    #keyslots = tpm.get_capability(tss_lib.TSS_TPMCAP_NV_LIST,[tss_lib.TSS_TPMCAP_PROP_SLOTS])


#[tss_lib.TSS_TPMCAP_PROP_SLOTS])
    #print("slots: {}".format(keyslots))
    #print("blaa:"+struct.unpack(keyslots))

    '''
    print("connected/logged in to TPM")
    mk=getMasterkeyNumberArray()
    print("master key={}".format(str(mk)))
    #clearKeys(context)

    print("currently registered key uuids: "+str(get_registered_keys(context)))
    idx="1"
    if(idx in get_registered_keys(context)):
      print("removed registered key with idx "+str(idx))
      k=get_current_key(idx,context)      
      k.unregisterKey()
      print("currently registered key uuids: "+str(get_registered_keys(context)))

    print("generating/storing deletable key with idx="+str(1))
    dk=get_new_key_and_replace_current(idx,context,first_run=True)
    print("deleteable key:\ndk={}".format(binascii.hexlify(dk.get_keyblob())))
    encry = dk.bind(mk)
    print("encrypted master key:\nmk={}".format(binascii.hexlify(encry)))
    print("unencrypted master key={}".format(dk.unbind(encry)))
    print("Got a secure delete request! Key-Cascade rebuilt, generatink new mk")
    mkk=getMasterkeyNumberArrayOne()
    print("new master key={}".format(mkk))
    print("exchanging dk")
    dkk=get_new_key_and_replace_current(idx,context,first_run=False)
    print("new deletable key:\ndk={}".format(binascii.hexlify(dkk.get_keyblob())))
    encry = dkk.bind(mkk) 
    print("new encrypted masterkey:\nmk={}".format(binascii.hexlify(encry)))
    print("new unencrypted mk={}".format(dkk.unbind(encry)))
    print("Done!")'''




    #keyslots = tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,[tss_lib.TSS_TPMCAP_PROP_SLOTS])
    #keyslots = tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,[tss_lib.TSS_TPMCAP_PROP_MAXNVAVAILABLE])
    #keyslots = tpm.get_capability(tss_lib.TSS_TPMCAP_PROPERTY,[tss_lib.TSS_TPMCAP_PROP_INPUTBUFFERSIZE])
    #keyslots = tpm.get_capability(tss_lib.TSS_TPMCAP_NV_LIST,[tss_lib.TSS_TPMCAP_PROP_SLOTS])


#[tss_lib.TSS_TPMCAP_PROP_SLOTS])
    #print("slots: {}".format(keyslots))
    #print("blaa:"+struct.unpack(keyslots))
#clearKeys()
#demo()
print("status: "+get_status())
'''
k=get_current_key()
k2=get_new_key_and_replace_current()
k3=get_new_key_and_replace_current()
'''
'''
MKencrypted=True
if not os.path.isfile(masterKeyFilePath):
    MKencrypted=False

if MKencrypted:
    #exchange keys: assumption old_uuid key exists, new_uuid key does not exist. oldkey encrypted masterkeyFile
    kOld=context.load_key_by_uuid(tss_lib.TSS_PS_TYPE_SYSTEM,old_uuid)
    kNew=context.create_wrap_key(keyFlags,srk.get_handle())
    with open(masterKeyFilePath, 'rb+') as f:
        encryptedData = bytearray(f.read())
        f.seek(0)
        #print("data: "+kOld.unbind(encryptedData))
        kNew.registerKey(new_uuid,srk_uuid)
        f.write(kNew.bind(kOld.unbind(encryptedData)))
        f.truncate()
    kOld.unregisterKey()
    kNew.registerKey(old_uuid,srk_uuid)
    kNew.unregisterKey(new_uuid)
    #kNew.loadkey if you want to use it further
else:
    #encrypt and save
    k=context.create_wrap_key(keyFlags,srk.get_handle())
    k.load_key()
    k.registerKey(old_uuid,srk_uuid)
    with open(masterKeyFilePath, 'wb') as f:
        f.write(k.bind(getMasterkeyNumberArray()))
'''
