from pytss import tspi_defines
import pytss
from pytss import *
import pytss.tspi_exceptions as tspi_exceptions
import uuid
from pytss.tspi_defines import *
import binascii

#from tspi_defines import *
#import interface
#from interface import tss_lib
#help(pytss)
srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
srkSecret = bytearray([0] * 20)
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

def exchangeMKWrap(oldKeyBinFile,dataList):
    newData=exchangeMasterKey(oldKeyBinFile,dataList)

    with open('newKey.bin', 'rb') as f:
        newkblob=bytearray(f.read())

    #exchange data with newData atomically, possible? or some critical section flag which is read on a crash restart
    currentData=newData
    with open(oldKeyBinFile, 'wb') as f:
        f.write(newkblob)
    return currentData

def exchangeMasterKey(oldKeyBinFile,dataList):
    context=TspiContext()
    context.connect()

    take_ownership(context)
    srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)

    srkpolicy = srk.get_policy_object(TSS_POLICY_USAGE)
    srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, srkSecret)


    flags =  TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE
    k=context.create_wrap_key(flags,srk.get_handle())
    k.load_key()
    with open('newKey.bin', 'wb') as f:
        f.write(k.get_keyblob())

    with open(oldKeyBinFile, 'rb') as f:
     oldkblob= bytearray(f.read())

    oldk=context.load_key_by_blob(srk, oldkblob)

    newDataList=[]
    for data in dataList:
        #TODO: load keys at each bind/unbind?
        #oldk=context.load_key_by_blob(srk, oldkblob)

        tmpClearData=oldk.unbind(data)
        print("clearData:"+str(tmpClearData))
        #k.load_key()
        newDataList.append(k.bind(tmpClearData))

    #with open(oldKeyBinFile, 'wb') as f:
        #f.write(k.get_keyblob())
    print("ko:"+binascii.hexlify(oldkblob))
    print("kn:"+binascii.hexlify(k.get_keyblob()))
    return newDataList
print("hi")
context=TspiContext()
context.connect()

take_ownership(context)
srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)

srkpolicy = srk.get_policy_object(TSS_POLICY_USAGE)
srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, srkSecret)


flags =  TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE
#hand= ffi.new(ctype)
#tss_lib.Tspi_Context_CreateObject(context, tss_type, flags, hand)
k=context.create_wrap_key(flags,srk.get_handle())

print("handle:"+str(k.get_handle()))


#kk=context.load_key_by_blob(srk, k.get_keyblob())
k.load_key()
dat=[0x61,0x62,0x63]
encdat = k.bind(dat)
#tss_lib.Tspi_Data_Bind()
print("encry:"+encdat)

decdat =k.unbind(encdat)
print("decry:"+decdat)

with open('somefile.bin', 'wb') as f:
    f.write(k.get_keyblob())

newk = None
with open('somefile.bin', 'rb') as f:
    newk= bytearray(f.read())
#print("k:"+binascii.hexlify(k.get_keyblob()))
#print("k:"+binascii.hexlify(newk))

kk=context.load_key_by_blob(srk, newk)
encdat = kk.bind(dat)
#tss_lib.Tspi_Data_Bind()
print("encry:"+encdat)

decdat =kk.unbind(encdat)
print("decrysds:"+decdat)

dataL=[kk.bind([0x61]),kk.bind([0x62]),kk.bind([0x63])]
print("dataL"+str(dataL))
dataL=exchangeMKWrap('somefile.bin',dataL)
print("dataL"+str(dataL))
print("=============================================1")
dataL=exchangeMKWrap('somefile.bin',dataL)
print("dataL"+str(dataL))
print("=============================================2")
dataL=exchangeMKWrap('somefile.bin',dataL)
print("dataL"+str(dataL))
print("=============================================3")


#print cap
#pytss.interface.Tspi_TPM_GetStatus(blaa.get_tpm_object(),1,1)
#print str(blaa.get_tpm_object())
#print dir(pytss.interface)
#print "blaa:"+str(pytss.interface.Tspi_TPM_GetStatus())
## 
#print dir(pytss)
