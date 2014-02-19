/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Yingdi Yu
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>

#include <iostream>

using namespace std;

void
checkUserInteraction()
{
  OSStatus res;
  Boolean allowInteraction;

  res = SecKeychainGetUserInteractionAllowed(&allowInteraction);
  cerr << "Allow Interaction: " << boolalpha << (allowInteraction == true) << endl;
}

void
checkKeychainStatus(SecKeychainRef keychain)
{
  OSStatus res;
  SecKeychainStatus keychainStatus;

  res = SecKeychainGetStatus (keychain, &keychainStatus);
  cerr << "Keychain Unlocked: " << boolalpha << ((kSecUnlockStateStatus & keychainStatus) != 0) << endl;
  cerr << "Keychain Readable: " << boolalpha << ((kSecReadPermStatus & keychainStatus) != 0) << endl;
  cerr << "Keychain Writable: " << boolalpha << ((kSecWritePermStatus & keychainStatus) != 0) << endl;
}

void
createKeyPair()
{
  OSStatus res;
  SecKeyRef publicKey, privateKey;
  int keySize = 2048;

  CFStringRef keyLabel = CFStringCreateWithCString (NULL, "keychain-locked-process-key", kCFStringEncodingUTF8);
  CFMutableDictionaryRef attrDict = CFDictionaryCreateMutable(NULL, 3, &kCFTypeDictionaryKeyCallBacks, NULL);
  CFDictionaryAddValue(attrDict, kSecAttrKeyType, kSecAttrKeyTypeRSA);
  CFDictionaryAddValue(attrDict, kSecAttrKeySizeInBits, CFNumberCreate(NULL, kCFNumberIntType, &keySize));
  CFDictionaryAddValue(attrDict, kSecAttrLabel, keyLabel);

  res = SecKeyGeneratePair(attrDict, &publicKey, &privateKey);
  
  cerr << "SecKeyGeneratePair res: " << res << endl;
}

void
deleteKeyPair()
{
  OSStatus res;

  CFStringRef keyLabel = CFStringCreateWithCString (NULL, "keychain-locked-process-key", kCFStringEncodingUTF8);
  CFMutableDictionaryRef attrDict = CFDictionaryCreateMutable(NULL, 4, &kCFTypeDictionaryKeyCallBacks, NULL);
  CFDictionaryAddValue(attrDict, kSecClass, kSecClassKey);
  CFDictionaryAddValue(attrDict, kSecAttrKeyType, kSecAttrKeyTypeRSA);
  CFDictionaryAddValue(attrDict, kSecAttrLabel, keyLabel);
  CFDictionaryAddValue(attrDict, kSecMatchLimit, kSecMatchLimitAll);

  res = SecItemDelete(attrDict);
  
  cerr << "SecItemDelete res: " << res << endl;
}

SecKeyRef
getPrivateKey()
{
  OSStatus res;
  SecKeyRef privateKey;

  CFStringRef keyLabel = CFStringCreateWithCString (NULL, "keychain-locked-process-key", kCFStringEncodingUTF8);    
  CFMutableDictionaryRef attrDict = CFDictionaryCreateMutable(NULL, 5, &kCFTypeDictionaryKeyCallBacks, NULL);
  CFDictionaryAddValue(attrDict, kSecClass, kSecClassKey);
  CFDictionaryAddValue(attrDict, kSecAttrLabel, keyLabel);
  CFDictionaryAddValue(attrDict, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
  CFDictionaryAddValue(attrDict, kSecReturnRef, kCFBooleanTrue);
    
  res = SecItemCopyMatching(attrDict, (CFTypeRef*)&privateKey);

  cerr << "SecItemCopyMatching res: " << res << endl;

  return privateKey;
}

void 
sign(SecKeyRef privateKey)
{
  CFErrorRef error;

  char data[10] = "encrypted";
  CFDataRef dataRef = CFDataCreateWithBytesNoCopy(NULL, reinterpret_cast<uint8_t*>(data), strlen(data), kCFAllocatorNull);

  SecTransformRef signer = SecSignTransformCreate(privateKey, &error);
  if (error)
    {
      CFShow (error);
      return;
    }

  SecTransformSetAttribute(signer, kSecTransformInputAttributeName, dataRef, &error);
  if (error)
    {
      CFShow (error);
      return;
    }

  SecTransformSetAttribute(signer, kSecPaddingKey, kSecPaddingPKCS1Key, &error);
  if (error)
    {
      CFShow (error);
      return;
    }

  SecTransformSetAttribute(signer, kSecDigestTypeAttribute, kSecDigestSHA2, &error);
  if (error)
    {
      CFShow (error);
      return;
    }

  long digestSize = 256;
  SecTransformSetAttribute(signer, kSecDigestLengthAttribute, CFNumberCreate(NULL, kCFNumberLongType, &digestSize), &error);
  if (error)
    {
      CFShow (error);
      return;
    }

  CFDataRef signature = (CFDataRef) SecTransformExecute(signer, &error);

  if (error) {
    CFShow(error);
    return;
  }
  
}

CFDataRef 
exportKey(SecKeyRef privateKey)
{
  CFDataRef exportedKey;
  OSStatus res;
  res = SecItemExport((SecKeychainItemRef)privateKey,
		      kSecFormatOpenSSL,
		      0,
		      NULL,
		      &exportedKey);

  cerr << "SecItemExport res: " << res << endl;
  
  return exportedKey;
}

void 
importKey(CFDataRef importedKey)
{
  OSStatus res;
  
  SecExternalFormat externalFormat = kSecFormatOpenSSL;

  SecExternalItemType externalType = kSecItemTypePrivateKey;

  SecKeyImportExportParameters keyParams;
  memset(&keyParams, 0, sizeof(keyParams));
  keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
  keyParams.keyAttributes = CSSM_KEYATTR_EXTRACTABLE | CSSM_KEYATTR_PERMANENT;
  SecAccessRef access;
  CFStringRef keyLabel = CFStringCreateWithCString (NULL, "keychain-locked-process-key", kCFStringEncodingUTF8);
  SecAccessCreate(keyLabel, NULL, &access);
  keyParams.accessRef = access;

  CFArrayRef outItems;

  SecKeychainRef keychainRef;
  SecKeychainCopyDefault(&keychainRef);

  res = SecKeychainItemImport (importedKey,
			       NULL,
			       &externalFormat,
			       &externalType,
			       0,
			       &keyParams,
			       keychainRef,
			       &outItems);

  cerr << "SecKeychainItemImport res: " << res << endl;

  if(res != errSecSuccess)
    return;

  SecKeychainItemRef privateKey = (SecKeychainItemRef)CFArrayGetValueAtIndex(outItems, 0);
  SecKeychainAttribute attrs[2]; // maximum number of attributes
  SecKeychainAttributeList attrList = { 0, attrs };
  string keyUri("keychain-locked-process-key");
  {
    attrs[attrList.count].tag = kSecKeyPrintName;
    attrs[attrList.count].length = keyUri.size();
    attrs[attrList.count].data = (void *)keyUri.c_str();
    attrList.count++;
  }
  
  res = SecKeychainItemModifyAttributesAndData(privateKey, 
                                               &attrList,
                                               0,
                                               NULL);
}

int main (int argc, char** argv)	
{
  OSStatus res;
  SecKeychainRef targetKeychain;
  SecKeychainRef originKeychain;
  
  checkUserInteraction ();
  res = SecKeychainSetUserInteractionAllowed (false);
  checkUserInteraction ();

  res = SecKeychainCreate ("example.keychain", 4, "1234", false, NULL, &targetKeychain);
  if(errSecDuplicateKeychain == res)
    res = SecKeychainOpen ("example.keychain", &targetKeychain);
  cerr << "Create/Open keychain res: " << res << endl;

  res = SecKeychainCopyDefault (&originKeychain);
  cerr << "Get default keychain res: " << res << endl;

  res = SecKeychainSetDefault (targetKeychain);
  cerr << "Set default keychain res: " << res << endl;

  checkKeychainStatus (targetKeychain);
  res = SecKeychainUnlock (targetKeychain, 4, "1234", true);
  checkKeychainStatus (targetKeychain);
  res = SecKeychainLock (targetKeychain);
  checkKeychainStatus (targetKeychain);  

  createKeyPair(); // Locked keychain, should fail

  res = SecKeychainUnlock (targetKeychain, 4, "1234", true);
  checkKeychainStatus (targetKeychain);

  createKeyPair(); 

  res = SecKeychainLock (targetKeychain);
  checkKeychainStatus (targetKeychain);

  SecKeyRef privateKey = getPrivateKey();
  sign(privateKey); // Locked keychain, should fail
  exportKey(privateKey); // Locked keychain, should fail

  res = SecKeychainUnlock (targetKeychain, 4, "1234", true);
  checkKeychainStatus (targetKeychain);

  sign(privateKey);
  CFDataRef exportedKey = exportKey(privateKey);

  deleteKeyPair();

  res = SecKeychainLock (targetKeychain);
  checkKeychainStatus (targetKeychain);

  importKey(exportedKey);

  res = SecKeychainUnlock (targetKeychain, 4, "1234", true);
  checkKeychainStatus (targetKeychain);

  importKey(exportedKey);

  deleteKeyPair(); // Some bug here, we cannot delete the imported key, I guess it is related to the access control, let's figure it out later
   
  res = SecKeychainSetDefault (originKeychain);
  cerr << "Set default keychain back res: " << res << endl;

  return 0;
}
