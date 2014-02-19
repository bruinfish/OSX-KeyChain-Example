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

int main (int argc, char** argv)	
{
  OSStatus res;
  SecKeychainRef targetKeychain;
  SecKeychainRef originKeychain;
  SecKeychainRef newDftKeychain;

  res = SecKeychainCreate ("example.keychain", 4, "1234", false, NULL, &targetKeychain);
  if(errSecDuplicateKeychain == res)
    res = SecKeychainOpen ("example.keychain", &targetKeychain);
  cerr << "Create/Open keychain res: " << res << endl;

  res = SecKeychainCopyDefault (&originKeychain);
  cerr << "Get default keychain res: " << res << endl;

  res = SecKeychainSetDefault (targetKeychain);
  cerr << "Set default keychain res: " << res << endl;

  res = SecKeychainCopyDefault (&newDftKeychain);
  char pathName[256] = {0};
  UInt32 pathLength = 256;
  res = SecKeychainGetPath (newDftKeychain, &pathLength, pathName);
  cerr << "New default keychain: " << pathName << endl;
  
  res = SecKeychainSetDefault (originKeychain);
  cerr << "Set default keychain back res: " << res << endl;

  res = SecKeychainCopyDefault (&newDftKeychain);
  memset(pathName, 0, pathLength);
  res = SecKeychainGetPath (newDftKeychain, &pathLength, pathName);
  cerr << "Now default keychain: " << pathName << endl;

  return 0;
}
