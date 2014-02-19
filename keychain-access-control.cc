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

  res = SecKeychainCreate ("example.keychain", 4, "1234", false, NULL, &targetKeychain);
  if(errSecDuplicateKeychain == res)
    res = SecKeychainOpen ("example.keychain", &targetKeychain);
  cerr << "Create/Open keychain res: " << res << endl;

  res = SecKeychainCopyDefault (&originKeychain);
  cerr << "Get default keychain res: " << res << endl;

  res = SecKeychainSetDefault (targetKeychain);
  cerr << "Set default keychain res: " << res << endl;

  // SecKeychainCopyAccess is not implemented in Mac OS X 10.8. Let's try it in later version.
  // SecAccessRef keychainAccess;
  // CFArrayRef keychainAclList;
  // res = SecKeychainCopyAccess (targetKeychain, &keychainAccess);
  // cerr << "SecKeychainCopyAccess res: " << res << endl;
  // res = SecAccessCopyACLList (keychainAccess, &keychainAclList);
  // cerr << "SecAccessCopyACLList res: " << res << endl;
  // cerr << "Number of ACL lists: " << CFArrayGetCount(keychainAclList) << endl;
   
  res = SecKeychainSetDefault (originKeychain);
  cerr << "Set default keychain back res: " << res << endl;

  return 0;
}
