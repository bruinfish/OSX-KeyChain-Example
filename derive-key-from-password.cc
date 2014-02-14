/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Yingdi Yu
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>
#include <Security/SecRandom.h>

#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>


namespace po = boost::program_options;
using namespace std;


int main(int argc, char** argv)	
{
  int iterations = 1024;
  string saltStr;
  string password;

  po::options_description desc("General Usage\n  derive-key-from-pw [-h] -i iterations -s salt -p password\nGeneral options");
  desc.add_options()
    ("help,h", "help message")
    ("iterations,i", po::value<int>(&iterations), "iteration count")
    ("salt,s", po::value<std::string>(&saltStr), "salt (hex encoded)")
    ("password,p", po::value<std::string>(&password), "password")
    ;

  po::positional_options_description p;
  p.add("iterations", 1);
  p.add("salt", 2);
  p.add("password", 3);
  
  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cerr << desc << endl;;
      return 1;
    }

  CFStringRef passwordRef = CFStringCreateWithCString(NULL, password.c_str(), kCFStringEncodingUTF8);

  string salt;
  CryptoPP::StringSource ss(reinterpret_cast<const byte*>(saltStr.c_str()), saltStr.size(), true, 
                  new CryptoPP::Base64Decoder(new CryptoPP::StringSink(salt)));
  CFDataRef saltRef = CFDataCreateWithBytesNoCopy(NULL, reinterpret_cast<const uint8_t*>(salt.c_str()), salt.size(), kCFAllocatorNull);

  uint32_t iterationCount = 2048;
  
  uint32_t keySize = 8*24;

  CFErrorRef error;

  CFMutableDictionaryRef parameters = CFDictionaryCreateMutable(NULL, 3, &kCFTypeDictionaryKeyCallBacks, NULL);
  CFDictionaryAddValue(parameters, kSecAttrSalt, saltRef);
  CFDictionaryAddValue(parameters, kSecAttrPRF, kSecAttrPRFHmacAlgSHA1);
  CFDictionaryAddValue(parameters, kSecAttrRounds, CFNumberCreate(NULL, kCFNumberIntType, &iterationCount));
  CFDictionaryAddValue(parameters, kSecAttrKeySizeInBits, CFNumberCreate(NULL, kCFNumberIntType, &keySize));

  SecKeyRef keyRef = SecKeyDeriveFromPassword(passwordRef, parameters, &error);

  CFDataRef exportedKey;

  OSStatus res = SecItemExport(keyRef,
                               kSecFormatRawKey,
                               0,
                               NULL,
                               &exportedKey);

  CryptoPP::StringSource ss2(CFDataGetBytePtr(exportedKey), CFDataGetLength(exportedKey), true,
                             new CryptoPP::HexEncoder(new CryptoPP::FileSink(cout)));
}
