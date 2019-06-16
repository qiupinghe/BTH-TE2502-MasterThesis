// g++ rsa_setup.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o rsa_setup
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <botan/rsa.h>
#include <botan/pkcs8.h>
#include <botan/x509cert.h>
#include <iostream>
#include <fstream>

int main()
  {
  Botan::AutoSeeded_RNG rng;
  // Generate RSA keypair
  std::cout << "Generating RSA key pair." << std::endl;
  Botan::RSA_PrivateKey key(rng, 3072);

  // Write private and public key to files
  std::cout << "Writing keys to files \"private.key\" and \"public.key\"." << std::endl;
  std::ofstream pem("rsa/private.key");
  pem << Botan::PKCS8::PEM_encode(key);
  pem.close();
  std::ofstream pub("rsa/public.key");
  pub << Botan::X509::PEM_encode(key);
  pub.close();

  // Load public and private key
  Botan::Public_Key* pub_key = Botan::X509::load_key("rsa/public.key");
  Botan::Private_Key* priv_key = Botan::PKCS8::load_key("rsa/private.key", rng, "-");

  // Create data to sign
  std::cout << "Creating signature of data: \"7e17c2bd4a83499699bbbcc91bd47fcf3f8664bb3d322cff10217fc44e50ff23\"" << std::endl;
  std::string text("7e17c2bd4a83499699bbbcc91bd47fcf3f8664bb3d322cff10217fc44e50ff23");
  std::vector<uint8_t> data(text.data(),text.data()+text.length());

  // sign data with loaded key
  Botan::PK_Signer signer2(*priv_key, rng, "EMSA4(SHA-256)");
  signer2.update(data);
  std::vector<uint8_t> signature = signer2.signature(rng);

  //write signature to file
  std::cout << "Writing signature to file \"signature.sig\"" << std::endl;
  std::ofstream f_out("rsa/signature.sig", std::ios::binary | std::ios::ate);
  f_out.write(reinterpret_cast<char*>(signature.data()), signature.size());
  f_out.close();

  return 0;
  }
