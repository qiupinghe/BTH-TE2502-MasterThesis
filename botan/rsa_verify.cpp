#include <botan/rsa.h>
#include <botan/pubkey.h>
#include <botan/x509cert.h>
#include <iostream>
#include <fstream>

int main(int argc, char* argv[])
  {
  // Load public key
  Botan::Public_Key* pub_key = Botan::X509::load_key(argv[1]);

  std::string text("7e17c2bd4a83499699bbbcc91bd47fcf3f8664bb3d322cff10217fc44e50ff23");
  std::vector<uint8_t> data(text.data(),text.data()+text.length());

  //read signature from file
  std::ifstream f_in(argv[2], std::ios::binary | std::ios::ate);
  std::streamsize size = f_in.tellg();
  f_in.seekg(0, std::ios::beg);
  Botan::secure_vector<uint8_t> signature(size);
  f_in.read(reinterpret_cast<char*>(signature.data()), size);

  //verify signature
  for (int i=0; i < std::stoi(argv[3]); i++){
    Botan::PK_Verifier verifier(*pub_key, "EMSA4(SHA-256)");
    verifier.update(data);
    verifier.check_signature(signature);
    //std::cout << "Signature is " << (verifier.check_signature(signature)? "valid" : "invalid") << std::endl;
  }
  return 0;
  }
