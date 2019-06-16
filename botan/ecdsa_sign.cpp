#include <botan/ecdsa.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>

int main(int argc, char* argv[])
{
  Botan::AutoSeeded_RNG rng;
  // Load private key
  Botan::Private_Key* priv_key = Botan::PKCS8::load_key(argv[1], rng, "-");

  std::string text("7e17c2bd4a83499699bbbcc91bd47fcf3f8664bb3d322cff10217fc44e50ff23");
  std::vector<uint8_t> data(text.data(),text.data()+text.length());

  // Sign data
  for (int i = 0; i < std::stoi(argv[2]); i++) {
    Botan::PK_Signer signer(*priv_key, rng, "EMSA1(SHA-256)");
    signer.update(data);
    std::vector<uint8_t> signature = signer.signature(rng);
  }
  return 0;
}
