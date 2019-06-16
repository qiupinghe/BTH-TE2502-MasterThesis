#include <botan/ecdsa.h>
#include <botan/auto_rng.h>

int main(int argc, char* argv[])
{
  Botan::AutoSeeded_RNG rng;
  //generating key pair
  for (int i=0; i < std::stoi(argv[1]); i++) {
    Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group("secp256r1"));
  }
  return 0;
}
