#include <botan/sm2.h>
#include <botan/auto_rng.h>

int main(int argc, char* argv[])
{
  Botan::AutoSeeded_RNG rng;
  //generating key pair
  for (int i=0; i < std::stoi(argv[1]); i++) {
    Botan::SM2_PrivateKey key(rng, Botan::EC_Group("sm2p256v1"));
  }
  return 0;
}
