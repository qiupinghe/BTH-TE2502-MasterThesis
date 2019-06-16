#include <botan/rsa.h>
#include <botan/auto_rng.h>

int main(int argc, char* argv[])
{
  Botan::AutoSeeded_RNG rng;
  // Generate RSA keypair
  for (int i=0; i < std::stoi(argv[1]); i ++){
    Botan::RSA_PrivateKey key(rng, 3072);
  }
  return 0;
}
