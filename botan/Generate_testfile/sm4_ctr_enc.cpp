#include <botan/stream_cipher.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

int main(int argc, char* argv[])
{
  std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create("CTR(SM4)"));
  const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");

  std::cout << "---- Cipher info ---- \n" << cipher->name() << std::endl \
   << "Minimum key length: " << cipher->minimum_keylength() << " bytes" << std::endl \
   << "Maximum key length: " << cipher->maximum_keylength() << " bytes" << std::endl\
   << "-----------------------------"<<std::endl;

  std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);
  std::vector<uint8_t> iv(8);
  rng->randomize(iv.data(),iv.size());

  // Writing CTR IV to file
  std::ofstream ctr_iv("sm4_ctr_iv", std::ios::binary | std::ios::ate);
  Botan::secure_vector<uint8_t> iv_buffer(iv.size());
  ctr_iv.write(reinterpret_cast<char*>(iv.data()), iv_buffer.size());
  ctr_iv.close();

  std::cout << "IV : " << iv.data() << std::endl;
  std::cout << "IV hex: " << Botan::hex_encode(iv) << std::endl << std::endl;
  // Encryption of file
  std::ifstream file(argv[1], std::ios::binary);
  Botan::secure_vector<uint8_t> buffer(2048);
  cipher->set_key(key);
  cipher->set_iv(iv.data(),iv.size());

  std::ofstream ctr_output("sm4_ctr_enc.bin", std::ios::binary | std::ios::ate);
  while(file.good())
  {
    file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    //std::cout << "Buffer data: " << buffer.data() << std::endl;

    size_t readcount = file.gcount();
    if(readcount < 2048) {
      buffer.resize(readcount);
      break;
    }
    cipher->encipher(buffer);
    ctr_output.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
  }

  // std::cout << cipher->name() << " with iv " << Botan::hex_encode(iv) << ": " \
  //           << Botan::hex_encode(buffer) << buffer.data() << "\n";
  cipher->encipher(buffer);
  ctr_output.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
  ctr_output.close();
  file.close();
  return 0;
}
