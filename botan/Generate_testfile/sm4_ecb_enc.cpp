#include <botan/block_cipher.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

int main(int argc, char* argv[])
{
  std::size_t no_blocks;
  std::unique_ptr<Botan::BlockCipher> cipher(Botan::BlockCipher::create("SM4"));

  std::cout << "---- Cipher info ---- \n" << cipher->name() << std::endl \
  << "Minimum key length: " << cipher->minimum_keylength() << " bytes" << std::endl \
  << "Maximum key length: " << cipher->maximum_keylength() << " bytes" << std::endl\
  << "-----------------------------"<<std::endl;

  //Configure 128 bit key for the cipher.
  std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
  cipher->set_key(key);

    std::ifstream fin(argv[1], std::ifstream::binary);
    std::ofstream fout("sm4_ecb_enc.bin", std::ios::binary | std::ios::ate);
    Botan::secure_vector<uint8_t> buffer(2048);

    while(fin.good()) {
      fin.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
      size_t readcount = fin.gcount();
      if(readcount < 2048) {
        buffer.resize(readcount);
        break;
      }
       cipher->encrypt_n(buffer.data(), buffer.data(), 128);
       // std::cout << "=========================================" << std:: endl << std::endl;
       // std::cout << "Buffer data:" << buffer.data() << std::endl;
      fout.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    }
    cipher->encrypt_n(buffer.data(), buffer.data(), buffer.size()/16);
    fout.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    fout.close();
    fin.close();
    return 0;
}
