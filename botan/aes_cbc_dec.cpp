#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

int main(int argc, char* argv[])
{
   Botan::AutoSeeded_RNG rng;
   std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::DECRYPTION);
   const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
   enc->set_key(key);

   // Read IV from file and store it into buffer
   std::ifstream cbc_iv(argv[1], std::ios::binary | std::ios::ate);
   std::streamsize iv_size = cbc_iv.tellg();
   cbc_iv.seekg(0, std::ios::beg);

   Botan::secure_vector<uint8_t> iv_buffer(iv_size);
   cbc_iv.read(reinterpret_cast<char*>(iv_buffer.data()), iv_size);
   cbc_iv.close();
   Botan::secure_vector<uint8_t> iv = iv_buffer;

   // Decryption of file
   std::ifstream fin(argv[2], std::ifstream::binary);
   std::ofstream fout("cbc_dec.bin", std::ios::binary | std::ios::ate);
   Botan::secure_vector<uint8_t> buffer(2048);
   enc->start(iv);
   while(fin.good()) {
     fin.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
     size_t readcount = fin.gcount();
     if(readcount < 2048) {
       buffer.resize(readcount);
       break;
     }
     enc->update(buffer);
     fout.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
   }
   enc->finish(buffer);
   fout.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
   fout.close();
   fin.close();
   return 0;
}
