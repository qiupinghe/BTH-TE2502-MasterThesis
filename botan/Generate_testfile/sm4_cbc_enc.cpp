#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

int main(int argc, char* argv[])
{
   Botan::AutoSeeded_RNG rng;

   std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("SM4/CBC/PKCS7", Botan::ENCRYPTION);
   std::cout << "---- Cipher info ---- \n" << enc->name() << std::endl \
   << "Minimum key length: " << enc->minimum_keylength() << " bytes" << std::endl \
   << "Maximum key length: " << enc->maximum_keylength() << " bytes" << std::endl\
   << "-----------------------------"<< std::endl;

   // Configure 128 bit key for the cipher.
   const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
   enc->set_key(key);

   // Generate fresh nonce (IV)
   Botan::secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length());
   std::cout << "IV buffer data: " << iv.data() << std::endl;
   std::cout << "IV content (hex): " << Botan::hex_encode(iv) << std::endl;
   std::cout <<  "-----------------------------"<< std::endl;

   // Write IV to file
   std::ofstream cbc_iv("sm4_cbc_iv", std::ios::binary | std::ios::ate);
   cbc_iv.write(reinterpret_cast<char*>(iv.data()), iv.size());
   cbc_iv.close();

   // Encryption of file
   std::ifstream fin(argv[1], std::ifstream::binary);
   std::ofstream fout("sm4_cbc_enc.bin", std::ios::binary | std::ios::ate);
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
   std::cout << "Encrypted file with " << enc->name() << " with iv " << Botan::hex_encode(iv) << std::endl;
   std::cout << "Encrypted data: " << buffer.data() << std::endl << Botan::hex_encode(buffer) << std::endl;
   return 0;
}
