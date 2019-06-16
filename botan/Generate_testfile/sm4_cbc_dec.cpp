#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

int main(int argc, char* argv[])
{
   Botan::AutoSeeded_RNG rng;

   std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("SM4/CBC/PKCS7", Botan::DECRYPTION);
   std::cout << "---- Cipher info ---- \n" << enc->name() << std::endl \
   << "Minimum key length: " << enc->minimum_keylength() << " bytes" << std::endl \
   << "Maximum key length: " << enc->maximum_keylength() << " bytes" << std::endl\
   << "-----------------------------"<< std::endl;

   // Configure 128 bit key for the cipher.
   const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
   enc->set_key(key);

   // Read IV from file and store it into buffer
   std::ifstream cbc_iv(argv[1], std::ios::binary | std::ios::ate);
   std::streamsize iv_size = cbc_iv.tellg();
   cbc_iv.seekg(0, std::ios::beg);
   Botan::secure_vector<uint8_t> iv_buffer(iv_size);
   cbc_iv.read(reinterpret_cast<char*>(iv_buffer.data()), iv_size);
   cbc_iv.close();

   std::cout << "IV data: " << iv_buffer.data() << std::endl;
   std::cout << "IV encoding: " << Botan::hex_encode(iv_buffer) << std::endl << std::endl;
   //generate fresh nonce (IV)
   Botan::secure_vector<uint8_t> iv = iv_buffer;

   // Encryption of file
   std::ifstream fin(argv[2], std::ios::binary);
   std::ofstream fout("sm4_cbc_dec.bin", std::ios::binary | std::ios::ate);
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
   std::cout << "Plaintext: " << buffer.data() << std::endl;
   return 0;
}
