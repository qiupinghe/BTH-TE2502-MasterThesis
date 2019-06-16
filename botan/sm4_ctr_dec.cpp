#include <botan/stream_cipher.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

int main(int argc, char* argv[])
{
  std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create("CTR(SM4)"));
  const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");

  // IV
  std::ifstream ctr_iv(argv[1], std::ios::binary | std::ios::ate);
  std::streamsize iv_size = ctr_iv.tellg();
  ctr_iv.seekg(0, std::ios::beg);
  Botan::secure_vector<uint8_t> iv_buffer(iv_size);
  ctr_iv.read(reinterpret_cast<char*>(iv_buffer.data()), iv_size);
  ctr_iv.close();
  Botan::secure_vector<uint8_t> iv = iv_buffer;

  // Encryption of file
  std::ifstream file(argv[2], std::ios::binary);
  Botan::secure_vector<uint8_t> buffer(2048);
  cipher->set_key(key);
  cipher->set_iv(iv.data(),iv.size());

  std::ofstream ctr_output("sm4_ctr_dec.bin", std::ios::binary | std::ios::ate);
  while(file.good())
  {
    file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    size_t readcount = file.gcount();
    if(readcount < 2048) {
      buffer.resize(readcount);
      break;
    }
    cipher->encipher(buffer);
    ctr_output.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
  }
  cipher->encipher(buffer);
  ctr_output.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
  ctr_output.close();
  file.close();
  return 0;
}
