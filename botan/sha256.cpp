#include <botan/hash.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>
#include <unistd.h>

int main (int argc, char* argv[])
   {
   std::unique_ptr<Botan::HashFunction> hash1(Botan::HashFunction::create("SHA-256"));
   std::ifstream fin(argv[1], std::ifstream::binary);
   std::vector<uint8_t> buf(2048);
   while(fin.good())
   {
     fin.read(reinterpret_cast<char*>(buf.data()), buf.size());
     size_t readcount = fin.gcount();
     hash1->update(buf.data(),readcount);
   }
   std::cout << "SHA-256: " << Botan::hex_encode(hash1->final()) << std::endl;
   return 0;
   }
// https://botan.randombit.net/manual/building.html#unix
// use "botan config cflags" and "botan config libs" to find flags needed to compile
//    g++ test.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o test
//    ./test
