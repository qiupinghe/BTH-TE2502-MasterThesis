// g++ ecdsa_setup.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o ecdsa_setup
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/sm2.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <botan/auto_rng.h>
#include <botan/rng.h>
#include <botan/pkcs8.h>
#include <botan/x509cert.h>
#include <iostream>
#include <fstream>

int main()
{
  std::unique_ptr<Botan::EC_Group> group(new Botan::EC_Group("secp256r1")); //NIST P-256 curve
  std::cout << std::endl << "Curve OID: " << group->get_curve_oid().as_string();
  std::cout << std::endl << "Size of p: " << group->get_p_bits();
  std::cout << std::endl << "Size of group order: " << group->get_order_bits();
  std::cout << std::endl << "Prime Modulus p: " << group->get_p();
  std::cout << std::endl << "a: " << group->get_a();
  std::cout << std::endl << "b: " << group->get_b();
  std::cout << std::endl << "Base point (x): " << group->get_g_x();
  std::cout << std::endl << "Base point (y): " << group->get_g_y();
  std::cout << std::endl << "Order of the group: " << group->get_order();
  std::cout << std::endl << "Cofactor: " << group->get_cofactor() << std::endl << std::endl;

  Botan::AutoSeeded_RNG rng;
  //generating key pair
  Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group("secp256r1"));
  std::cout << "Generated " << key.algo_name() << " key pair." << std::endl;

  // write private and public key to file
  std::cout << "Writing keys to files \"private.key\" and \"public.key\"." << std::endl;
  std::ofstream pem("ecdsa/private.key");
  pem << Botan::PKCS8::PEM_encode(key);
  pem.close();
  std::ofstream pub("ecdsa/public.key");
  pub << Botan::X509::PEM_encode(key);
  pub.close();

  // Load public and private key
  Botan::Public_Key* pub_key = Botan::X509::load_key("ecdsa/public.key");
  Botan::Private_Key* priv_key = Botan::PKCS8::load_key("ecdsa/private.key", rng, "-");

  std::string text("7e17c2bd4a83499699bbbcc91bd47fcf3f8664bb3d322cff10217fc44e50ff23");
  std::vector<uint8_t> data(text.data(),text.data()+text.length());

  //sign data
  Botan::PK_Signer signer(*priv_key, rng, "EMSA1(SHA-256)");
  signer.update(data);
  std::vector<uint8_t> signature = signer.signature(rng);

  //write signature to file
  std::cout << "Writing signature to file \"signature.sig\"" << std::endl;
  std::ofstream f_out("ecdsa/signature.sig", std::ios::binary | std::ios::ate);
  f_out.write(reinterpret_cast<char*>(signature.data()), signature.size());
  f_out.close();

  Botan::PK_Verifier verifier(key, "EMSA1(SHA-256)");
  verifier.update(data);
  std::cout << "Signature is " << (verifier.check_signature(signature)? "valid" : "invalid") << std::endl;

  return 0;
}
