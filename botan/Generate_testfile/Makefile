make:
	g++ aes_ecb_enc.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o aes_ecb_enc.o
	g++ aes_ecb_dec.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o aes_ecb_dec.o

	g++ aes_cbc_enc.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o aes_cbc_enc.o
	g++ aes_cbc_dec.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o aes_cbc_dec.o

	g++ aes_ctr_enc.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o aes_ctr_enc.o
	g++ aes_ctr_dec.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o aes_ctr_dec.o

	g++ sm4_ecb_enc.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o sm4_ecb_enc.o
	g++ sm4_ecb_dec.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o sm4_ecb_dec.o

	g++ sm4_cbc_enc.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o sm4_cbc_enc.o
	g++ sm4_cbc_dec.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o sm4_cbc_dec.o

	g++ sm4_ctr_enc.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o sm4_ctr_enc.o
	g++ sm4_ctr_dec.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o sm4_ctr_dec.o

	g++ sm2_setup.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o sm2_setup
	g++ rsa_setup.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o rsa_setup
	g++ ecdsa_setup.cpp -std=c++11 -I/usr/local/include/botan-2 -lbotan-2 -ldl -lrt -o ecdsa_setup

clean:
	rm -f *.o
	rm -f *_iv
	rm -f *.bin
