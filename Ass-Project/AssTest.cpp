#include "Debug\cryptopp600\aes.h"
#include "Debug\cryptopp600\cryptlib.h"
#include "Debug\cryptopp600\filters.h"
#include "Debug\cryptopp600\osrng.h"
#include "Debug\cryptopp600\hex.h"
#include "Debug\cryptopp600\modes.h"
#include <stdio.h>
#include <iostream>
#include <string>
#include <iomanip>
#include <string.h>
using namespace std;
using namespace CryptoPP;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::StringSink;
using CryptoPP::StreamTransformation;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AES;
using CryptoPP::ECB_Mode;
//1.Initialization of key data
void InitKey(byte* key, size_t size) {
	for (size_t i = 0; i < size; ++i) {
		key[i] = rand();
	}
}


template <class K, class T> void AESTest(string plainText, K enc, T dec) {
	//Initialize common key and IV with appropriate values
	byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
	byte iv[CryptoPP::AES::BLOCKSIZE];

	// Initialize common key and IV with appropriate values
	InitKey(key, sizeof(key));
	InitKey(iv, sizeof(iv));

	//string plainText = "AES in Crypto++,Areej Qasrawi";
	cout << "Plain Text : " << plainText << endl;
	//Create an encrypted object
	//CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
	enc.SetKeyWithIV(key, sizeof(key), iv);
	string encText;
	CryptoPP::StreamTransformationFilter encFilter(enc, new CryptoPP::StringSink(encText));

	// encryption
	encFilter.Put(reinterpret_cast<const byte*>(plainText.c_str()), plainText.size());
	encFilter.MessageEnd();

	cout << "Encrypted Text : " << encText << endl;
	//CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
	dec.SetKeyWithIV(key, sizeof(key), iv);

	//Creation of conversion filter for decryption
	string decText;
	CryptoPP::StreamTransformationFilter decFilter(dec, new CryptoPP::StringSink(decText));
	decFilter.Put(reinterpret_cast<const byte*>(encText.c_str()), encText.size());
	decFilter.MessageEnd();

	cout << "Decrypted Text : " << decText << endl;
}

void AES_Mode_CTR(string plainText) {
	cout << "Mode CTR: " << endl;
	CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
	CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
	AESTest<>(plainText, enc, dec);
}

void AES_Mode_ECB(string plainText) {
	cout << "Mode ECB: " << endl;
	CryptoPP::ECB_Mode<AES>::Encryption enc;
	CryptoPP::ECB_Mode<AES>::Decryption dec;
	AESTest<>(plainText, enc, dec);
}

void AES_Mode_CBC(string plainText) {
	cout << "Mode CBC: " << endl;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
	AESTest<>(plainText, enc, dec);
}

void AES_Mode_CFB(string plainText) {
	cout << "Mode CFB: " << endl;
	CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc;
	CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption dec;
	AESTest<>(plainText, enc, dec);
}

void AES_Mode_OFB(string plainText) {
	cout << "Mode OFB: " << endl;
	CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption enc;
	CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption dec;
	AESTest<>(plainText, enc, dec);
}

void get_All_AESMode(string plainText) {
	AES_Mode_CTR(plainText);
	AES_Mode_ECB(plainText);
	AES_Mode_CBC(plainText);
	AES_Mode_CFB(plainText);
	AES_Mode_OFB(plainText);
}

void SHA1_hashing(string plainText)
{
	CryptoPP::SHA1 sha1;
	string hash = "";
	CryptoPP::StringSource(plainText, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
	cout << " SHA1: " << hash << endl;
}

void SHA2_hashing(string plainText) {
	CryptoPP::SHA512 sha512;
	string hash = "";
	CryptoPP::StringSource(plainText, true, new CryptoPP::HashFilter(sha512, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
	cout << " SHA512: " << hash << endl;
}

void SHA3_hashing(string plainText) {
	CryptoPP::SHA384 sha384;
	string hash = "";
	CryptoPP::StringSource(plainText, true, new CryptoPP::HashFilter(sha384, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
	cout << " SHA384: " << hash << endl;
}

void get_All_HashFunction(string plainText) {
	SHA1_hashing(plainText);
	SHA2_hashing(plainText);
	SHA3_hashing(plainText);
}
void main()
{
	string plainText = "tran hoang phuc";
	//get_All_AESMode(plainText);
	//get_All_HashFunction(plainText);
	system("PAUSE");
}