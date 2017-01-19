#include "encprot.h"
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <openssl/pem.h>
#include <string>
#include <string.h>
#include <fstream>
#include <vector>

void EncProtInit()
{
	OpenSSL_add_all_algorithms();
	RAND_poll();
}

RSA* CreateRSAKeySet()
{
	RSA* rsa = RSA_new();

	static const char* e = "65537";
	BIGNUM* num = BN_new();
	BN_dec2bn(&num, e);

	RSA_generate_key_ex(rsa, 4096, num, nullptr);

	return rsa;
}

void LoadRSAPubKey(RSA** rsa, const char* filePath)
{
	FILE* file = fopen(filePath, "r");
	PEM_read_RSAPublicKey(file, rsa, nullptr, nullptr);
	fclose(file);
}
int passwordCallback(char* pwBuffer, int size, int rwFlag, void *pPas)
{
	memcpy(pwBuffer, pPas, size);
	return strlen((char*)pPas);
}

void LoadRSAPrivKey(RSA** rsa, const char* pw, const char* filePath)
{
	FILE* file = fopen(filePath, "r");
	if (pw)
		PEM_read_RSAPrivateKey(file, rsa, passwordCallback, (void*)pw);
	else
		PEM_read_RSAPrivateKey(file, rsa, nullptr, nullptr);

}
RSA* LoadRSAKeySet(const char* pw, const char* pubName, const char* privName)
{
	RSA* rsa = RSA_new();
	LoadRSAPubKey(&rsa, pubName);
	LoadRSAPrivKey(&rsa, pw, privName);

	return rsa;
}

void WriteRSAPubKey(RSA* rsa, const char* filePath)
{
	FILE* file = fopen(filePath, "w");
	PEM_write_RSAPublicKey(file, rsa);
	fclose(file);
}

void WriteRSAPrivKey(RSA* rsa, const char* pw, const char* filePath)
{
	FILE* file = fopen(filePath, "w");
	if (pw)
		PEM_write_RSAPrivateKey(file, rsa, EVP_aes_256_cbc(), (unsigned char*)pw, (int)strlen(pw), nullptr, nullptr);
	else
		PEM_write_RSAPrivateKey(file, rsa, nullptr, nullptr, 0, nullptr, nullptr);

	fclose(file);
}

void WriteRSAKeySet(RSA* rsa, const char* pw, const char* pubName, const char* privName)
{
	WriteRSAPubKey(rsa, pubName);
	WriteRSAPrivKey(rsa, pw, privName);
}

//TODO instead of returning simple byte stream, output a struct with size details
EncryptedMessage* EncryptMessagev1(RSA* rsa, unsigned char* msg, int size)
{
	int blocks = size / (RSA_size(rsa) - 42) + 1;
	unsigned char* buffer = new unsigned char[blocks * RSA_size(rsa)];

	for (int i = 0; i < blocks; i++)
	{
		int len = size > (RSA_size(rsa) - 41) ? (RSA_size(rsa) - 42) : size;

		RSA_public_encrypt(len, msg + i * (RSA_size(rsa) - 42), buffer + i * RSA_size(rsa), rsa, RSA_PKCS1_OAEP_PADDING);
	}

	EncryptedMessage* code = new EncryptedMessage;
	code->code = buffer;
	code->size = size;
	code->blocks = blocks;
	code->paddingStyle = RSA_PKCS1_OAEP_PADDING;

	return code;
}

unsigned char* DecryptMessage(RSA* rsa, const EncryptedMessage* code)
{
	if (code->paddingStyle == RSA_PKCS1_OAEP_PADDING)
	{
		unsigned char* buffer = new unsigned char[code->blocks * RSA_size(rsa)]();
		for (int i = 0; i < code->blocks; i++)
		{
			RSA_private_decrypt(RSA_size(rsa), code->code + i * RSA_size(rsa), buffer + i * (RSA_size(rsa) - 42), rsa, code->paddingStyle);
		}
		return buffer;
	}

	return nullptr;
}
