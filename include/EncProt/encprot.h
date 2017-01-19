#ifndef ENCPROT_H
#define ENCPROT_H

#include <fstream>
#include <openssl/rsa.h>
#include "libdef.h"

#define ENCFILE_EOF 0
#define ENCFILE_SUCCESS 1
#define ENCFILE_FAIL -1

struct DLL EncryptedMessage
{
	int size;
	int blocks;
	unsigned char* code;
	int paddingStyle;

	//Used for splitting larger encryptions into parts
	int partNumber;
	bool endPart;
};

class DLL EncFile
{
public:
	int PartEncryptv1(EncryptedMessage**);

	//Returns true if there are more parts to be read.
	//Returns false if there was a file error or if
	//end of file was reached.
	EncFile(RSA* rsa, const char* fileName);

private:
	std::ifstream mFile;
	RSA* mRsa;
	int mPartNumber;
};

void DLL EncProtInit();

RSA* DLL CreateRSAKeySet();

void DLL LoadRSAPubKey(RSA** rsa, const char* filePath);

int passwordCallback(char* pwBuffer, int size, int rwFlag, void *pPas);

void DLL LoadRSAPrivKey(RSA** rsa, const char* pw, const char* filePath);

RSA* DLL LoadRSAKeySet(const char* pw, const char* pubName, const char* privName);

void DLL WriteRSAPubKey(RSA* rsa, const char* filePath);

void DLL WriteRSAPrivKey(RSA* rsa, const char* pw, const char* filePath);

void DLL WriteRSAKeySet(RSA* rsa, const char* pw, const char* pubName, const char* privName);

//TODO instead of returning simple byte stream, output a struct with size details
EncryptedMessage* DLL EncryptMessagev1(RSA *rsa, unsigned char* msg, int size);

unsigned char* DLL DecryptMessage(RSA *rsa, const EncryptedMessage *code);

#endif // ENCPROT_H
