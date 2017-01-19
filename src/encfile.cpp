
#include "encprot.h"
#include <iostream>

EncFile::EncFile(RSA* rsa, const char* file) : mRsa(rsa), mFile(file, std::ios::binary), mPartNumber(0)
{
}

int EncFile::PartEncryptv1(EncryptedMessage** msg)
{

	(*msg) = new EncryptedMessage;

	if (mFile)
	{
		unsigned char* data = new unsigned char[470];
		mFile.read((char*)data, 470);

		if (!mFile.bad())
		{
			(*msg)->size = mFile.gcount();
			(*msg)->blocks = 1;
			(*msg)->paddingStyle = RSA_PKCS1_OAEP_PADDING;
			(*msg)->partNumber = mPartNumber;
			(*msg)->code = new unsigned char[RSA_size(mRsa)];

			RSA_public_encrypt((*msg)->size, data, (*msg)->code, mRsa, RSA_PKCS1_OAEP_PADDING);

			mPartNumber++;

			if (mFile.eof())
			{
				(*msg)->endPart = true;
				return 0;
			}
			else
			{
				(*msg)->endPart = false;
				return 1;
			}
		}
		else
		{
			return -1;
		}
	}
	return -1;
}
