
#include "encprot.h"
#include <vector>

using namespace std;


int main(int argc, char *argv[])
{
	EncProtInit();

	RSA* rsa = CreateRSAKeySet();

	std::vector<EncryptedMessage*> arr;

	EncFile file(rsa, "Makefile");
	EncryptedMessage** msg = new EncryptedMessage*;

	while (file.PartEncryptv1(msg) != ENCFILE_FAIL)
	{
		arr.push_back(*msg);
//		printf("%s", (char*)(*msg)->code);
	}

	for (EncryptedMessage* m : arr)
	{
		unsigned char* de = DecryptMessage(rsa, m);
		printf("%s", (char*)de);
	}

	return 0;
}
