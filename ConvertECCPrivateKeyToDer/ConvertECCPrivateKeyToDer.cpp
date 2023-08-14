// ConvertECCPrivateKeyToDer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <ncrypt.h>

int main(int argc, char *argv[])
{
	if (argc != 3)
		std::cout << "Usage: " << argv[0] << " subjectName password" << std::endl;
	HCERTSTORE certStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING, NULL, CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG, L"My");
	CertCloseStore(certStore, 0);
}

