// ConvertECCPrivateKeyToDer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <ncrypt.h>

int evaluateStatus(SECURITY_STATUS status)
{
	if (status == ERROR_SUCCESS)
		return 0;
	switch (status)
	{
	case NTE_INVALID_HANDLE:
		fprintf(stderr, "Cryptographic functionr returned error code: NTE_INVALID_HANDLE");
		return 1;
	case NTE_INVALID_PARAMETER:
		fprintf(stderr, "Cryptographic function returned error code: NTE_INVALID_PARAMETER");
		return 1;
	case NTE_BAD_FLAGS:
		fprintf(stderr, "Cryptographic function returned error code: NTE_BAD_FLAGS");
		return 1;
	case NTE_BAD_KEYSET:
		fprintf(stderr, "Cryptographic function returned error code: NTE_BAD_KEYSET");
		return 1;
	case NTE_NOT_SUPPORTED:
		fprintf(stderr, "Cryptographic function returned error code: NTE_NOT_SUPPORTED");
		return 1;

	default:
		fprintf(stderr, "Cryptographic function returned unknown error code");
		return 1;

	}

}


int main(int argc, char *argv[])
{
	if (argc != 3)
		std::cout << "Usage: " << argv[0] << " subjectName password" << std::endl;
	HCERTSTORE certStore = CertOpenSystemStore(NULL, L"My");
	wchar_t* wideSubjectName = new wchar_t[strlen(argv[1])+1];
	size_t numBytes;
	mbstowcs_s(&numBytes, wideSubjectName, (size_t)strlen(argv[1])+1, argv[1], (size_t)strlen(argv[1]));
	PCCERT_CONTEXT pContext = CertFindCertificateInStore(certStore, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, wideSubjectName, NULL);
	delete [] wideSubjectName;
	NCRYPT_KEY_HANDLE keyHandle;
	DWORD keySpec;
	BOOL release;
	BOOL ret = CryptAcquireCertificatePrivateKey(pContext, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &keyHandle, &keySpec, &release);

	SECURITY_STATUS status = 0;

	DWORD cbResult;


	void *pKeyBlob = NULL;
	NCryptBufferDesc bufferDesc;
	bufferDesc.cBuffers = 3;
	bufferDesc.pBuffers = new NCryptBuffer[3];
	bufferDesc.ulVersion = NCRYPTBUFFER_VERSION;
	bufferDesc.pBuffers[0].BufferType = NCRYPTBUFFER_PKCS_SECRET;
	bufferDesc.pBuffers[0].pvBuffer = (PVOID)L"Pa$$w0rd";
	bufferDesc.pBuffers[0].cbBuffer = 18;
	bufferDesc.pBuffers[1].BufferType = NCRYPTBUFFER_PKCS_ALG_OID;
	bufferDesc.pBuffers[1].pvBuffer = (void*)"1.2.840.113549.1.12.1.3";

	  bufferDesc.pBuffers[1].cbBuffer = strlen((const char *)bufferDesc.pBuffers[1].pvBuffer) + 1;
	CRYPT_PKCS12_PBE_PARAMS *pbeParams = (CRYPT_PKCS12_PBE_PARAMS *)malloc(sizeof(CRYPT_PKCS12_PBE_PARAMS) + 8);
	pbeParams->cbSalt = 8;
	pbeParams->iIterations = 1024;
	char* salt = ((char *)pbeParams) + sizeof(CRYPT_PKCS12_PBE_PARAMS);
	for (int i = 0; i < 8; i++)
	{
		salt[i] = i;
	}
	bufferDesc.pBuffers[2].pvBuffer = pbeParams;
	bufferDesc.pBuffers[2].cbBuffer = sizeof(CRYPT_PKCS12_PBE_PARAMS) + 8;
	bufferDesc.pBuffers[2].BufferType = NCRYPTBUFFER_PKCS_ALG_PARAM;

	
	status = NCryptExportKey(keyHandle, NULL, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &bufferDesc, NULL, 0, &cbResult, 0);
	pKeyBlob = new char[cbResult];
	status = NCryptExportKey(keyHandle, NULL, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &bufferDesc, (PBYTE)pKeyBlob, cbResult, &cbResult, 0);
	if (evaluateStatus(status) != 0)
	{
		CertFreeCertificateContext(pContext);
		CertCloseStore(certStore, 0);
		NCryptFreeObject(keyHandle);
		delete[] pKeyBlob;
		return -1;
	}
	CertFreeCertificateContext(pContext);
	CertCloseStore(certStore, 0);
	HANDLE myFile = CreateFile(L"MyKeyBlob", GENERIC_WRITE, 0, NULL, 1, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD written;
	WriteFile(myFile, pKeyBlob, cbResult, &written, NULL);
	CloseHandle(myFile);
}

