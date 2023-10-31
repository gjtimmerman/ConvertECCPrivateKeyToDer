// ConvertECCPrivateKeyToDer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

int evaluateBStatus(NTSTATUS status)
{
	if (status == ERROR_SUCCESS)
		return 0;
	switch (status)
	{
	case STATUS_INVALID_HANDLE:
		fprintf(stderr, "Cryptographic functionr returned error code: STATUS_INVALID_HANDLE");
		return 1;
	case STATUS_INVALID_PARAMETER:
		fprintf(stderr, "Cryptographic function returned error code: STATUS_INVALID_PARAMETER");
		return 1;
	case STATUS_NO_MEMORY:
		fprintf(stderr, "Cryptographic function returned error code: STATUS_NO_MEMORY");
		return 1;

	default:
		fprintf(stderr, "Cryptographic function returned unknown error code");
		return 1;

	}

}


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


	unsigned char *pKeyBlob = NULL;
	NCryptBufferDesc bufferDesc;
	bufferDesc.cBuffers = 3;
	bufferDesc.pBuffers = new NCryptBuffer[3];
	bufferDesc.ulVersion = NCRYPTBUFFER_VERSION;
	bufferDesc.pBuffers[0].BufferType = NCRYPTBUFFER_PKCS_SECRET;
	bufferDesc.pBuffers[0].pvBuffer = (PVOID)L"Pa$$w0rd";
	bufferDesc.pBuffers[0].cbBuffer = 18;
	bufferDesc.pBuffers[1].BufferType = NCRYPTBUFFER_PKCS_ALG_OID;
	bufferDesc.pBuffers[1].pvBuffer = (void*)"1.2.840.113549.1.12.1.3";
//	bufferDesc.pBuffers[1].pvBuffer = (void*)"1.2.840.113549.1.5.13";


	bufferDesc.pBuffers[1].cbBuffer = (ULONG)(strlen((const char *)bufferDesc.pBuffers[1].pvBuffer) + 1);
	CRYPT_PKCS12_PBE_PARAMS *pbeParams = (CRYPT_PKCS12_PBE_PARAMS *)malloc(sizeof(CRYPT_PKCS12_PBE_PARAMS) + 32);
	pbeParams->cbSalt = 32;
	pbeParams->iIterations = 1000;
	char* pSalt = ((char *)pbeParams) + sizeof(CRYPT_PKCS12_PBE_PARAMS);
	for (int i = 0; i < 32; i++)
	{
		pSalt[i] = i;
	}
	bufferDesc.pBuffers[2].pvBuffer = pbeParams;
	bufferDesc.pBuffers[2].cbBuffer = sizeof(CRYPT_PKCS12_PBE_PARAMS) + 32;
	bufferDesc.pBuffers[2].BufferType = NCRYPTBUFFER_PKCS_ALG_PARAM;

	
	status = NCryptExportKey(keyHandle, NULL, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &bufferDesc, NULL, 0, &cbResult, 0);
	pKeyBlob = new unsigned char[cbResult];
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
	HANDLE myFile = CreateFile(L"MyKeyBlob", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD written;
	WriteFile(myFile, pKeyBlob, cbResult, &written, NULL);
	FlushFileBuffers(myFile);
	CloseHandle(myFile);


	NTSTATUS bStatus;
	BCRYPT_ALG_HANDLE algHandle;
	char salt[32];
	for (int i = 0; i < 32; i++)
		salt[i] = i;
	unsigned char iv[8] = {};
	BCRYPT_KEY_HANDLE derivedKeyHandle;
	bStatus = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA1_ALGORITHM, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (evaluateBStatus(bStatus) != 0)
		return 0;
	char keyData[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + 192/8];
	wchar_t password[16] = L"Pa$$w0rd";
	//unsigned char* passwordChars = (unsigned char*)password;

	//for (int i = 0; i < 16; i+=2)
	//{
	//	unsigned char tmp = passwordChars[i];
	//	passwordChars[i] = passwordChars[i + 1];
	//	passwordChars[i + 1] = tmp;
	//}


	bStatus = BCryptDeriveKeyPBKDF2(algHandle, (PUCHAR)L"Pa$$w0rd", 16, (PUCHAR)salt, 32, 1000, (PUCHAR)keyData + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), 192 / 8, 0);
	if (evaluateBStatus(bStatus) != 0)
		return 0;
	bStatus = BCryptCloseAlgorithmProvider(algHandle, 0);
	if (evaluateBStatus(bStatus) != 0)
		return 0;
	bStatus = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_3DES_ALGORITHM, NULL, 0);
	if (evaluateBStatus(bStatus) != 0)
		return 0;
	BCRYPT_KEY_DATA_BLOB_HEADER* pKeyDataHeader = (BCRYPT_KEY_DATA_BLOB_HEADER *)keyData;
	pKeyDataHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
	pKeyDataHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
	pKeyDataHeader->cbKeyData = 192 / 8;
	bStatus = BCryptImportKey(algHandle, NULL, BCRYPT_KEY_DATA_BLOB, &derivedKeyHandle, NULL, 0, (PUCHAR)keyData, sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + 192 / 8, 0);
	if (evaluateBStatus(bStatus) != 0)
		return 0;
	unsigned char decrypted[168];
	ULONG cbOutput = 0;
	bStatus = BCryptDecrypt(derivedKeyHandle, pKeyBlob + 60, 168, NULL, iv, 8, decrypted, 168, &cbOutput, BCRYPT_PAD_PKCS1);
	if (evaluateBStatus(bStatus) != 0)
		return 0;

	bStatus = BCryptDestroyKey(derivedKeyHandle);
	if (evaluateBStatus(bStatus) != 0)
		return 0;
	bStatus = BCryptCloseAlgorithmProvider(algHandle, 0);
	if (evaluateBStatus(bStatus) != 0)
		return 0;
	HANDLE myFile2 = CreateFile(L"MyDecryptedKeyBlob", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	WriteFile(myFile2, decrypted, cbOutput, &written, NULL);
	FlushFileBuffers(myFile2);
	CloseHandle(myFile2);

	return 0;
}

