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

int main(int argc, char *argv[])
{
	if (argc != 3)
		std::cout << "Usage: " << argv[0] << " subjectName password" << std::endl;
	HCERTSTORE certStore = CertOpenSystemStore(NULL, L"My");
	HCERTSTORE certStore2 = CertOpenSystemStore(NULL, L"TrustedPeople");
	wchar_t* wideSubjectName = new wchar_t[strlen(argv[1])+1];
	size_t numBytes;
	mbstowcs_s(&numBytes, wideSubjectName, (size_t)strlen(argv[1])+1, argv[1], (size_t)strlen(argv[1]));
	PCCERT_CONTEXT pContext = CertFindCertificateInStore(certStore, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, wideSubjectName, NULL);
	PCCERT_CONTEXT pContext2 = CertFindCertificateInStore(certStore2, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, L"MyPersonal", NULL);
	delete [] wideSubjectName;
	NCRYPT_KEY_HANDLE keyHandle;
	DWORD keySpec;
	BOOL release;
	BOOL ret = CryptAcquireCertificatePrivateKey(pContext, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &keyHandle, &keySpec, &release);

	SECURITY_STATUS status = 0;
	NCRYPT_PROV_HANDLE provHandle;
	BCRYPT_KEY_HANDLE keyHandle2;
	NCRYPT_KEY_HANDLE nKeyHandle2;

	status = NCryptOpenStorageProvider(&provHandle, MS_KEY_STORAGE_PROVIDER, 0);
	ret = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &(pContext2->pCertInfo->SubjectPublicKeyInfo), 0, NULL, &keyHandle2);
	DWORD cbResult;
	NTSTATUS ntStatus;
	ntStatus = BCryptExportKey(keyHandle2, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &cbResult, 0);
	BCRYPT_RSAKEY_BLOB *pPubKeyBlob = (BCRYPT_RSAKEY_BLOB *)new char[cbResult];;
	ntStatus = BCryptExportKey(keyHandle2, NULL, BCRYPT_RSAPUBLIC_BLOB, (PBYTE)pPubKeyBlob, cbResult, &cbResult, 0);
	if (evaluateBStatus(ntStatus) != 0)
	{
		CertFreeCertificateContext(pContext);
		CertFreeCertificateContext(pContext2);
		CertCloseStore(certStore, 0);
		NCryptFreeObject(provHandle);
		NCryptFreeObject(keyHandle);
		BCryptDestroyKey(keyHandle2);
		delete[] pPubKeyBlob;
		return -1;
	}
	status = NCryptImportKey(provHandle, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, &nKeyHandle2, (PBYTE)pPubKeyBlob, cbResult, 0);
	if (evaluateStatus(status) != 0)
	{
		CertFreeCertificateContext(pContext);
		CertFreeCertificateContext(pContext2);
		CertCloseStore(certStore, 0);
		NCryptFreeObject(provHandle);
		NCryptFreeObject(keyHandle);
		BCryptDestroyKey(keyHandle2);
		delete[] pPubKeyBlob;
		return -1;
	}

	//CERT_BLOB certBlob;
	//certBlob.cbData = 0;
	//certBlob.pbData = NULL;

	//CertSaveStore(certStore2, X509_ASN_ENCODING, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &certBlob, 0);
	//certBlob.pbData = (PBYTE)new char[certBlob.cbData];
	//CertSaveStore(certStore2, X509_ASN_ENCODING, CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_MEMORY, &certBlob, 0);


	BCRYPT_ECCKEY_BLOB *pKeyBlob = NULL;
	NCryptBufferDesc bufferDesc;
	bufferDesc.cBuffers = 3;
	bufferDesc.pBuffers = new NCryptBuffer[3];
	bufferDesc.ulVersion = NCRYPTBUFFER_VERSION;
	bufferDesc.pBuffers[0].BufferType = NCRYPTBUFFER_PKCS_SECRET;
	bufferDesc.pBuffers[0].pvBuffer = (PVOID)L"Pa$$w0rd";
	bufferDesc.pBuffers[0].cbBuffer = 18;
	bufferDesc.pBuffers[1].BufferType = NCRYPTBUFFER_PKCS_ALG_OID;
//	bufferDesc.pBuffers[1].pvBuffer = (void*)szOID_NIST_AES128_WRAP;
	bufferDesc.pBuffers[1].pvBuffer = (void*)"1.2.840.10045.2.1";
	bufferDesc.pBuffers[1].cbBuffer = strlen((const char *)bufferDesc.pBuffers[1].pvBuffer) + 1;
	CRYPT_PKCS12_PBE_PARAMS *pbeParams = (CRYPT_PKCS12_PBE_PARAMS *)malloc(sizeof(CRYPT_PKCS12_PBE_PARAMS) + 16);
	pbeParams->cbSalt = 16;
	pbeParams->iIterations = 100000;
	char* salt = ((char *)pbeParams) + sizeof(CRYPT_PKCS12_PBE_PARAMS);
	for (int i = 0; i < 16; i++)
	{
		salt[i] = i;
	}
	bufferDesc.pBuffers[2].pvBuffer = pbeParams;
	bufferDesc.pBuffers[2].cbBuffer = sizeof(CRYPT_PKCS12_PBE_PARAMS);
	bufferDesc.pBuffers[2].BufferType = NCRYPTBUFFER_PKCS_ALG_PARAM;

	//bufferDesc.pBuffers[1].BufferType = NCRYPTBUFFER_CERT_BLOB;
	//bufferDesc.pBuffers[1].cbBuffer = certBlob.cbData;
	//bufferDesc.pBuffers[1].pvBuffer = certBlob.pbData;
	
	status = NCryptExportKey(keyHandle, NULL, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &bufferDesc, NULL, 0, &cbResult, 0);
	pKeyBlob = (BCRYPT_ECCKEY_BLOB*)new char[cbResult];
	status = NCryptExportKey(keyHandle, NULL, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &bufferDesc, (PBYTE)pKeyBlob, cbResult, &cbResult, 0);
	if (evaluateStatus(status) != 0)
	{
		CertFreeCertificateContext(pContext);
//		CertFreeCertificateContext(pContext2);
		CertCloseStore(certStore, 0);
		NCryptFreeObject(provHandle);
		NCryptFreeObject(keyHandle);
		NCryptFreeObject(nKeyHandle2);
		BCryptDestroyKey(keyHandle2);
		delete[] pKeyBlob;
//		delete[] pPubKeyBlob;
		return -1;
	}
	CertFreeCertificateContext(pContext);
	CertCloseStore(certStore, 0);
}

