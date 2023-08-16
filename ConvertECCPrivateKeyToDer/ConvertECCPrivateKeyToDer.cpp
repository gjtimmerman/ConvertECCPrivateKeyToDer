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


	BCRYPT_ECCKEY_BLOB *pKeyBlob = NULL;
	status = NCryptExportKey(keyHandle, nKeyHandle2, BCRYPT_ECCPRIVATE_BLOB, 0, NULL, 0, &cbResult, 0);
	pKeyBlob = (BCRYPT_ECCKEY_BLOB*)new char[cbResult];
	status = NCryptExportKey(keyHandle, nKeyHandle2, BCRYPT_ECCPRIVATE_BLOB, 0, (PBYTE)pKeyBlob, cbResult, &cbResult, 0);
	if (evaluateStatus(status) != 0)
	{
		CertFreeCertificateContext(pContext);
		CertFreeCertificateContext(pContext2);
		CertCloseStore(certStore, 0);
		NCryptFreeObject(provHandle);
		NCryptFreeObject(keyHandle);
		NCryptFreeObject(nKeyHandle2);
		BCryptDestroyKey(keyHandle2);
		delete[] pKeyBlob;
		delete[] pPubKeyBlob;
		return -1;
	}
	CertFreeCertificateContext(pContext);
	CertCloseStore(certStore, 0);
}

