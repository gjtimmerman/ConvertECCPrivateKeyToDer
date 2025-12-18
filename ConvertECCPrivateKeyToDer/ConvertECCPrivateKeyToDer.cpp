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
	fprintf(stderr, "BCrypt error code: 0x%08X\n", status);
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
	fprintf(stderr, "Cryptographic function returned error code: 0x%08X\n", status);
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
	case NTE_BAD_KEY_STATE:
		fprintf(stderr, "NTE_BAD_KEY_STATE\n");
		return 1;
	case NTE_BAD_TYPE:
		fprintf(stderr, "NTE_BAD_TYPE\n");
		return 1;
	case NTE_PERM:
		fprintf(stderr, "NTE_PERM - Access denied\n");
		return 1;

	case NTE_NOT_SUPPORTED:
		fprintf(stderr, "Cryptographic function returned error code: NTE_NOT_SUPPORTED");
		return 1;

	default:
		fprintf(stderr, "Cryptographic function returned unknown error code");
		return 1;

	}

}

// Add this function before main() - implements PKCS#12 key derivation
void PKCS12_KDF(
	const wchar_t* password,
	DWORD cbPassword,
	const unsigned char* salt,
	DWORD saltLen,
	DWORD iterations,
	BYTE id,
	unsigned char* output,
	DWORD outputLen)
{
	NTSTATUS bStatus;
	BCRYPT_ALG_HANDLE hAlg;
	bStatus = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
	if (evaluateBStatus(bStatus) != 0)
	{
		return;
	}


	const DWORD v = 64;
	const DWORD u = 20;

	// Convert password to BMPString (UTF-16BE + null terminator)
	DWORD passCharCount = cbPassword / 2;
	DWORD passLen = (passCharCount + 1) * 2;
	unsigned char* pass = new unsigned char[passLen];

	for (DWORD i = 0; i < passCharCount; i++)
	{
		pass[i * 2] = (password[i] >> 8) & 0xFF;
		pass[i * 2 + 1] = password[i] & 0xFF;
	}
	pass[passCharCount * 2] = 0;
	pass[passCharCount * 2 + 1] = 0;

	// Step 1: Construct D
	unsigned char* D = new unsigned char[v];
	memset(D, id, v);

	// Step 2: Handle salt and password padding
	DWORD sLen = (saltLen > 0) ? v : 0;
	DWORD pLen = v;
	DWORD iLen = sLen + pLen;

	unsigned char* I = new unsigned char[iLen];

	// Fill I with S || P
	if (saltLen > 0)
	{
		for (DWORD i = 0; i < v; i++)
			I[i] = salt[i % saltLen];
	}

	for (DWORD i = 0; i < v; i++)
		I[sLen + i] = pass[i % passLen];

	DWORD c = (outputLen + u - 1) / u;
	unsigned char* A = new unsigned char[u];
	unsigned char* B = new unsigned char[v];

	for (DWORD i = 0; i < c; i++)
	{
		// Hash D || I
		BCRYPT_HASH_HANDLE hHash;
		bStatus = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
		if (evaluateBStatus(bStatus) != 0)
		{
			BCryptCloseAlgorithmProvider(hAlg, 0);
			return;
		}

		bStatus = BCryptHashData(hHash, D, v, 0);
		if (evaluateBStatus(bStatus) != 0)
		{
			BCryptDestroyHash(hHash);
			BCryptCloseAlgorithmProvider(hAlg, 0);
			return;
		}

		bStatus = BCryptHashData(hHash, I, iLen, 0);  
		if (evaluateBStatus(bStatus) != 0)
		{
			BCryptDestroyHash(hHash);
			BCryptCloseAlgorithmProvider(hAlg, 0);
			return;
		}
		bStatus = BCryptFinishHash(hHash, A, u, 0);
		if (evaluateBStatus(bStatus) != 0)
		{
			BCryptDestroyHash(hHash);
			BCryptCloseAlgorithmProvider(hAlg, 0);
			return;
		}

		bStatus = BCryptDestroyHash(hHash);
		if (evaluateBStatus(bStatus) != 0)
		{
			BCryptCloseAlgorithmProvider(hAlg, 0);
			return;
		}

		// Perform iterations
		for (DWORD j = 1; j < iterations; j++)
		{
			bStatus = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
			if (evaluateBStatus(bStatus) != 0)
			{
				BCryptCloseAlgorithmProvider(hAlg, 0);
				return;
			}

			bStatus = BCryptHashData(hHash, A, u, 0);
			if (evaluateBStatus(bStatus) != 0)
			{
				BCryptDestroyHash(hHash);
				BCryptCloseAlgorithmProvider(hAlg, 0);
				return;
			}
			bStatus = BCryptFinishHash(hHash, A, u, 0);
			if (evaluateBStatus(bStatus) != 0)
			{
				BCryptDestroyHash(hHash);
				BCryptCloseAlgorithmProvider(hAlg, 0);
				return;
			}

			bStatus = BCryptDestroyHash(hHash);
			if (evaluateBStatus(bStatus) != 0)
			{
				BCryptCloseAlgorithmProvider(hAlg, 0);
				return;
			}
		}

		// Copy output
		DWORD copyLen = min(u, outputLen - i * u);
		memcpy(output + i * u, A, copyLen);

		if (i < c - 1)
		{
			// Create B by repeating A
			for (DWORD j = 0; j < v; j++)
				B[j] = A[j % u];

			// Compute B + 1
			unsigned int carry = 1;
			for (int k = v - 1; k >= 0 && carry; k--)
			{
				unsigned int sum = B[k] + carry;
				B[k] = sum & 0xFF;
				carry = sum >> 8;
			}

			// Add B to each block of I
			DWORD numBlocks = iLen / v;
			for (DWORD j = 0; j < numBlocks; j++)
			{
				carry = 0;
				for (int k = v - 1; k >= 0; k--)
				{
					unsigned int sum = I[j * v + k] + B[k] + carry;
					I[j * v + k] = sum & 0xFF;
					carry = sum >> 8;
				}
			}
		}
	}

	BCryptCloseAlgorithmProvider(hAlg, 0);

	delete[] D;
	delete[] I;
	delete[] A;
	delete[] B;
	delete[] pass;
}


int main(int argc, char* argv[])
{

	if (argc != 3)
	{
		std::cout << "Usage: " << argv[0] << " subjectName password" << std::endl;
		return -1;
	}
	HCERTSTORE certStore = CertOpenSystemStore(NULL, L"My");
	if (!certStore)
	{
		fprintf(stderr, "Failed to open certificate store. Error: 0x%08X\n", GetLastError());
		return -1;
	}
	wchar_t* wideSubjectName = new wchar_t[strlen(argv[1]) + 1];
	size_t numBytes;
	mbstowcs_s(&numBytes, wideSubjectName, (size_t)strlen(argv[1]) + 1, argv[1], (size_t)strlen(argv[1]));
	fprintf(stderr, "Searching for certificate with subject: %S\n", wideSubjectName);
	wchar_t* password= new wchar_t[strlen(argv[2]) + 1];
	mbstowcs_s(&numBytes, password, (size_t)strlen(argv[2]) + 1, argv[2], (size_t)strlen(argv[2]));
	PCCERT_CONTEXT pContext = CertFindCertificateInStore(certStore, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, wideSubjectName, NULL);
	if (!pContext)
	{
		fprintf(stderr, "Certificate not found\n");
		delete[] wideSubjectName;
		CertCloseStore(certStore, 0);
		return -1;
	}
	delete[] wideSubjectName;
	NCRYPT_KEY_HANDLE keyHandle;
	DWORD keySpec;
	BOOL release;
	BOOL ret = CryptAcquireCertificatePrivateKey(pContext, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &keyHandle, &keySpec, &release);
	if (!ret)
	{
		fprintf(stderr, "Failed with NCRYPT flag. Trying without...\n");
		ret = CryptAcquireCertificatePrivateKey(pContext, 0, NULL, &keyHandle, &keySpec, &release);
		if (!ret)
		{
			fprintf(stderr, "Failed to acquire private key\n");
			CertFreeCertificateContext(pContext);
			CertCloseStore(certStore, 0);
			return -1;
		}
	}

	fprintf(stderr, "Private key acquired. KeySpec: 0x%08X\n", keySpec);


	DWORD cbResult;

	DWORD cbProviderName = 0;
	SECURITY_STATUS status = NCryptGetProperty(keyHandle, NCRYPT_PROVIDER_HANDLE_PROPERTY, NULL, 0, &cbProviderName, 0);
	if (status == ERROR_SUCCESS)
	{
		wchar_t* providerName = new wchar_t[cbProviderName / sizeof(wchar_t) + 1];
		status = NCryptGetProperty(keyHandle, NCRYPT_UNIQUE_NAME_PROPERTY, (PBYTE)providerName, cbProviderName, &cbProviderName, 0);
		if (status == ERROR_SUCCESS)
		{
			fprintf(stderr, "Key unique name: %S\n", providerName);
		}
		delete[] providerName;
	}

	DWORD dwPolicy = 0;
	DWORD cbData = sizeof(DWORD);
	status = NCryptGetProperty(keyHandle, NCRYPT_EXPORT_POLICY_PROPERTY,
		(PBYTE)&dwPolicy, cbData, &cbData, 0);
	if (status == ERROR_SUCCESS)
	{
		fprintf(stderr, "Export policy: 0x%08X\n", dwPolicy);
		if (dwPolicy & NCRYPT_ALLOW_EXPORT_FLAG)
			fprintf(stderr, "  - NCRYPT_ALLOW_EXPORT_FLAG: YES\n");
		if (dwPolicy & NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG)
			fprintf(stderr, "  - NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG: YES\n");
	}
	DWORD dwImplType = 0;
	status = NCryptGetProperty(keyHandle, NCRYPT_IMPL_TYPE_PROPERTY,
		(PBYTE)&dwImplType, sizeof(DWORD), &cbData, 0);
	if (status == ERROR_SUCCESS)
	{
		fprintf(stderr, "Implementation type: 0x%08X\n", dwImplType);
		if (dwImplType & NCRYPT_IMPL_HARDWARE_FLAG)
			fprintf(stderr, "  - HARDWARE (TPM/Smart Card)\n");
		if (dwImplType & NCRYPT_IMPL_SOFTWARE_FLAG)
			fprintf(stderr, "  - SOFTWARE\n");
		if (dwImplType & NCRYPT_IMPL_REMOVABLE_FLAG)
			fprintf(stderr, "  - REMOVABLE\n");
		if (dwImplType & NCRYPT_IMPL_HARDWARE_RNG_FLAG)
			fprintf(stderr, "  - HARDWARE RNG\n");
	}

	unsigned char* pKeyBlob = NULL;
	NCryptBufferDesc bufferDesc;
	bufferDesc.cBuffers = 3;
	bufferDesc.pBuffers = new NCryptBuffer[3];
	bufferDesc.ulVersion = NCRYPTBUFFER_VERSION;
	bufferDesc.pBuffers[0].BufferType = NCRYPTBUFFER_PKCS_SECRET;
	bufferDesc.pBuffers[0].pvBuffer = (PVOID)password;
	bufferDesc.pBuffers[0].cbBuffer = (ULONG)(wcslen(password)+1) * sizeof(wchar_t);
	bufferDesc.pBuffers[1].BufferType = NCRYPTBUFFER_PKCS_ALG_OID;
	bufferDesc.pBuffers[1].pvBuffer = (void*)"1.2.840.113549.1.12.1.3\0";

	bufferDesc.pBuffers[1].cbBuffer = (ULONG)(strlen((const char*)bufferDesc.pBuffers[1].pvBuffer) + 1);
	const DWORD saltLength = 16;  // 16 bytes is recommended
	const DWORD iterationCount = 600000;  // OWASP 2023 recommendation for PBKDF2


	CRYPT_PKCS12_PBE_PARAMS *pbeParams = (CRYPT_PKCS12_PBE_PARAMS *)malloc(sizeof(CRYPT_PKCS12_PBE_PARAMS) + saltLength);
	pbeParams->cbSalt = saltLength;
	pbeParams->iIterations = iterationCount;
	// Generate cryptographically secure random salt
	unsigned char* pSalt = ((unsigned char*)pbeParams) + sizeof(CRYPT_PKCS12_PBE_PARAMS);
	NTSTATUS ntStatus = BCryptGenRandom(NULL, pSalt, saltLength, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (ntStatus != 0)
	{
		fprintf(stderr, "Failed to generate random salt\n");
		free(pbeParams);
		return -1;
	}
	fprintf(stderr, "\n=== PBE Parameters ===\n");
	fprintf(stderr, "Salt (%d bytes): ", saltLength);
	for (DWORD i = 0; i < saltLength; i++)
		fprintf(stderr, "%02X ", pSalt[i]);
	fprintf(stderr, "\nIterations: %d\n", iterationCount);

	bufferDesc.pBuffers[2].pvBuffer = pbeParams;
	bufferDesc.pBuffers[2].cbBuffer = sizeof(CRYPT_PKCS12_PBE_PARAMS) + saltLength;
	bufferDesc.pBuffers[2].BufferType = NCRYPTBUFFER_PKCS_ALG_PARAM;


//	status = NCryptExportKey(keyHandle, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, NULL, 0, &cbResult, 0);
	status = NCryptExportKey(keyHandle, NULL, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &bufferDesc, NULL, 0, &cbResult, 0);
	if (evaluateStatus(status) != 0)
	{
		CertFreeCertificateContext(pContext);
		CertCloseStore(certStore, 0);
		NCryptFreeObject(keyHandle);
		delete[] pKeyBlob;
		return -1;
	}
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
	HANDLE myFile = CreateFile(L"EncryptedKeyBlob.der", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD written;
	WriteFile(myFile, pKeyBlob, cbResult, &written, NULL);
	FlushFileBuffers(myFile);
	CloseHandle(myFile);

	NTSTATUS bStatus;
	BCRYPT_ALG_HANDLE algHandle;
	//	char salt[9];
	char keyData[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + 192 / 8];
	unsigned char iv[8] = {};
	BCRYPT_KEY_HANDLE derivedKeyHandle;
	bStatus = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA1_ALGORITHM, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (evaluateBStatus(bStatus) != 0)
		return 0;


	// After successfully exporting the encrypted key, add diagnostic code:

	fprintf(stderr, "\n=== Encrypted PKCS#8 Blob Analysis ===\n");
	fprintf(stderr, "Total blob size: %d bytes\n\n", cbResult);

	// Dump the blob in hex
	fprintf(stderr, "Blob hex dump:\n");
	for (DWORD i = 0; i < cbResult; i++)
	{
		fprintf(stderr, "%02X ", pKeyBlob[i]);
		if ((i + 1) % 16 == 0) fprintf(stderr, "\n");
	}
	fprintf(stderr, "\n\n");

	// Try to decode using CryptDecodeObjectEx
	CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* pEncryptedKeyInfo = NULL;
	DWORD cbDecoded = 0;

	BOOL decodeResult = CryptDecodeObjectEx(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		PKCS_ENCRYPTED_PRIVATE_KEY_INFO,
		pKeyBlob,
		cbResult,
		CRYPT_DECODE_ALLOC_FLAG,
		NULL,
		&pEncryptedKeyInfo,
		&cbDecoded);

	if (decodeResult && pEncryptedKeyInfo)
	{
		fprintf(stderr, "=== Successfully decoded EncryptedPrivateKeyInfo ===\n");
		fprintf(stderr, "Algorithm OID: %s\n", pEncryptedKeyInfo->EncryptionAlgorithm.pszObjId);
		fprintf(stderr, "Parameters size: %d bytes\n", pEncryptedKeyInfo->EncryptionAlgorithm.Parameters.cbData);

		if (pEncryptedKeyInfo->EncryptionAlgorithm.Parameters.cbData > 0)
		{
			fprintf(stderr, "Parameters hex:\n");
			for (DWORD i = 0; i < pEncryptedKeyInfo->EncryptionAlgorithm.Parameters.cbData; i++)
			{
				fprintf(stderr, "%02X ", pEncryptedKeyInfo->EncryptionAlgorithm.Parameters.pbData[i]);
				if ((i + 1) % 16 == 0) fprintf(stderr, "\n");
			}
			fprintf(stderr, "\n");

			// Try to decode parameters as PKCS12_PBE_PARAMS
			CRYPT_DATA_BLOB paramsBlob;
			paramsBlob.cbData = pEncryptedKeyInfo->EncryptionAlgorithm.Parameters.cbData;
			paramsBlob.pbData = pEncryptedKeyInfo->EncryptionAlgorithm.Parameters.pbData;
			BYTE* pEncryptedData = pEncryptedKeyInfo->EncryptedPrivateKey.pbData;
			DWORD encryptedDataLen = pEncryptedKeyInfo->EncryptedPrivateKey.cbData;
			CRYPT_ALGORITHM_IDENTIFIER* pAlgParams = NULL;
			DWORD cbAlgParams = 0;
			unsigned char decrypted[168];
			ULONG cbOutput = 0;

			// The parameters contain a SEQUENCE with salt and iterations
			// Manual parse: skip SEQUENCE tag (0x30) and length
			unsigned char* pParams = pEncryptedKeyInfo->EncryptionAlgorithm.Parameters.pbData;
			int offset = 0;

			bStatus = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_3DES_ALGORITHM, NULL, 0);
			if (evaluateBStatus(bStatus) != 0)
			{
				LocalFree(pEncryptedKeyInfo);
				return 0;
			}




			if (pParams[offset] == 0x30) // SEQUENCE
			{
				offset++;
				int seqLen = pParams[offset];
				offset++;
				fprintf(stderr, "\nParsing parameters SEQUENCE (length=%d):\n", seqLen);

				// Extract salt (OCTET STRING tag = 0x04)
				if (pParams[offset] == 0x04)
				{
					offset++;
					int saltLen = pParams[offset];
					offset++;
					fprintf(stderr, "Salt found (length=%d): ", saltLen);

					unsigned char* extractedSalt = pParams + offset;
					for (int i = 0; i < saltLen; i++)
					{
						fprintf(stderr, "%02X ", extractedSalt[i]);
					}
					fprintf(stderr, "\n");
					offset += saltLen;

					// Extract iterations (INTEGER tag = 0x02)
					if (pParams[offset] == 0x02)
					{
						offset++;
						int iterLen = pParams[offset];
						offset++;
						int iterations = 0;
						for (int i = 0; i < iterLen; i++)
						{
							iterations = (iterations << 8) | pParams[offset + i];
						}
						fprintf(stderr, "Iterations: %d\n", iterations);

						// Now derive keys with PKCS#12 KDF (NOT PBKDF2!)
						fprintf(stderr, "\n=== Deriving encryption key and IV using PKCS#12 KDF ===\n");

						// Derive key (ID=1)
						PKCS12_KDF(
							password,
							(ULONG)wcslen(password) * sizeof(wchar_t),
							extractedSalt,
							saltLen,
							iterations,
							1,  // ID for key material
							(PUCHAR)keyData + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER),
							192 / 8);

						// Derive IV (ID=2)
						PKCS12_KDF(
							password,
							(ULONG)wcslen(password) * sizeof(wchar_t),
							extractedSalt,
							saltLen,
							iterations,
							2,  // ID for IV
							iv,
							8);
					}
				}

			}
			else
			{

				// Fall back to defaults
				PKCS12_KDF(password, (ULONG)(wcslen(password)) * sizeof(wchar_t), NULL, 0, 0, 1,
					(PUCHAR)keyData + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), 192 / 8);
				PKCS12_KDF(password, (ULONG)(wcslen(password)) * sizeof(wchar_t), NULL, 0, 0, 2, iv, 8);
			}


			fprintf(stderr, "Derived 3DES Key (24 bytes): ");
			for (int i = 0; i < 24; i++)
				fprintf(stderr, "%02X ", ((unsigned char*)keyData)[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + i]);
			fprintf(stderr, "\n");

			fprintf(stderr, "Derived IV (8 bytes): ");
			for (int i = 0; i < 8; i++)
				fprintf(stderr, "%02X ", iv[i]);
			fprintf(stderr, "\n");

			BCRYPT_KEY_DATA_BLOB_HEADER* pKeyDataHeader = (BCRYPT_KEY_DATA_BLOB_HEADER*)keyData;
			pKeyDataHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
			pKeyDataHeader->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
			pKeyDataHeader->cbKeyData = 192 / 8;

			fprintf(stderr, "\nImporting 3DES key...\n");
			fprintf(stderr, "Key header magic: 0x%08X\n", pKeyDataHeader->dwMagic);
			fprintf(stderr, "Key header version: %d\n", pKeyDataHeader->dwVersion);
			fprintf(stderr, "Key data length: %d bytes\n", pKeyDataHeader->cbKeyData);

			fprintf(stderr, "Key1 (DES key 1): ");
			for (int i = 0; i < 8; i++)
				fprintf(stderr, "%02X ", ((unsigned char*)keyData)[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + i]);
			fprintf(stderr, "\nKey2 (DES key 2): ");
			for (int i = 8; i < 16; i++)
				fprintf(stderr, "%02X ", ((unsigned char*)keyData)[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + i]);
			fprintf(stderr, "\nKey3 (DES key 3): ");
			for (int i = 16; i < 24; i++)
				fprintf(stderr, "%02X ", ((unsigned char*)keyData)[sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + i]);
			fprintf(stderr, "\n\n");


			bStatus = BCryptImportKey(algHandle, NULL, BCRYPT_KEY_DATA_BLOB, &derivedKeyHandle, NULL, 0,
				(PUCHAR)keyData, sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + 192 / 8, 0);
			if (evaluateBStatus(bStatus) != 0)
			{
				fprintf(stderr, "BCryptImportKey failed\n");
				LocalFree(pEncryptedKeyInfo);
				return 0;
			}

			fprintf(stderr, "3DES key imported successfully\n");
			fprintf(stderr, "Attempting decryption with 3-key 3DES-CBC...\n");
			fprintf(stderr, "Encrypted data: %d bytes\n", encryptedDataLen);
			fprintf(stderr, "IV: ");
			for (int i = 0; i < 8; i++)
				fprintf(stderr, "%02X ", iv[i]);
			fprintf(stderr, "\n\n");


			bStatus = BCryptDecrypt(derivedKeyHandle, pEncryptedData, encryptedDataLen, NULL,
				iv, 8, decrypted, 168, &cbOutput, BCRYPT_BLOCK_PADDING);

			if (evaluateBStatus(bStatus) != 0)
			{
				fprintf(stderr, "Decryption failed\n");
				BCryptDestroyKey(derivedKeyHandle);
				LocalFree(pEncryptedKeyInfo);
				return 0;

			}
			BCryptDestroyKey(derivedKeyHandle);

			
			// Save the decrypted data as DER file
			HANDLE hKeyFile = CreateFile(L"DecryptedKey.der", GENERIC_WRITE, 0, NULL,
				CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
			WriteFile(hKeyFile, decrypted, cbOutput, &written, NULL);
			CloseHandle(hKeyFile);

			fprintf(stderr, "\nSaved decrypted data to DecryptedPrivateKey.der\n");

			LocalFree(pEncryptedKeyInfo);
			CRYPT_PRIVATE_KEY_INFO* pDecryptedKey = NULL;
			cbDecoded = 0;

			BOOL decodeResult = CryptDecodeObjectEx(
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				PKCS_PRIVATE_KEY_INFO,
				decrypted,
				cbOutput,
				CRYPT_DECODE_ALLOC_FLAG,
				NULL,
				&pDecryptedKey,
				&cbDecoded);
			if (decodeResult && pDecryptedKey)
			{
				fprintf(stderr, "=== Successfully decoded decrypted PrivateKeyInfo ===\n");
				fprintf(stderr, "Algorithm OID: %s\n", pDecryptedKey->Algorithm.pszObjId);
				// Decode ECC curve parameters
				if (pDecryptedKey->Algorithm.Parameters.cbData > 0)
				{
					fprintf(stderr, "\n=== ECC Curve Parameters ===\n");
					LPSTR *pszCurveOid = NULL;
					DWORD cbCurveOid = 0;

					if (CryptDecodeObjectEx(
						X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
						X509_OBJECT_IDENTIFIER,
						pDecryptedKey->Algorithm.Parameters.pbData,
						pDecryptedKey->Algorithm.Parameters.cbData,
						CRYPT_DECODE_ALLOC_FLAG,
						NULL,
						&pszCurveOid,
						&cbCurveOid))
					{
						fprintf(stderr, "Curve OID: %s", *pszCurveOid);

						if (strcmp(*pszCurveOid, "1.2.840.10045.3.1.7") == 0)
							fprintf(stderr, " (NIST P-256 / secp256r1)");
						else if (strcmp(*pszCurveOid, "1.3.132.0.34") == 0)
							fprintf(stderr, " (NIST P-384 / secp384r1)");
						else if (strcmp(*pszCurveOid, "1.3.132.0.35") == 0)
							fprintf(stderr, " (NIST P-521 / secp521r1)");

						fprintf(stderr, "\n");
						LocalFree(pszCurveOid);
					}
				}
				fprintf(stderr, "Private key size: %d\n", pDecryptedKey->PrivateKey.cbData);
				fprintf(stderr, "Number of attributes: %d\n", pDecryptedKey->pAttributes->cAttr);
				fprintf(stderr, "Attributes OID: %s\n", pDecryptedKey->pAttributes->rgAttr[0].pszObjId);
				fprintf(stderr, "Attributes number: %d\n", pDecryptedKey->pAttributes->rgAttr[0].cValue);
				if (pDecryptedKey->pAttributes && pDecryptedKey->pAttributes->cAttr > 0)
				{
					fprintf(stderr, "Number of attributes: %d\n", pDecryptedKey->pAttributes->cAttr);

					for (DWORD attrIdx = 0; attrIdx < pDecryptedKey->pAttributes->cAttr; attrIdx++)
					{
						fprintf(stderr, "\n--- Attribute[%d] ---\n", attrIdx);
						fprintf(stderr, "Attribute OID: %s\n", pDecryptedKey->pAttributes->rgAttr[attrIdx].pszObjId);
						fprintf(stderr, "Attribute value count: %d\n", pDecryptedKey->pAttributes->rgAttr[attrIdx].cValue);
						if (strcmp(pDecryptedKey->pAttributes->rgAttr[attrIdx].pszObjId, "2.5.29.15") == 0)
						{
							fprintf(stderr, "Type: Key Usage Extension\n");

							for (DWORD valIdx = 0; valIdx < pDecryptedKey->pAttributes->rgAttr[attrIdx].cValue; valIdx++)
							{
								DWORD valueSize = pDecryptedKey->pAttributes->rgAttr[attrIdx].rgValue[valIdx].cbData;
								BYTE* valueData = pDecryptedKey->pAttributes->rgAttr[attrIdx].rgValue[valIdx].pbData;

								fprintf(stderr, "Attribute value size: %d bytes\n", valueSize);
								fprintf(stderr, "Raw value hex: ");
								for (DWORD i = 0; i < valueSize; i++)
									fprintf(stderr, "%02X ", valueData[i]);
								fprintf(stderr, "\n");
								// the ASN.1 structure breakdown
								if (valueSize >= 4 && valueData[0] == 0x03)
								{
									fprintf(stderr, "ASN.1 BIT STRING breakdown:\n");
									fprintf(stderr, "  Tag: 0x%02X (BIT STRING)\n", valueData[0]);
									fprintf(stderr, "  Length: %d bytes\n", valueData[1]);
									fprintf(stderr, "  Unused bits: %d\n", valueData[2]);
									fprintf(stderr, "  Data byte(s): ");
									for (DWORD i = 3; i < valueSize; i++)
										fprintf(stderr, "0x%02X ", valueData[i]);
									fprintf(stderr, "\n");
								}

								// Decode as BIT STRING
								CRYPT_BIT_BLOB* pKeyUsage = NULL;
								DWORD cbKeyUsage = 0;

								if (CryptDecodeObjectEx(
									X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
									X509_BITS,
									valueData,
									valueSize,
									CRYPT_DECODE_ALLOC_FLAG,
									NULL,
									&pKeyUsage,
									&cbKeyUsage))
								{
									fprintf(stderr, "\n=== Key Usage Flags ===\n");
									if (pKeyUsage->cbData > 0)
									{
										BYTE usageByte1 = pKeyUsage->pbData[0];

										if (usageByte1 & 0x80) fprintf(stderr, "  [X] digitalSignature (0x80)\n");
										else fprintf(stderr, "  [ ] digitalSignature\n");

										if (usageByte1 & 0x40) fprintf(stderr, "  [X] nonRepudiation (0x40)\n");
										else fprintf(stderr, "  [ ] nonRepudiation\n");

										if (usageByte1 & 0x20) fprintf(stderr, "  [X] keyEncipherment (0x20)\n");
										else fprintf(stderr, "  [ ] keyEncipherment\n");

										if (usageByte1 & 0x10) fprintf(stderr, "  [X] dataEncipherment (0x10)\n");
										else fprintf(stderr, "  [ ] dataEncipherment\n");

										if (usageByte1 & 0x08) fprintf(stderr, "  [X] keyAgreement (0x08)\n");
										else fprintf(stderr, "  [ ] keyAgreement\n");

										if (usageByte1 & 0x04) fprintf(stderr, "  [X] keyCertSign (0x04)\n");
										else fprintf(stderr, "  [ ] keyCertSign\n");

										if (usageByte1 & 0x02) fprintf(stderr, "  [X] cRLSign (0x02)\n");
										else fprintf(stderr, "  [ ] cRLSign\n");

										if (usageByte1 & 0x01) fprintf(stderr, "  [X] encipherOnly (0x01)\n");
										else fprintf(stderr, "  [ ] encipherOnly\n");

										// Second byte (if present)
										if (pKeyUsage->cbData > 1)
										{
											BYTE usageByte2 = pKeyUsage->pbData[1];
											if (usageByte2 & 0x80) fprintf(stderr, "  [X] decipherOnly (0x8000)\n");
											else fprintf(stderr, "  [ ] decipherOnly\n");
										}
									}
									LocalFree(pKeyUsage);
								}
								else
								{
									fprintf(stderr, "Failed to decode Key Usage BIT STRING: 0x%08X\n", GetLastError());
								}
							}
						}
						else
						{
							fprintf(stderr, "Type: Other attribute\n");
						}
					}
				}
				fprintf(stderr, "Private key: ");
				for (DWORD i = 0; i < pDecryptedKey->PrivateKey.cbData; i++)
					fprintf(stderr, "%02X ", pDecryptedKey->PrivateKey.pbData[i]);
				fprintf(stderr, "\n");
				CRYPT_ECC_PRIVATE_KEY_INFO* pEccKey = NULL;
				decodeResult = CryptDecodeObjectEx(
					X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
					X509_ECC_PRIVATE_KEY,
					pDecryptedKey->PrivateKey.pbData,
					pDecryptedKey->PrivateKey.cbData,
					CRYPT_DECODE_ALLOC_FLAG,
					NULL,
					&pEccKey,
					&cbDecoded);
				if (decodeResult && pEccKey)
				{
					fprintf(stderr, "\n=== Successfully decoded ECC Private Key Blob ===\n");
					fprintf(stderr, "ECC Private key size: %d\n", pEccKey->PrivateKey.cbData);
					fprintf(stderr, "ECC Private key: ");
					for (DWORD i = 0; i < pEccKey->PrivateKey.cbData; i++)
						fprintf(stderr, "%02X ", pEccKey->PrivateKey.pbData[i]);
					fprintf(stderr, "\n");
				}
				else
				{
					fprintf(stderr, "Failed to decode ECC Private Key Blob: %x\n", GetLastError());
				}
				if (pEccKey->PublicKey.cbData > 0)
				{
					fprintf(stderr, "\n=== ECC Public Key (from PrivateKeyInfo) ===\n");
					fprintf(stderr, "Public key size: %d bytes\n", pEccKey->PublicKey.cbData);
					fprintf(stderr, "Public key unused bits: %d\n", pEccKey->PublicKey.cUnusedBits);
					if (pEccKey->PublicKey.pbData[0] == 0x04)
					{
						fprintf(stderr, "Format: Uncompressed point\n");

						// Calculate coordinate size (excluding the 0x04 byte)
						DWORD coordSize = (pEccKey->PublicKey.cbData - 1) / 2;

						fprintf(stderr, "X coordinate (%d bytes):\n", coordSize);
						for (DWORD i = 1; i <= coordSize; i++)
							fprintf(stderr, "%02X ", pEccKey->PublicKey.pbData[i]);

						fprintf(stderr, "\nY coordinate (%d bytes):\n", coordSize);
						for (DWORD i = coordSize + 1; i < pEccKey->PublicKey.cbData; i++)
							fprintf(stderr, "%02X ", pEccKey->PublicKey.pbData[i]);

						fprintf(stderr, "\n");
					}
					else if (pEccKey->PublicKey.pbData[0] == 0x02)
					{
						fprintf(stderr, "Format: Compressed point (Y is even)\n");
						fprintf(stderr, "X coordinate:\n");
						for (DWORD i = 1; i < pEccKey->PublicKey.cbData; i++)
							fprintf(stderr, "%02X ", pEccKey->PublicKey.pbData[i]);
						fprintf(stderr, "\n");
					}
					else if (pEccKey->PublicKey.pbData[0] == 0x03)
					{
						fprintf(stderr, "Format: Compressed point (Y is odd)\n");
						fprintf(stderr, "X coordinate:\n");
						for (DWORD i = 1; i < pEccKey->PublicKey.cbData; i++)
							fprintf(stderr, "%02X ", pEccKey->PublicKey.pbData[i]);
						fprintf(stderr, "\n");
					}
					else
					{
						fprintf(stderr, "Unknown point format: 0x%02X\n", pEccKey->PublicKey.pbData[0]);
					}
				}

			}
			else
			{
				fprintf(stderr, "Failed to decode decrypted PrivateKeyInfo: %x\n", GetLastError());
			}
			LocalFree(pDecryptedKey);


		}

		return 0;
	}
}

