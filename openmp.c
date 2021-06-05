// AES 128 bits block and key length performed in ECB
// the encryption should use PKCS#5 or PKCS#7 padding

#define _CRT_SECURE_NO_WARNINGS

#include <openssl/aes.h>

#include <stdio.h>
#include <omp.h>

#include <string.h>
#include <malloc.h>

void sequentialAES(unsigned char* inBuf, unsigned char* outBuf, long int outLen, FILE* fEncrypted, AES_KEY akey) {

	// encrypt
	for (int i = 0; i < (outLen / AES_BLOCK_SIZE); i++) {
		AES_encrypt(&(inBuf[i * AES_BLOCK_SIZE]), &(outBuf[i * AES_BLOCK_SIZE]), &akey);
	}
	fwrite(outBuf, outLen, 1, fEncrypted);

	fclose(fEncrypted);
}

void parallelAES(unsigned char* inBuf, unsigned char* outBuf, long int outLen, FILE* fEncrypted, AES_KEY akey,
	int lowLimit, int upLimit) {

	int noThreads = omp_get_num_procs();
	int interval = (upLimit - lowLimit) / noThreads;

#pragma omp parallel
	{
		int id = omp_get_thread_num();
		int lLimit = id * interval + lowLimit;
		int uLimit = (id + 1) * interval + lowLimit - 1;

		if (id == (noThreads - 1)) {
			uLimit = upLimit;
		}

		for (unsigned i = lLimit; i < uLimit; i++) {
			AES_encrypt(&(inBuf[i * AES_BLOCK_SIZE]), &(outBuf[i * AES_BLOCK_SIZE]), &akey);
		}
	}

	fwrite(outBuf, outLen, 1, fEncrypted);

	fclose(fEncrypted);
}

void benchmarkSeq(void (*pf)(unsigned char*, unsigned char*, long int, FILE*, AES_KEY),
	unsigned char* inBuf, unsigned char* outBuf, long int outLen, FILE* fEncrypted, AES_KEY akey) {

	printf("\nTest for sequential AES.");

	double tStart = omp_get_wtime();
	pf(inBuf, outBuf, outLen, fEncrypted, akey);
	double tFinal = omp_get_wtime();

	printf("\nDuration: %f (sec)", tFinal - tStart);
}

void benchmarkParallel(void (*pf)(unsigned char*, unsigned char*, long int, FILE*, AES_KEY, int, int),
	unsigned char* inBuf, unsigned char* outBuf, long int outLen, FILE* fEncrypted, AES_KEY akey, int lowLimit, int upLimit) {

	printf("\nTest for parallel AES.");

	double tStart = omp_get_wtime();
	pf(inBuf, outBuf, outLen, fEncrypted, akey, lowLimit, upLimit);
	double tFinal = omp_get_wtime();

	printf("\nDuration: %f (sec)", tFinal - tStart);
}

int main(int argc, char* argv[]) {
	// the solution gets the filename and the AES symmetric key by its main function arguments
	// encryptme.txt 62990EB44EB0898D

	FILE* fOriginal = fopen(argv[1], "rb");
	FILE* fEncrypted = fopen("encrypted_sequential.txt", "wb");

	// get key
	unsigned char key[AES_BLOCK_SIZE];
	memcpy(key, argv[2], AES_BLOCK_SIZE);

	// get files size
	fseek(fOriginal, 0, SEEK_END);
	long int fOriginalLen = ftell(fOriginal);
	fseek(fOriginal, 0, SEEK_SET);

	long int fEncryptedLen = 0;

	unsigned char* inBuf;
	unsigned char* outBuf;

	inBuf = (unsigned char*)malloc(fOriginalLen);

	if ((fOriginalLen % AES_BLOCK_SIZE) == 0) {
		fEncryptedLen = fOriginalLen;

		
		outBuf = (unsigned char*)malloc(fEncryptedLen);
	}
	else {
		fEncryptedLen = ((fOriginalLen / AES_BLOCK_SIZE) * AES_BLOCK_SIZE) + AES_BLOCK_SIZE;
		
		outBuf = (unsigned char*)malloc(fEncryptedLen);

		// PKCS#7 padding
		int bytes = AES_BLOCK_SIZE - (fOriginalLen % AES_BLOCK_SIZE);

		switch (bytes) {
		case 1:
			memset(inBuf, 0x01, fEncryptedLen);
			break;
		case 2:
			memset(inBuf, 0x02, fEncryptedLen);
			break;
		case 3:
			memset(inBuf, 0x03, fEncryptedLen);
			break;
		case 4:
			memset(inBuf, 0x04, fEncryptedLen);
			break;
		case 5:
			memset(inBuf, 0x05, fEncryptedLen);
			break;
		case 6:
			memset(inBuf, 0x06, fEncryptedLen);
			break;
		case 7:
			memset(inBuf, 0x07, fEncryptedLen);
			break;
		case 8:
			memset(inBuf, 0x08, fEncryptedLen);
			break;
		case 9:
			memset(inBuf, 0x09, fEncryptedLen);
			break;
		case 10:
			memset(inBuf, 0x0A, fEncryptedLen);
			break;
		case 11:
			memset(inBuf, 0x0B, fEncryptedLen);
			break;
		case 12:
			memset(inBuf, 0x0C, fEncryptedLen);
			break;
		case 13:
			memset(inBuf, 0x0D, fEncryptedLen);
			break;
		case 14:
			memset(inBuf, 0x0E, fEncryptedLen);
			break;
		case 15:
			memset(inBuf, 0x0F, fEncryptedLen);
			break;
		}
	}

	// put file contents in buffer
	fread(inBuf, fOriginalLen, 1, fOriginal);

	fclose(fOriginal);

	// set the key
	AES_KEY akey;
	AES_set_encrypt_key(key, AES_BLOCK_SIZE * 8, &akey);

	// figure out sections
	int lowLimit = 0;
	int upLimit = fOriginalLen / AES_BLOCK_SIZE;

	benchmarkSeq(sequentialAES, inBuf, outBuf, fEncryptedLen, fEncrypted, akey);
	printf("\n");

	fEncrypted = fopen("encrypted_parallel.txt", "wb");
	benchmarkParallel(parallelAES, inBuf, outBuf, fEncryptedLen, fEncrypted, akey, lowLimit, upLimit);
	printf("\n");

	return 0;
}
