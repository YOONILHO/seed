#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "KISA_SEED_CBC.h"

#define PROCESS_BLOCK_LEN	32
#define READ_BLOCK_SIZE		8192
#define VERSION			"1.1"

BYTE pbszUserKey[16] = {0x088, 0x0e3, 0x04f, 0x08f, 0x008, 0x017, 0x079, 0x0f1, 0x0e9, 0x0f3, 0x094, 0x037, 0x00a, 0x0d4, 0x005, 0x089}; 
BYTE pbszIV[16] = {0x026, 0x08d, 0x066, 0x0a7, 0x035, 0x0a8, 0x01a, 0x081, 0x06f, 0x0ba, 0x0d9, 0x0fa, 0x036, 0x016, 0x025, 0x001};
BYTE pbszInputText[80] = {0x00};
unsigned int outbuf[PROCESS_BLOCK_LEN];
KISA_SEED_INFO info;
int nRetOutLeng = 0;

int help(char* arg)
{
	printf("Version %s\n", VERSION);
	printf("Usage   %s [option...]\n", arg);
	printf("        -h           : Help message\n");
	printf("        -s           : Silent mode\n");
	printf("        -v           : Verbose mode\n");
	printf("        -p string    : Encrypt PlainText string\n");
	printf("        -c string    : Decrypt CipherText string\n");
	printf("        -K string    : Use key string\n");
	printf("        -k file_name : Use key file\n");
	printf("        -e file_name : Encrypt PlainText file\n");
	printf("        -d file_name : Decrypt CipherText file\n");
	printf("        -o file_name : Output by file_name\n");
	exit(-1);
}

int CBC_Loop(BYTE* pDest, BYTE* pSrc, int msgSize)
{
	int i;
	unsigned int *data;
	BYTE *cdata;
	int remainleng = 0;

	for (i = 0; i < msgSize - PROCESS_BLOCK_LEN;)
	{
		memcpy(pbszInputText, pSrc + i, PROCESS_BLOCK_LEN);
		data = chartoint32_for_SEED_CBC(pbszInputText, PROCESS_BLOCK_LEN);
		SEED_CBC_Process(&info, data, PROCESS_BLOCK_LEN, outbuf, &nRetOutLeng);
		cdata = int32tochar_for_SEED_CBC(outbuf, nRetOutLeng);
		memcpy(pDest + i, cdata, nRetOutLeng);
		i += nRetOutLeng;
		free(data);
		free(cdata);
	}
	remainleng = msgSize % PROCESS_BLOCK_LEN;
	if (remainleng == 0)
		remainleng = PROCESS_BLOCK_LEN;

	memcpy(pbszInputText, pSrc + i, remainleng);
	data = chartoint32_for_SEED_CBC(pbszInputText, remainleng);
	SEED_CBC_Process(&info, data, remainleng, outbuf, &nRetOutLeng);
	free(data);
	cdata = int32tochar_for_SEED_CBC(outbuf, nRetOutLeng);
	memcpy(pDest + i, cdata, nRetOutLeng);
	i += nRetOutLeng;
	free(cdata);

	return i;
}

int encryption(BYTE* pDest, BYTE* pSrc, int msgSize)
{
	BYTE *cdata;
	int nOutputTextLen;
	int nPaddingLeng = 0;

	// Incryption Algorithm //
	SEED_CBC_init(&info, KISA_ENCRYPT, pbszUserKey, pbszIV);

	nOutputTextLen = CBC_Loop(pDest, pSrc, msgSize);
	SEED_CBC_Close(&info, outbuf, &nPaddingLeng);
	cdata = int32tochar_for_SEED_CBC(outbuf, nPaddingLeng);
	memcpy(pDest + nOutputTextLen, cdata, nPaddingLeng);
	free(cdata);

	return (nOutputTextLen + nPaddingLeng);
}

int decryption(BYTE* pDest, BYTE* pSrc, int msgSize)
{
	int nOutputTextLen;
	int nPaddingLeng = 0;

	// Decryption Algorithm //
	if (msgSize % BLOCK_SIZE_SEED > 0)
		return 0;

	SEED_CBC_init(&info, KISA_DECRYPT, pbszUserKey, pbszIV);
	nOutputTextLen = CBC_Loop(pDest, pSrc, msgSize);
	if (SEED_CBC_Close(&info, outbuf + (nRetOutLeng)/4, &nPaddingLeng) > 0)
		return (nOutputTextLen - nPaddingLeng);

	return 0;
}

// method 2 start
int main(int argc, char *argv[])
{
	int opt;
	int opt_plain = 0;
	int opt_cyper = 0;
	int opt_encrypt = 0;
	int opt_decrypt = 0;
	int opt_silent = 0;
	int opt_verbose = 0;
	char *file_name = NULL;
	char *out_file_name = NULL;
	char *key_file_name = NULL;
	char *input_string = NULL;
	char *key_str = NULL;

	FILE *fp_in;
	FILE *fp_out;
	char output_filename[1024];

	while ((opt = getopt(argc, argv, "hk:K:p:c:e:d:o:sv")) != -1)
	{
		switch(opt)
		{
			case 'h':
				help(argv[0]);
				break;
			case 'k':
				key_file_name = optarg;
				break;
			case 'K':
				key_str = optarg;
				break;
			case 'p':
				opt_plain = 1;
				input_string = optarg;
				break;
			case 'c':
				opt_cyper = 1;
				input_string = optarg;
				break;
			case 'e':
				opt_encrypt = 1;
				file_name = optarg;
				break;
			case 'd':
				opt_decrypt = 1;
				file_name = optarg;
				break;
			case 'o':
				out_file_name = optarg;
				break;
			case 's':
				opt_silent = 1;
				break;
			case 'v':
				opt_verbose = 1;
				break;
		}
	}

	if (key_file_name && key_str)
		help(argv[0]);

	if (key_file_name != NULL)
	{
		FILE *fp_key;
		char temp[255];
		char *ptr;
		BYTE input_key[BLOCK_SIZE_SEED];
		long key;
		int i;

		if ((fp_key = fopen(key_file_name, "rb")) == NULL)
		{
			printf("key file open fail(%s)\n", key_file_name);
			exit(-1);
		}
		for (i = 0; i < BLOCK_SIZE_SEED; i++)
		{
			if (fgets(temp, sizeof(temp), fp_key) == NULL)
				break;
			if (strlen(temp) >= BLOCK_SIZE_SEED)
				break;
                        key = strtol(temp, &ptr, 16);
			if ((ptr - temp) < 4)
			{
				printf("key format error(line %d) : %s\n", i + 1, temp);
				break;
			}
			input_key[i] = (BYTE)key;
		}
		if (i == BLOCK_SIZE_SEED)
			memcpy(pbszUserKey, input_key, BLOCK_SIZE_SEED);
		else
		{
			printf("key size error(%d)\n", i);
			exit (-1);
		}
		fclose(fp_key);
	}

	if (key_str != NULL)
	{
		if (opt_verbose) printf("Input Key String : %s\n", key_str);

		if (strlen(key_str) == BLOCK_SIZE_SEED)
		{
			memcpy(pbszUserKey, key_str, BLOCK_SIZE_SEED);
		}
		else if (strlen(key_str) == BLOCK_SIZE_SEED*2)
		{
			char temp[3];
			BYTE input_key[BLOCK_SIZE_SEED];
			char *ptr;
			long key;

			for (int i = 0; i < BLOCK_SIZE_SEED; i++)
			{
				temp[0] = key_str[2*i + 0];
				temp[1] = key_str[2*i + 1];
				temp[2] = '\0';
				key = strtol(temp, &ptr, 16);
				if ((ptr - temp) < 2)
				{
					printf("key format error(%s)\n", temp);
					exit (-1);
				}
				input_key[i] = (BYTE)key;
			}
			memcpy(pbszUserKey, input_key, BLOCK_SIZE_SEED);
		}
		else
		{
			printf("key size error(%d)\n", strlen(key_str));
			exit (-1);
		}
	}
	
	if (opt_plain && opt_cyper)
		help(argv[0]);

	if (opt_plain)
	{
		BYTE *outbuf;
		int nOutputTextLen;

		outbuf = (BYTE*)malloc(strlen(input_string) + BLOCK_SIZE_SEED);
		nOutputTextLen = encryption(outbuf, (BYTE*)input_string, strlen(input_string));
		if (opt_verbose) printf("\bInput String(%d)  : %s\n", strlen(input_string), input_string);
		if (!opt_silent) printf ("Encrypted String : ");
		for (int i = 0; i < nOutputTextLen; i++)
			printf("%02X", outbuf[i]);
#ifndef _WIN32
		putchar('\n');
#endif

		free(outbuf);
		if (nOutputTextLen == 0)
			return -2;
		else
			return 0;
	}

	if (opt_cyper)
	{
		BYTE *inbuf;
		BYTE *outbuf;
		char temp[sizeof(short) + 1];
		char *ptr;
		long key;
		int msgSize;
		int nOutputTextLen;

		msgSize = strlen(input_string);

		if (msgSize % (BLOCK_SIZE_SEED*2))
		{
			printf ("\nDecrypted String Size Error: %d", msgSize);
			return -1;
		}

		inbuf = (BYTE*)malloc(msgSize/2);
		outbuf = (BYTE*)malloc(msgSize + BLOCK_SIZE_SEED);
		temp[sizeof(short)] = '\0';
		for (int i = 0; i < msgSize/sizeof(short); i++)
		{
			memcpy(temp, input_string + i*sizeof(short), sizeof(short));
			key = strtol(temp, &ptr, 16);
			inbuf[i] = (BYTE)key;
		}
		if (opt_verbose) 
		{
			printf ("Input String(%d)  : ", msgSize/2);
			for (int i = 0; i < msgSize/2; i++)
				printf("%02X ", inbuf[i]);
			putchar('\n');
		}

		nOutputTextLen = decryption(outbuf, inbuf, msgSize/2);
		if (!opt_silent) printf ("Decrypted String : ");
		for (int i = 0; i < nOutputTextLen; i++)
			putchar(outbuf[i]);
#ifndef _WIN32
		putchar('\n');
#endif

		free(inbuf);
		free(outbuf);
		if (nOutputTextLen == 0)
			return -2;
		else
			return 0;
	}

	if ((opt_encrypt + opt_decrypt == 0) || (opt_encrypt * opt_decrypt == 1))
		help(argv[0]);

	if (out_file_name != NULL)
	{
		if (strlen(out_file_name) > sizeof(output_filename))
		{
			printf("output file name is too long(%d)\n", strlen(out_file_name));
			exit(-1);
		}
		strcpy(output_filename, out_file_name);
	}
	else
	{
		if (strlen(file_name) + 3 > sizeof(output_filename))
		{
			printf("file name is too long(%d)\n", strlen(file_name));
			exit(-1);
		}
		strcpy(output_filename, file_name);

		if (opt_encrypt)
			strcat(output_filename, ".en");
		else
			strcat(output_filename, ".de");

	}
	
	if ((fp_out = fopen(output_filename, "wb")) == NULL)
	{
		printf("output file open fail(%s)\n", output_filename);
		exit(-1);
	}

	if ((fp_in = fopen(file_name, "rb")) != NULL)
	{
		BYTE inputBuffer[READ_BLOCK_SIZE + BLOCK_SIZE_SEED];
		BYTE outputBuffer[READ_BLOCK_SIZE + BLOCK_SIZE_SEED];
		int msgSize;
		int nOutputTextLen;
		BYTE *cdata;
		int nPaddingLeng = 0;

		if (!opt_silent)
		{
			printf ("\nUser Key : ");
			for (int i = 0; i < BLOCK_SIZE_SEED; i++)
				printf("%02X ", pbszUserKey[i]);
		}
		
		if (opt_encrypt)
		{
			if (!opt_silent) printf ("\n\nEncryption.... %s\n", file_name);
			SEED_CBC_init(&info, KISA_ENCRYPT, pbszUserKey, pbszIV);
		}
		else
		{
			if (!opt_silent) printf ("\n\nDecryption.... %s\n", file_name);
			SEED_CBC_init(&info, KISA_DECRYPT, pbszUserKey, pbszIV);
		}

		while((msgSize = fread(inputBuffer, 1, READ_BLOCK_SIZE, fp_in)) > 0)
		{
			if (opt_verbose) printf("Input Msg Size  = %d\n", msgSize);
			if (!opt_silent && !opt_verbose) putchar('.');
			if (msgSize < READ_BLOCK_SIZE)
				break;
			nOutputTextLen = CBC_Loop(outputBuffer, inputBuffer, msgSize);
			fwrite(outputBuffer, 1, nOutputTextLen, fp_out);
			if (opt_verbose) printf("Output Msg Size = %d\n", nOutputTextLen);
		}
		nOutputTextLen = CBC_Loop(outputBuffer, inputBuffer, msgSize);

		if (opt_encrypt)
		{
			SEED_CBC_Close(&info, outbuf, &nPaddingLeng);
			cdata = int32tochar_for_SEED_CBC(outbuf, nPaddingLeng);
			memcpy(outputBuffer + nOutputTextLen, cdata, nPaddingLeng);
			free(cdata);

			fwrite(outputBuffer, 1, nOutputTextLen + nPaddingLeng, fp_out);
			if (opt_verbose) printf("\bOutput Msg Size = %d\n", nOutputTextLen + nPaddingLeng);
		}
		else
		{
			if (SEED_CBC_Close(&info, outbuf + (nRetOutLeng)/4, &nPaddingLeng) > 0)
			{
				fwrite(outputBuffer, 1, nOutputTextLen - nPaddingLeng, fp_out);
				if (opt_verbose) printf("\bOutput Msg Size = %d\n", nOutputTextLen - nPaddingLeng);
			}
			else
				if (opt_verbose) printf("\bOutput Msg Size = 0\n");
		}
		fclose(fp_in);
	}
	else
	{
#ifdef _WIN32
		printf("file open fail(%s)", file_name);
#else
		printf("file open fail!(%s)\n", file_name);
#endif
		exit (-1);
	}

	fclose(fp_out);
	if (!opt_silent) printf("\nOutput file is %s\n", output_filename);
}
