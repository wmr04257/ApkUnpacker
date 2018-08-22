#include <stdio.h>
#include <windows.h>

char *enc_dex;
char space1[0xe0] = { 0, };

int offset = 0;
DWORD v7 = 0; DWORD v8 = 0; DWORD v9 = 0;
int v12 = 0; int v14 = 0;

DWORD dex_len = 0xe0;
int magic = 32;

DWORD cnt = 0;
int i = 0;

void decrypt_dex(BYTE *ret,BYTE *argv)
{
	enc_dex = (char *)malloc(0xe0);
	memcpy(enc_dex, argv, 0xe0);
	cnt = dex_len / 8;

	v12 = -1640531527 * magic;
	v14 = -1640531527 * magic + magic * 1640531527;
	while (i < cnt)
	{
		offset = 8 * (i & 1);
		v7 = *(DWORD *)(enc_dex + 4);
		v8 = *(DWORD *)(space1 + offset) ^ *(DWORD *)enc_dex;
		*(DWORD *)enc_dex = v8;
		v9 = *(DWORD *)(space1 + offset + 4) ^ v7;
		*(DWORD *)(enc_dex + 4) = v9;

		for (int j = v12; j != v14; j += 1640531527)
		{
			v9 -= (v8 + j) ^ (16 * v8 + *(DWORD*)(space1 + 8)) ^ ((v8 >> 5) + *(DWORD *)(space1 + 12));
			v8 -= (v9 + j) ^ (16 * v9 + *(DWORD*)space1) ^ ((v9 >> 5) + *(DWORD *)(space1 + 4));
		}
		*(DWORD *)enc_dex = v8;
		*(DWORD *)(enc_dex + 4) = v9;

		memcpy(ret, enc_dex, 4);
		memcpy(ret+4, enc_dex+4, 4);

		++i;
		enc_dex += 8;
		ret += 8;
	}
}

int main(int argc, char **argv)
{

	BYTE decrypt_data[0xFF] = { 0, };
	BYTE * encrypt_data = NULL;
	int file_size = 0;
	
	if (argc < 2)
	{
		printf("argv[1] Error\n");
		return -1;
	}

	HANDLE dex_handle=CreateFileA(argv[1], GENERIC_WRITE | GENERIC_READ,FILE_SHARE_READ ,NULL, OPEN_ALWAYS, 0, NULL);

	file_size =GetFileSize(dex_handle, NULL);
	
	if (file_size < 1)
	{
		printf("size Error\n");
		return -1;
	}
	encrypt_data = (BYTE *)malloc(file_size);
	
	ReadFile(dex_handle, encrypt_data, file_size, NULL, NULL);
	CloseHandle(dex_handle);
	
	for (int i = 0; i < file_size; i++)
	{//\x39\xE4\xF2\x36\x19\x9D\x9B\x09
		if (encrypt_data[i] == 0x39)
		{
			if (encrypt_data[i + 1] == 0xe4)
			{
				if (encrypt_data[i + 2] == 0xF2)
				{
					if (encrypt_data[i + 3] == 0x36)
					{
						if (encrypt_data[i + 4] == 0x19)
						{
							if (encrypt_data[i + 5] == 0x9d)
							{
								if (encrypt_data[i + 6] == 0x9b)
								{
									if (encrypt_data[i + 7] == 0x09)
									{
										decrypt_dex(decrypt_data,encrypt_data+i);
										
										int dec_dex_size= *(DWORD *)(decrypt_data + 32);
										HANDLE dec_dex_handle = CreateFileA("dec_classes.dex", GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ , NULL, CREATE_NEW, 0, NULL);

										//printf("%x %x\n", encrypt_data + i + 0xe0, dec_dex_size - 0xe0);

										WriteFile(dec_dex_handle, decrypt_data, 0xe0, NULL, NULL);
										WriteFile(dec_dex_handle, encrypt_data + i + 0xe0, dec_dex_size - 0xe0, NULL, NULL);
										/*
										for (int i = 0; i < 0xe0; i++) {

										printf("%02x", decrypt_data[i]);
										}
										*/

										CloseHandle(dec_dex_handle);
										printf("Success!\n");
										return 0;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	printf("Unknown Error\n");
	return -1;

}


