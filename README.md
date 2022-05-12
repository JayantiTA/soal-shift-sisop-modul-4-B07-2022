# Soal Shift Sisop Modul 4 B07 2022

Repository untuk soal shift sisop modul 4 tahun 2022

Anggota:

1. [Hans Sean Nathanael](https://gitlab.com/HansSeanNathanael) (5025201019)
2. [Jayanti Totti Andhina](https://gitlab.com/JayantiTA) (5025201037)
3. [Agnesfia Anggraeni](https://gitlab.com/agnesfiaa) (5025201059)

Karena ketiga permasalahan saling berkaitan dan diprogram dalam 1 file, maka laporan praktikum nomor 1 sampai 3 dijadikan satu juga. Sebagian besar function yang digunakan juga saling tumpang tindih.

```C++
static int ANIMEKU = 0;
static int IAN = 1;
static int NAM_DO_SAQ = 2;

static char rootPath[1024];
static char wibuLogPath[1024];
static char innuLogPath[1024];
static char *vigenereKey = "INNUGANTENG";
static int vigenereKeyLength = 11;
```

Pertama-tama membuat variable static yang perlu digunakan. Variabel rootPath untuk menyimpan path directory "/home/[USER]/Documents", wibuLogPath untuk menyimpan current working directory program sebagai lokasi penyimpanan log wibu pada nomor 1, dan innuLogPath untuk menyimpan path file log pada nomor 2.

```C++
char atbashCipher(char c)
{
	if (c >= 'A' && c <= 'Z')
	{
		return 'Z' - (c - 'A'); 
	}
	return -1;
}

char rot13(char c)
{
	if (c >= 'a' && c <= 'm')
	{
		return c + 13;
	}
	else if (c >= 'n' && c <= 'z')
	{
		return c - 13;
	}
	return -1;
}

char vigenereCipherEncode(char c, int i)
{
	int addition = vigenereKey[i % vigenereKeyLength] - 'A';
	if (c >= 'a' && c <= 'z')
	{
		return (c - 'a' + addition) % 26 + 'a';
	}
	else if (c >= 'A' && c <= 'Z')
	{
		return (c - 'A' + addition) % 26 + 'A';
	}
	return c;
}

char vigenereCipherDecode(char c, int i)
{
	int addition = vigenereKey[i % vigenereKeyLength] - 'A';
	if (c >= 'a' && c <= 'z')
	{
		return (c - 'a' + 26 - addition) % 26 + 'a';
	}
	else if (c >= 'A' && c <= 'Z')
	{
		return (c - 'A' + 26 - addition) % 26 + 'A';
	}
	return c;
}

void convertBinerToDecimal(char decimal[], char binary[])
{
	unsigned long long int decimalValue = 0;
	int length = strlen(binary);
	for (int i = 0; i < length; i++)
	{
		decimalValue <<= 1;
		decimalValue += binary[i] - '0';
	}
	sprintf(decimal, "%d", decimalValue);
}

void convertDecimalToBinary(char binary[], char decimal[])
{
	unsigned long long int decimalValue = 0;
	int length = strlen(decimal);
	for (int i = 0; i < length; i++)
	{
		decimalValue *= 10;
		decimalValue += decimal[i] - '0';
	}
	
	length = 0;
	for (length = 0; decimalValue > 0; length++)
	{
		binary[length] = decimalValue % 2 + '0';
		decimalValue >>= 1;
	}
	
	char temp;
	for (int i = 0; i < length/2; i++)
	{
		temp = binary[i];
		binary[i] = binary[length - 1 - i];
		binary[length - 1 - i] = temp;
	}
	
	binary[length] = '\0';
}
```

Function di atas digunakan untuk melakukan enkripsi dan dekripsi string. atbashCipher dan rot13 menggunakan fungsi yang sama untuk enkripsi dan dekripsi karena cara enkripsi dan dekripsinya sama dan digunakan untuk permasalahan nomor 1; vigenereCipherEncode dan vigenereCipherDecode digunakan pada permasalahan nomor 2; convertBinerToDecimal dan convertDecimalToBinary digunakan pada permasalahan nomor 3.

```C++
int isRegularFile(const char *path)
{
	struct stat pathStat;
	stat(path, &pathStat);
	return S_ISREG(pathStat.st_mode);
}
```

Function isRegularFile digunakan untuk mengecek apakah path merupakan sebuah file. Ini digunakan pada readdir karena sistem enkripsi file dengan directory berbeda.

```C++
int getEncryptionType(const char *path, int *offset)
{
	int encryptionType = -1;
	if (strncmp(path + *offset, "/Animeku_", 9) == 0)
	{
		encryptionType = ANIMEKU;
	}
	else if (strncmp(path + *offset, "/IAN_", 5) == 0)
	{
		encryptionType = IAN;
	}
	else if (strncmp(path + *offset, "/nam_do-saq_", 12) == 0)
	{
		encryptionType = NAM_DO_SAQ;
	}
	
	char *pos = strstr(path + *offset + 1, "/");
	if (pos != NULL)
	{
		*offset = pos - path;
	}
	else
	{
		*offset = -1;
	}
	return encryptionType;
}
```

Function getEncryptionType digunakan untuk mengecek sub string path untuk menentukan enkripsi atau dekripsi apakah yang diperlukan. Sub string yang di cek adalah nama folder atau file, sehingga jenis enkripsi ditentukan oleh nama folder yang paling dalam, contohnya bila ada directory /Animeku_A/IAN_B/..., maka semua folder dan file di dalam IAN_B adkan dienkripsi dengan vigenere.

```C++
void decryptText(char *str, int startIndex, int endIndex, int encryptionType)
{
	int vigenereIndex = 0;
	
	if (encryptionType != NAM_DO_SAQ && encryptionType != -1)
	{
		for (int i = startIndex; i < endIndex; i++)
		{
			if (encryptionType == ANIMEKU)
			{
				if (str[i] >= 'a' && str[i] <= 'z')
				{
					str[i] = rot13(str[i]);
				}
				else if (str[i] >= 'A' && str[i] <= 'Z')
				{
					str[i] = atbashCipher(str[i]);
				}
			}
			else if (encryptionType == IAN)
			{
				str[i] = vigenereCipherDecode(str[i], vigenereIndex);
				vigenereIndex++;
			}
		}
	}
	else if (encryptionType == NAM_DO_SAQ)
	{
		if (endIndex != -1)
		{
			char binary[128];
			convertDecimalToBinary(binary, str + endIndex);
			int length = strlen(binary);
			for (int i = length-1; i >= 0; i--)
			{
				if (binary[i] == '1')
				{
					str[startIndex] = str[startIndex] - 'A' + 'a';
				}
				startIndex--;
			}
		}
	}
}

void decryptFile(char *str, int startIndex, int endIndex, int encryptionType)
{
	int fileExtensionPos = endIndex - 1;
	if (encryptionType == ANIMEKU)
	{
		while(fileExtensionPos >= startIndex && str[fileExtensionPos] != '.')
		{
			fileExtensionPos--;
		}
		if (fileExtensionPos < startIndex)
		{
			decryptText(str, startIndex, endIndex, encryptionType);
		}
		else
		{
			decryptText(str, startIndex, fileExtensionPos + 1, encryptionType);
		}
	}
	else if (encryptionType == IAN)
	{
		decryptText(str, startIndex, endIndex, encryptionType);
	}
	else if (encryptionType == NAM_DO_SAQ)
	{
		int fileExtensionPosDecimalCode = endIndex - 1;
		while(fileExtensionPosDecimalCode >= startIndex && str[fileExtensionPosDecimalCode] != '.')
		{
			fileExtensionPosDecimalCode--;
		}
		
		fileExtensionPos = fileExtensionPosDecimalCode - 1;
		while(fileExtensionPos >= startIndex && str[fileExtensionPos] != '.')
		{
			fileExtensionPos--;
		}
		
		if (fileExtensionPosDecimalCode < startIndex)
		{
			decryptText(str, startIndex, -1, encryptionType);
		}
		else if (fileExtensionPos < 0)
		{
			decryptText(str, fileExtensionPosDecimalCode - 1, fileExtensionPosDecimalCode + 1, encryptionType);
		}
		else
		{
			decryptText(str, fileExtensionPos - 1, fileExtensionPosDecimalCode + 1, encryptionType);
			str[fileExtensionPosDecimalCode] = '\0';
		}
	}
}

void decodeDirectoryPath(const char *path, int offset, int length, int encryptionType)
{
	char *slashPos = NULL;

	if (offset < length)
	{
		if ((slashPos = strstr(path + offset, "/")) != NULL)
		{
			if (encryptionType == NAM_DO_SAQ)
			{
				decryptText(path, offset, -1, encryptionType);
			}
			else
			{
				decryptText(path, offset, slashPos - path, encryptionType);
			}
		}
		else
		{
			decryptFile(path, offset, length, encryptionType);
		}
	}
}

int decodePath(char *filePath, const char *path)
{ 
	int encryptionType = -1;
	int pathStringLength = strlen(path);
	
	if (strcmp(path, "/") == 0)
	{
		sprintf(filePath, "%s", rootPath);
	}
	else
	{
		int offset = 0;
		while(offset != -1)
		{
			decodeDirectoryPath(path, offset + 1, pathStringLength, encryptionType);
			
			int nextEncryption = getEncryptionType(path, &offset);
			if (encryptionType == -1 || nextEncryption != -1)
			{
				encryptionType = nextEncryption;
			}
		}
		sprintf(filePath, "%s%s", rootPath, path);
	}
	
	return encryptionType;
}
```

Function di atas digunakan untuk mendekripsi path dan untuk function decodePath akan paling sering dipanggil untuk decode directory FUSE yang terenkripsi.

```C++
void decodeDirectoryForRename(const char *filePath, const char *path)
{
	char tempPath[1024];
	char tempPath2[1024];
	strcpy(tempPath, path);
	int slashFinder = strlen(tempPath) - 1;
	while(tempPath[slashFinder] != '/' && slashFinder >= 0)
	{
		slashFinder--;
	}
	if (slashFinder >= 0)
	{
		tempPath[slashFinder] = '\0';
	}
	
	decodePath(tempPath2, tempPath);
	strcat(tempPath, path + slashFinder);
	strcat(tempPath2, path + slashFinder);
	strcpy(filePath, tempPath2);
	strcpy(path, tempPath);
}
```

Function decodeDirectoryForRename digunakan untuk dekripsi path file khusus untuk lokasi directory suatu file atau folder dan membiarkan nama file atau foldernya tidak didekripsi. Fungsi ini akan digunakan pada implementasi rename dan mkdir.

```C++
void encryptText(char *str, int startIndex, int endIndex, int encryptionType)
{
	int vigenereIndex = 0;
	if (encryptionType != NAM_DO_SAQ)
	{
		for (int i = startIndex; i < endIndex; i++)
		{
			if (encryptionType == ANIMEKU)
			{
				if (str[i] >= 'a' && str[i] <= 'z')
				{
					str[i] = rot13(str[i]);
				}
				else if (str[i] >= 'A' && str[i] <= 'Z')
				{
					str[i] = atbashCipher(str[i]);
				}
			}
			else if (encryptionType == IAN)
			{
				str[i] = vigenereCipherEncode(str[i], vigenereIndex);
				vigenereIndex++;
			}
		}
	}
	else
	{
		char biner[endIndex - startIndex + 1];
		for (int i = 0; i < endIndex - startIndex; i++)
		{
			if (str[i] >= 'a' && str[i] <= 'z')
			{
				str[i] = str[i] - 'a' + 'A';
				biner[i] = '1';
			}
			else
			{
				biner[i] = '0';
			}
		}
		biner[endIndex - startIndex] = '\0';
		char decimal[128];
		convertBinerToDecimal(decimal, biner);
		strcat(str, ".");
		strcat(str, decimal);
	}
}

void encryptFile(char *str, int startIndex, int endIndex, int encryptionType)
{
	int fileExtensionPos = endIndex - 1;
	if (encryptionType == ANIMEKU || encryptionType == NAM_DO_SAQ)
	{
		while(fileExtensionPos >= startIndex && str[fileExtensionPos] != '.')
		{
			fileExtensionPos--;
		}
		if (fileExtensionPos < startIndex)
		{
			encryptText(str, startIndex, endIndex, encryptionType);
		}
		else
		{
			encryptText(str, startIndex, fileExtensionPos, encryptionType);
		}
	}
	else if (encryptionType == IAN)
	{
		encryptText(str, startIndex, endIndex, encryptionType);
	}
}
```

Function di atas adalah function untuk mengenkripsi string path. Enrkipsi hanya diperlukan pada implementasi readdir.

```C++
void getFileNameFromPath(char *fileName, const char *path)
{
	int offset = strlen(path);
	while(offset >= 0 && path[offset] != '/')
	{
		offset--;
	}
	
	strcpy(fileName, path + offset + 1);
}
```

Function getFileNameFromPath digunakan untuk mengambil nama file atau folder dari string path. Fungsi ini diperlukan untuk membuat log wibu karena harus mengecek apakah sebuah folder terenkripsi atau terdekripsi ketika di-rename.

```C++
void writeLog(char level[], char operand[], char arg1[], char arg2[])
{
	FILE *fileWriterInnuLogPath = fopen(innuLogPath, "a");
	time_t currentTime = time(NULL);
	struct tm currentLocalTime = *localtime(&currentTime);
	char logText[256];
	
	sprintf(logText, "%s::%02d%02d%04d-%02d:%02d:%02d::%s",
		level,
		currentLocalTime.tm_mday, 
		currentLocalTime.tm_mon,
		currentLocalTime.tm_year + 1900,
		currentLocalTime.tm_hour,
		currentLocalTime.tm_min,
		currentLocalTime.tm_sec,
		operand
	);

	if (strlen(arg1) != 0)
	{
		strcat(logText, "::");
		strcat(logText, arg1);
	}

	if (strlen(arg2) != 0)
	{
		strcat(logText, "::");
		strcat(logText, arg2);
	}
	fprintf(fileWriterInnuLogPath, "%s\n", logText);
	
	fclose(fileWriterInnuLogPath);
}
```

Function writeLog digunakan untuk membuat log innu (log permasalahan nomor 2). Struct tm dan function localtime digunakan untuk mengubah waktu time_t menjadi memiliki format tahun, bulan, tanggal, jam, menit, dan detik. 

```C++
static int fuse_getattr(const char *path, struct stat *st)
{
	char filePath[1024];
	decodePath(filePath, path);
	
	if (lstat(filePath, st) == -1)
	{
		return -errno;
	}
	
	return 0;
}
```

Pada implementasi getattr, string path akan didecode terlebih dahulu dan kemudian diambil statnya.

```C++
static int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	char filePath[1024];
	int encryptionType = decodePath(filePath, path);
	
	DIR *directory;
	struct dirent *dirData;
	struct stat st;
	char fileName[1024];

	(void) offset;
	(void) fi;
	
	directory = opendir(filePath);
	
	if (directory == NULL) 
	{
		return -errno;
	}	
	
	while((dirData = readdir(directory)) != NULL) 
	{
		memset(&st, 0, sizeof(st));
		
		st.st_ino = dirData->d_ino;
		st.st_mode = dirData->d_type << 12;
		
		
		strcpy(fileName, filePath);
		strcat(fileName, "/");
		strcat(fileName, dirData->d_name);
		if (isRegularFile(fileName))
		{	
			strcpy(fileName, dirData->d_name);
			encryptFile(fileName, 0, strlen(fileName), encryptionType);
		}
		else
		{
			strcpy(fileName, dirData->d_name);
			if (encryptionType != NAM_DO_SAQ)
			{
				encryptText(fileName, 0, strlen(fileName), encryptionType);
			}
		}

		if (filler(buf, fileName, &st, 0)) break;
	}
	
	closedir(directory);
	
	return 0;
}
```

Pada implementasi readdir, path akan didecode terlebih dahulu kemudian tipe enkripsi terakhir akan disimpan karena menentukan cara enkripsi file yang akan ditampilkan. Setelah didecode, path akan dibuka dan dibaca satu persatu nama file yang ada di dalamnya dan kemudian dicek apakah merupakan sebuah file atau diretory. Pengecekan ini penting karena file dan directory dienkripsi dengan cara yang berbeda.

```C++
static int fuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	char filePath[1024];
	decodePath(filePath, path);
	
	int fileDescriptor = 0;
	
	(void) fi;
	
	fileDescriptor = open(filePath, O_RDONLY);
	if (fileDescriptor == -1) 
	{ 
		return -errno;
	}
	
	fi->fh = fileDescriptor;
	int res = pread(fi->fh, buf, size, offset);
	close(fi->fh);
	
	writeLog("INFO", "READ", path, "");
	
	if (res == -1)
	{
		return -errno;
	}
	return res;
}
```

Pada implementasi read seperti sebelumnya, di awal akan didecode string pathnya kemudian dibuka file tersebut dan dibaca menggunakan function pread.

```C++
static int fuse_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	char filePath[1024];
	decodePath(filePath, path);
	
	FILE *fileWriterWibuLog = fopen(wibuLogPath, "a");
	fprintf(fileWriterWibuLog, "Write: %s\n", filePath);
	fclose(fileWriterWibuLog);
	
	int fileDescriptor = 0;
	
	(void) fi;
	
	fileDescriptor = open(filePath, O_WRONLY | O_APPEND);
	if (fileDescriptor == -1) 
	{ 
		return -errno;
	}
	
	fi->fh = fileDescriptor;
	pwrite(fi->fh, buf, size, offset);
	close(fi->fh);
	
	writeLog("INFO", "WRITE", path, "");
	
	return size;
}
```

Implementasi write tidak berhasil namun kode programnya tidak dihapus. File yang dibuka dari dalam directory FUSE tidak akan dapat di ganti isinya.

```C++
static int fuse_mkdir(const char *path, mode_t mode)
{
	char filePath[1024];
	decodeDirectoryForRename(filePath, path);
	
	writeLog("INFO", "MKDIR", path, "");
	
	return mkdir(filePath, mode |S_IFDIR);
}

static int fuse_rmdir(const char *path)
{
	char filePath[1024];
	decodePath(filePath, path);
	
	writeLog("WARNING", "RMDIR", path, "");
	
	return rmdir(filePath);
}

static int fuse_unlink(const char *path)
{
	char filePath[1024];
	decodePath(filePath, path);
	
	writeLog("WARNING", "UNLINK", path, "");
	
	return unlink(filePath);
}
```

Implementasi mkdir, rmdir, dan unlink sangat sederhana yaitu pertama memanggil decodePath kemudian langsung memanggil mkdir, rmdir, atau unlink.

```C++
static int fuse_rename(const char *old, const char *new)
{
	char filePathOld[1024];
	char filePathNew[1024];
	decodePath(filePathOld, old);
	decodeDirectoryForRename(filePathNew, new);
	
	char fileNameOld[1024];
	char fileNameNew[1024];
	
	getFileNameFromPath(fileNameOld, old);
	getFileNameFromPath(fileNameNew, new);
	
	FILE *fileWriterWibuLog = fopen(wibuLogPath, "a");
	if (strncmp(fileNameOld, "Animeku_", 8) == 0 && strncmp(fileNameNew, "Animeku_", 8) != 0)
	{
		fprintf(fileWriterWibuLog, "RENAME terdecode %s --> %s\n", old, new);
	}
	else if (strncmp(fileNameOld, "Animeku_", 8) != 0 && strncmp(fileNameNew, "Animeku_", 8) == 0)
	{
		fprintf(fileWriterWibuLog, "RENAME terenkripsi %s --> %s\n", old, new);
	}
	fclose(fileWriterWibuLog);

	writeLog("INFO", "RENAME", old, new);
	
	return rename(filePathOld, filePathNew);
}
```

Pada implementasi rename, string path yang lama akan didecode satu string penuh sedangkan untuk string path baru hanya akan didecode lokasi file atau folder sehingga nama file atau folder yang baru pada string path baru tidak akan didecode. Kemudian bila terdapat perubahan nama "Animeku_" akan dicatat di dalam log wibu.

Untuk log innu (log nomor 2) akan mencatat read, write, mkdir, rmdir, unlink, dan rename.

```C++
static struct fuse_operations fuseAnya = {
	.getattr = fuse_getattr,
	.readdir = fuse_readdir,
	.read = fuse_read,
	.write = fuse_write,
	.mkdir = fuse_mkdir,
	.rmdir = fuse_rmdir,
	.unlink = fuse_unlink,
	.rename = fuse_rename,
};
```

Di atas adalah daftar method yang diimplementasikan.

```C++
int main(int argc, char** argv)
{
	umask(0);
	
	struct passwd *pw = getpwuid(getuid());
	strcpy(rootPath, pw->pw_dir);
	strcat(rootPath, "/Documents");
	getcwd(wibuLogPath, sizeof(wibuLogPath));
	strcat(wibuLogPath, "/Wibu.log");
	strcpy(innuLogPath, rootPath);
	strcat(innuLogPath, "/hayolongapain_B07.log");
	return fuse_main(argc, argv, &fuseAnya, NULL);
}
```

Pada main, sebelum fuse dibuat akan menyimpan lokasi "/home/[USER]/Documents", kemudian current working directory untuk log wibu, dan path untuk log innu.

## Dokumentasi

### nomor 1

![dokumentasi_1](/uploads/6b07815671a8fe3bba3e58833d206a9a/dokumentasi_1.png)

![dokumentasi_2](/uploads/2b4fcf55c02e33b17582db5ea18621c4/dokumentasi_2.png)

![dokumentasi_3](/uploads/10936b2e7c575315cca4237dce177396/dokumentasi_3.png)

### nomor 2

![dokumentasi_4](/uploads/8ecf455392ba80598db7f42e67214d11/dokumentasi_4.png)

### nomor 3

![dokumentasi_6](/uploads/98b9f03a5769655f9188b3a3027d9e59/dokumentasi_6.png)

![dokumentasi_7](/uploads/7580c6b70e1978caacfbf430f7edcd05/dokumentasi_7.png)

![dokumentasi_8](/uploads/0c293cdee329ae3d2279be05292977ae/dokumentasi_8.png)
