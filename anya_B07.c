#define FUSE_USE_VERSION 28
#include "stdio.h"
#include "string.h"
#include "unistd.h"
#include "dirent.h"
#include "time.h"
#include "fcntl.h"
#include "errno.h"
#include "fuse.h"
#include "pwd.h"
#include "sys/time.h"
#include "sys/types.h"

static int ANIMEKU = 0;
static int IAN = 1;
static int NAM_DO_SAQ = 2;

static char rootPath[1024];
static char wibuLogPath[1024];
static char innuLogPath[1024];
static char *vigenereKey = "INNUGANTENG";
static int vigenereKeyLength = 11;

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

int isRegularFile(const char *path)
{
	struct stat pathStat;
	stat(path, &pathStat);
	return S_ISREG(pathStat.st_mode);
}

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

void getFileNameFromPath(char *fileName, const char *path)
{
	int offset = strlen(path);
	while(offset >= 0 && path[offset] != '/')
	{
		offset--;
	}
	
	strcpy(fileName, path + offset + 1);
}

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
