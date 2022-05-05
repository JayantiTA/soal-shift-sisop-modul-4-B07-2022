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

void decryptText(char *str, int startIndex, int endIndex, int encryptionType)
{
	int vigenereIndex = 0;
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
}

void decodeDirectoryPath(const char *path, int encryptionType)
{
	int idx = 0;
	int length = strlen(path);
	char *slashPos;
	while(idx < length)
	{
		if ((slashPos = strstr(path + idx, "/")) != NULL)
		{
			decryptText(path, idx, slashPos - path, encryptionType);
			idx = slashPos - path + 1;
		}
		else
		{
			decryptFile(path, idx, length, encryptionType);
			idx = length;
		}
	}
}

void encryptText(char *str, int startIndex, int endIndex, int encryptionType)
{
	int vigenereIndex = 0;
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

void encryptFile(char *str, int startIndex, int endIndex, int encryptionType)
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
	char *pos;
	int encryptionType = -1;
	if ((pos = strstr(path, "/Animeku_")) != NULL)
	{
		encryptionType = ANIMEKU;
	}
	else if ((pos = strstr(path, "/IAN_")) != NULL)
	{
		encryptionType = IAN;
	}
	
	if (pos != NULL)
	{
		pos = strstr(pos+1, "/");
		if (pos != NULL)
		{
			*offset = pos - path + 1;
		}
		else
		{
			*offset = strlen(path);
		}
	}
	else
	{
		*offset = strlen(path);
	}
	return encryptionType;
}

int decodePath(char *filePath, const char *path)
{ 
	int encryptionType = -1;
	
	if (strcmp(path, "/") == 0)
	{
		sprintf(filePath, "%s", rootPath);
	}
	else
	{
		int offset = -1;
		encryptionType = getEncryptionType(path, &offset);
		if (encryptionType != -1)
		{
			decodeDirectoryPath(path + offset, encryptionType);
		}
		sprintf(filePath, "%s%s", rootPath, path);
	}
	
	return encryptionType;
}

void decodeDirectoryForRename(const char *path, const char *decodedPath)
{
	char tempPath[1024];
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
	
	int offset = -1;
	int encryptionType = getEncryptionType(tempPath, &offset);
	if (encryptionType != -1)
	{
		decodeDirectoryPath(tempPath + offset, encryptionType);
	}
	strcat(tempPath, path + slashFinder);
	if (decodedPath != NULL)
	{
		strcpy(decodedPath, tempPath);
	}
	sprintf(path, "%s%s", rootPath, tempPath);
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

static int fuse_getattr(const char *path, struct stat *st)
{
	int offset = -1;
	int encryptionType = getEncryptionType(path, &offset);
	if (encryptionType != -1)
	{
		decodeDirectoryPath(path + offset, encryptionType);
	}
	
	char filePath[1024];
	sprintf(filePath, "%s%s", rootPath, path);
	
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
		
		strcpy(fileName, dirData->d_name);
		if (encryptionType != -1)
		{
			encryptFile(fileName, 0, strlen(fileName), encryptionType);
		}
		if (filler(buf, fileName, &st, 0)) break;
	}
	
	closedir(directory);
	
	FILE *fileWriterInnuLogPath = fopen(innuLogPath, "a");
	time_t currentTime = time(NULL);
	struct tm currentLocalTime = *localtime(&currentTime);
	char logText[256];
	
	sprintf(logText, "WARNING::%02d%02d%04d-%02d:%02d:%02d::READDIR::%s", 
		currentLocalTime.tm_mday, 
		currentLocalTime.tm_mon,
		currentLocalTime.tm_year + 1900,
		currentLocalTime.tm_hour,
		currentLocalTime.tm_min,
		currentLocalTime.tm_sec,
		path
	);
	fprintf(fileWriterInnuLogPath, "%s\n", logText);
	
	fclose(fileWriterInnuLogPath);
	
	return 0;
}

static int fuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	char filePath[1024];
	int encryptionType = decodePath(filePath, path);
	
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
	
	FILE *fileWriterInnuLogPath = fopen(innuLogPath, "a");
	time_t currentTime = time(NULL);
	struct tm currentLocalTime = *localtime(&currentTime);
	char logText[256];
	
	sprintf(logText, "WARNING::%02d%02d%04d-%02d:%02d:%02d::READ::%s", 
		currentLocalTime.tm_mday, 
		currentLocalTime.tm_mon,
		currentLocalTime.tm_year + 1900,
		currentLocalTime.tm_hour,
		currentLocalTime.tm_min,
		currentLocalTime.tm_sec,
		path
	);
	fprintf(fileWriterInnuLogPath, "%s\n", logText);
	
	fclose(fileWriterInnuLogPath);
	
	if (res == -1)
	{
		return -errno;
	}
	return res;
}

static int fuse_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	char filePath[1024];
	int encryptionType = decodePath(filePath, path);
	
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
	
	FILE *fileWriterInnuLogPath = fopen(innuLogPath, "a");
	time_t currentTime = time(NULL);
	struct tm currentLocalTime = *localtime(&currentTime);
	char logText[256];
	
	sprintf(logText, "WARNING::%02d%02d%04d-%02d:%02d:%02d::WRITE::%s", 
		currentLocalTime.tm_mday, 
		currentLocalTime.tm_mon,
		currentLocalTime.tm_year + 1900,
		currentLocalTime.tm_hour,
		currentLocalTime.tm_min,
		currentLocalTime.tm_sec,
		path
	);
	fprintf(fileWriterInnuLogPath, "%s\n", logText);
	
	fclose(fileWriterInnuLogPath);
	
	return size;
}

static int fuse_mkdir(const char *path, mode_t mode)
{
	char filePath[1024];
	decodePath(filePath, path);
	
	FILE *fileWriterInnuLogPath = fopen(innuLogPath, "a");
	time_t currentTime = time(NULL);
	struct tm currentLocalTime = *localtime(&currentTime);
	char logText[256];
	
	sprintf(logText, "INFO::%02d%02d%04d-%02d:%02d:%02d::MKDIR::%s", 
		currentLocalTime.tm_mday, 
		currentLocalTime.tm_mon,
		currentLocalTime.tm_year + 1900,
		currentLocalTime.tm_hour,
		currentLocalTime.tm_min,
		currentLocalTime.tm_sec,
		path
	);
	fprintf(fileWriterInnuLogPath, "%s\n", logText);
	
	fclose(fileWriterInnuLogPath);
	
	return mkdir(filePath, mode);
}

static int fuse_rmdir(const char *path)
{
	char filePath[1024];
	decodePath(filePath, path);
	
	FILE *fileWriterInnuLogPath = fopen(innuLogPath, "a");
	time_t currentTime = time(NULL);
	struct tm currentLocalTime = *localtime(&currentTime);
	char logText[256];
	
	sprintf(logText, "WARNING::%02d%02d%04d-%02d:%02d:%02d::RMDIR::%s", 
		currentLocalTime.tm_mday, 
		currentLocalTime.tm_mon,
		currentLocalTime.tm_year + 1900,
		currentLocalTime.tm_hour,
		currentLocalTime.tm_min,
		currentLocalTime.tm_sec,
		path
	);
	fprintf(fileWriterInnuLogPath, "%s\n", logText);
	
	fclose(fileWriterInnuLogPath);
	
	return rmdir(filePath);
}

static int fuse_unlink(const char *path)
{
	char filePath[1024];
	decodePath(filePath, path);
	
	FILE *fileWriterInnuLogPath = fopen(innuLogPath, "a");
	time_t currentTime = time(NULL);
	struct tm currentLocalTime = *localtime(&currentTime);
	char logText[256];
	
	sprintf(logText, "WARNING::%02d%02d%04d-%02d:%02d:%02d::UNLINK::%s", 
		currentLocalTime.tm_mday, 
		currentLocalTime.tm_mon,
		currentLocalTime.tm_year + 1900,
		currentLocalTime.tm_hour,
		currentLocalTime.tm_min,
		currentLocalTime.tm_sec,
		path
	);
	fprintf(fileWriterInnuLogPath, "%s\n", logText);
	
	fclose(fileWriterInnuLogPath);
	
	return unlink(filePath);
}

static int fuse_rename(const char *old, const char *new)
{
	char filePathOld[1024];
	char filePathNew[1024];
	strcpy(filePathOld, old);
	decodePath(old, filePathOld);
	decodeDirectoryForRename(new, filePathNew);
	
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
	
	
	FILE *fileWriterInnuLogPath = fopen(innuLogPath, "a");
	time_t currentTime = time(NULL);
	struct tm currentLocalTime = *localtime(&currentTime);
	char logText[4096];
	
	sprintf(logText, "INFO::%02d%02d%04d-%02d:%02d:%02d::RENAME::%s::%s", 
		currentLocalTime.tm_mday, 
		currentLocalTime.tm_mon,
		currentLocalTime.tm_year + 1900,
		currentLocalTime.tm_hour,
		currentLocalTime.tm_min,
		currentLocalTime.tm_sec,
		filePathOld,
		filePathNew
	);
	fprintf(fileWriterInnuLogPath, "%s\n", logText);
	
	fclose(fileWriterInnuLogPath);
	
	return rename(old, new);
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
