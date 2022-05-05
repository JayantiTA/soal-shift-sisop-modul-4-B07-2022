#define FUSE_USE_VERSION 28
#include "stdio.h"
#include "string.h"
#include "unistd.h"
#include "dirent.h"
#include "fcntl.h"
#include "errno.h"
#include "fuse.h"
#include "pwd.h"
#include "sys/time.h"
#include "sys/types.h"

static int ANIMEKU = 0;

static char rootPath[256];
static char wibuLogPath[256];

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

void decryptText(char *str, int startIndex, int endIndex, int encryptionType)
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
	}
}

void decryptFile(char *str, int startIndex, int endIndex, int encryptionType)
{
	int fileExtensionPos = endIndex - 1;
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
	}
}

void encryptFile(char *str, int startIndex, int endIndex, int encryptionType)
{
	int fileExtensionPos = endIndex - 1;
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

int getEncryptionType(const char *path, int *offset)
{
	char *pos;
	int encryptionType = -1;
	if ((pos = strstr(path, "/Animeku_")) != NULL)
	{
		encryptionType = ANIMEKU;
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

void decodeDirectoryForRename(const char *path)
{
	char tempPath[256];
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
	
	char filePath[256];
	sprintf(filePath, "%s%s", rootPath, path);
	
	if (lstat(filePath, st) == -1)
	{
		return -errno;
	}
	
	return 0;
}

static int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	char filePath[256];
	int encryptionType = decodePath(filePath, path);
	
	DIR *directory;
	struct dirent *dirData;
	struct stat st;
	char fileName[256];

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
	return 0;
}

static int fuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	char filePath[256];
	int encryptionType = decodePath(filePath, path);
	
	int fileDescriptor = 0;
	
	(void) fi;
	
	fileDescriptor = open(filePath, O_RDONLY);
	if (fileDescriptor == -1) 
	{ 
		return -errno;
	}
	
	int result = pread(fileDescriptor, buf, size, offset);

	close(fileDescriptor);
	
	if (result == -1)
	{
		return -errno;
	}
	return 0;
}

static int fuse_mkdir(const char *path, mode_t mode)
{
	char filePath[256];
	int encryptionType = decodePath(filePath, path);
	
	return mkdir(filePath, mode);
}

static int fuse_rmdir(const char *path)
{
	char filePath[256];
	int encryptionType = decodePath(filePath, path);
	
	return rmdir(filePath);
}

static int fuse_rename(const char *old, const char *new, unsigned int flags)
{
	char filePathOld[256];
	strcpy(filePathOld, old);
	decodePath(old, filePathOld);
	decodeDirectoryForRename(new);
	
	char fileNameOld[256];
	char fileNameNew[256];
	
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
	
	rename(old, new);
}

static struct fuse_operations fuseAnya = {
	.getattr = fuse_getattr,
	.readdir = fuse_readdir,
	.read = fuse_read,
	.mkdir = fuse_mkdir,
	.rmdir = fuse_rmdir,
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
	return fuse_main(argc, argv, &fuseAnya, NULL);
}
