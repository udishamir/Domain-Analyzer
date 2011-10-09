#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#include "analyzer.h"

unsigned char result[MD5_DIGEST_LENGTH];

int hex2char(unsigned char *data, size_t len, unsigned char *buf)
{
   char *p;
   int i;
   
   static char hexa[] = "0123456789abcdef";
   
   for(p = buf,i = 0; i < len; i++)
     { 
 				*(p++) = hexa[(data[i] & 0xf0) >> 4];
 				*(p++) = hexa[(data[i] & 0x0f) >> 0];
     }
   
   
   *p = 0;
   
   return 0;
}

// Get the size of the file by its file descriptor
unsigned long get_size_by_fd(int fd) {
    struct stat statbuf;
    if(fstat(fd, &statbuf) < 0) exit(-1);
    return statbuf.st_size;
}

int md5sum(char *hashsum, char *fname)
{
    int file_descript;
    unsigned long file_size;
    char* file_buffer;
    unsigned char asciisum[32];

    file_descript = open(fname, O_RDONLY);
    if(file_descript < 0) 
    	return -1;
    	
    file_size = get_size_by_fd(file_descript);

    file_buffer = mmap(0, file_size, PROT_READ, MAP_SHARED, file_descript, 0);
    MD5((unsigned char*) file_buffer, file_size, result);
		
		// translate binary to ascii //
    hex2char(result, 16, hashsum);
    
    return 0;
}
