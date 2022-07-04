/*
    Name:   Parker Skinner 
    ID:     1001541467
*/

// The MIT License (MIT)
//
// Copyright (c) 2020 Trevor Bakker
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <ctype.h>

#define MAX_NUM_ARGUMENTS 4

#define WHITESPACE " \t\n" // We want to split our command line up into tokens \
                           // so we need to define what delimits our tokens.   \
                           // In this case  white space                        \
                           // will separate the tokens on our command line

#define MAX_COMMAND_SIZE 255 // The maximum command-line size

FILE *fp;
int file_status = 0;
char BS_OMEName[8];
int16_t BPB_BytesPerSec;
int8_t BPB_SecPerClus;
int16_t BPB_RsvdSecCnt;
int8_t BPB_NumFATs;
int16_t BPB_RootEntCnt;
char BS_VolLab[11];
int32_t BPB_FATSz32;
int32_t BPB_RootClus;
int32_t RootDirSectors = 0;
int32_t FirstDataSector = 0;
int32_t FirstSectorofCluseter = 0;

struct __attribute__((__packed__)) DirectoryEntry
{
  char DIR_Name[11];
  uint8_t DIR_Attr;
  uint8_t Unused1[8];
  uint16_t DIR_FirstClusterHigh;
  uint8_t Unused2[4];
  uint16_t DIR_FirstClusterLow;
  uint32_t DIR_FileSize;
};
struct DirectoryEntry dir[16];

int LBAToOffset(int32_t sector)
{
  if (sector < 2)
  {
    sector = 2;
  }
  return ((sector - 2) * BPB_BytesPerSec) + (BPB_BytesPerSec * BPB_RsvdSecCnt) + (BPB_NumFATs * BPB_FATSz32 * BPB_BytesPerSec);
}

int16_t NextLB(uint32_t sector)
{
  uint32_t FATAddress = (BPB_BytesPerSec * BPB_RsvdSecCnt) + (sector * 4);
  int16_t val;
  fseek(fp, FATAddress, SEEK_SET);
  fread(&val, 2, 1, fp);
  return val;
}

bool compare(char *input, char *rawname)
{
  char name[12];
  char expanded_name[12];

  strncpy(name, rawname, 12);

  memset(expanded_name, ' ', 12);

  char *token = strtok(input, ".");

  strncpy(expanded_name, token, strlen(token));
  token = strtok(NULL, ".");
  if (token)
  {
    strncpy((char *)(expanded_name + 8), token, strlen(token));
  }

  expanded_name[11] = '\0';

  int i;
  for (i = 0; i < 11; i++)
  {
    expanded_name[i] = toupper(expanded_name[i]);
  }

  if (strncmp(expanded_name, name, 11) == 0)
  {
    return true;
  }

  return false;
}

int main()
{

  char *cmd_str = (char *)malloc(MAX_COMMAND_SIZE);

  while (1)
  {
    // Print out the mfs prompt
    printf("mfs> ");

    // Read the command from the commandline.  The
    // maximum command that will be read is MAX_COMMAND_SIZE
    // This while command will wait here until the user
    // inputs something since fgets returns NULL when there
    // is no input
    while (!fgets(cmd_str, MAX_COMMAND_SIZE, stdin))
      ;

    /* Parse input */
    char *token[MAX_NUM_ARGUMENTS];

    int token_count = 0;

    // Pointer to point to the token
    // parsed by strsep
    char *arg_ptr;

    char *working_str = strdup(cmd_str);

    // we are going to move the working_str pointer so
    // keep track of its original value so we can deallocate
    // the correct amount at the end
    char *working_root = working_str;

    // Tokenize the input stringswith whitespace used as the delimiter
    while (((arg_ptr = strsep(&working_str, WHITESPACE)) != NULL) &&
           (token_count < MAX_NUM_ARGUMENTS))
    {
      token[token_count] = strndup(arg_ptr, MAX_COMMAND_SIZE);
      if (strlen(token[token_count]) == 0)
      {
        token[token_count] = NULL;
      }
      token_count++;
    }

    // Now print the tokenized input as a debug check
    // \TODO Remove this code and replace with your FAT32 functionality

    if (token != NULL)
    {
      if (strcmp(token[0], "open") == 0)
      {
        fp = fopen(token[1], "r+");

        if (fp == NULL)
        {
          printf("Error: File system image not found.\n");
        }

        else if (file_status == 1)
        {
          printf("Error: File system image already open.\n");
        }

        else
        {
          file_status = 1;
          char readptr[15];

          fseek(fp, 3, SEEK_SET);
          fread(readptr, 8, 1, fp);
          memcpy(BS_OMEName, readptr, 8);

          fseek(fp, 11, SEEK_SET);
          fread(readptr, 2, 1, fp);
          memcpy(&BPB_BytesPerSec, readptr, 2);

          fseek(fp, 13, SEEK_SET);
          fread(readptr, 1, 1, fp);
          memcpy(&BPB_SecPerClus, readptr, 1);

          fseek(fp, 14, SEEK_SET);
          fread(readptr, 2, 1, fp);
          memcpy(&BPB_RsvdSecCnt, readptr, 2);

          fseek(fp, 16, SEEK_SET);
          fread(readptr, 1, 1, fp);
          memcpy(&BPB_NumFATs, readptr, 1);

          fseek(fp, 17, SEEK_SET);
          fread(readptr, 2, 1, fp);
          memcpy(&BPB_RootEntCnt, readptr, 2);

          fseek(fp, 43, SEEK_SET);
          fread(readptr, 11, 1, fp);
          memcpy(BS_VolLab, readptr, 11);

          fseek(fp, 36, SEEK_SET);
          fread(readptr, 4, 1, fp);
          memcpy(&BPB_FATSz32, readptr, 4);

          fseek(fp, 44, SEEK_SET);
          fread(readptr, 4, 1, fp);
          memcpy(&BPB_RootClus, readptr, 4);

          int RDA = (BPB_NumFATs * BPB_FATSz32 * BPB_BytesPerSec) + (BPB_RsvdSecCnt * BPB_BytesPerSec);
          fseek(fp, RDA, SEEK_SET);
          int i;
          for (i = 0; i < 16; i++)
          {
            fread(&dir[i], 32, 1, fp);
          }
        }
      }

      else if (strcmp(token[0], "close") == 0)
      {

        if (file_status == 0)
        {
          printf("Error: File system not open.\n");
        }

        else
        {
          fclose(fp);
          strcpy(BS_OMEName, "");
          BPB_BytesPerSec = 0;
          BPB_SecPerClus = 0;
          BPB_RsvdSecCnt = 0;
          BPB_NumFATs = 0;
          BPB_RootEntCnt = 0;
          strcpy(BS_VolLab, "");
          BPB_FATSz32 = 0;
          BPB_RootClus = 0;
          file_status = 0;
          RootDirSectors = 0;
          FirstDataSector = 0;
          FirstSectorofCluseter = 0;
        }
      }

      else if (strcmp(token[0], "bpb") == 0)
      {
        if (file_status == 0)
        {
          printf("Error: File system image must be opened first.\n");
        }

        else
        {
          printf("-Base 10-\n");
          printf("BPB_BytesPerSec: %d\n", BPB_BytesPerSec);
          printf("BPB_SecPerClus: %d\n", BPB_SecPerClus);
          printf("BPB_RsvdSecCnt: %d\n", BPB_RsvdSecCnt);
          printf("BPB_NumFATS: %d\n", BPB_NumFATs);
          printf("BPB_FATSz32: %d\n", BPB_FATSz32);

          printf("-Hexadecimal-\n");
          printf("BPB_BytesPerSec: %x\n", BPB_BytesPerSec);
          printf("BPB_SecPerClus: %x\n", BPB_SecPerClus);
          printf("BPB_RsvdSecCnt: %x\n", BPB_RsvdSecCnt);
          printf("BPB_NumFATS: %x\n", BPB_NumFATs);
          printf("BPB_FATSz32: %x\n", BPB_FATSz32);
        }
      }

      else if (strcmp(token[0], "stat") == 0)
      {
        if (file_status == 0)
        {
          printf("Error: File system image must be opened first.\n");
        }
        else
        {

          if (token[1])
          {
            int i;
            for (i = 0; i < 16; i++)
            {
              char tempname[12];
              strncpy(tempname, token[1], 11);
              bool check = (compare(tempname, dir[i].DIR_Name));
              if ((dir[i].DIR_Attr == 0x01 || dir[i].DIR_Attr == 0x10 || dir[i].DIR_Attr == 0x20) && (dir[i].DIR_Name[0] != 0xe5) && check)
              {
                printf("%s attributes: \n", token[1]);

                char temp[11];
                strncpy(temp, dir[i].DIR_Name, 11);
                printf("Name: %s\n", temp);
                printf("Attribute: %d\n", dir[i].DIR_Attr);
                printf("Starting Cluster: %d\n", dir[i].DIR_FirstClusterLow);

                if ((dir[i].DIR_Name[0] == 0x2e))
                {
                  printf("Size: 0\n");
                }
                else
                {
                  printf("Size: %d\n", dir[i].DIR_FileSize);
                }
                break;
              }
            }
            if (i == 16)
            {
              printf("Error: FIle not found\n");
            }
          }
        }
      }

      else if (strcmp(token[0], "get") == 0)
      {
        if (file_status == 0)
        {
          printf("Error: File system image must be opened first.\n");
        }
        else
        {
          if (token[1])
          {
            int i;
            for (i = 0; i < 16; i++)
            {
              char tempname[12];
              strncpy(tempname, token[1], 12);
              bool check = (compare(tempname, dir[i].DIR_Name));
              if ((dir[i].DIR_Attr == 0x01 || dir[i].DIR_Attr == 0x10 || dir[i].DIR_Attr == 0x20) && (dir[i].DIR_Name[0] != 0xe5) && check)
              {
                FILE *getfile;
                if (token[2])
                {
                  getfile = fopen(token[2], "w");
                }

                else
                {
                  getfile = fopen(token[1], "w");
                }

                char write;
                int CurrentSector = dir[i].DIR_FirstClusterLow;
                int CurrentOffest = LBAToOffset(dir[i].DIR_FirstClusterLow);
                int Block = 512;
                int j;

                for (j = 0; j < dir[i].DIR_FileSize; j++)
                {
                  if (j % Block == 0 && j != 0)
                  {
                    CurrentSector = NextLB(CurrentSector);
                    CurrentOffest = LBAToOffset(CurrentSector);
                  }

                  fseek(fp, CurrentOffest++, SEEK_SET);
                  fread(&write, 1, 1, fp);
                  fputc(write, getfile);
                }

                fclose(getfile);

                break;
              }
            }
            if (i == 16)
            {
              printf("Error: FIle not found\n");
            }
          }
        }
      }

      else if (strcmp(token[0], "cd") == 0)
      {
        if (file_status == 0)
        {
          printf("Error: File system image must be opened first.\n");
        }

        else if (token[1])
        {
          char *temp = strtok(token[1], "/");
          while (temp != NULL)
          {
            if (strcmp(temp, "..") == 0)
            {
              int i;
              for (i = 0; i < 16; i++)
              {
                if ((dir[i].DIR_Name[0] == 0x2e) && (dir[i].DIR_Name[1] == 0x2e))
                {
                  int offset = LBAToOffset(dir[i].DIR_FirstClusterLow);
                  fseek(fp, offset, SEEK_SET);
                  int i;
                  for (i = 0; i < 16; i++)
                  {
                    fread(&dir[i], 32, 1, fp);
                  }
                  break;
                }
              }
            }
            else
            {
              int i;
              for (i = 0; i < 16; i++)
              {
                if (compare(temp, dir[i].DIR_Name) && dir[i].DIR_Attr == 0x10)
                {
                  int offset = LBAToOffset(dir[i].DIR_FirstClusterLow);
                  fseek(fp, offset, SEEK_SET);
                  int i;
                  for (i = 0; i < 16; i++)
                  {
                    fread(&dir[i], 32, 1, fp);
                  }
                  break;
                }
              }
            }
            temp = strtok(NULL, "/");
          }
        }
      }

      else if (strcmp(token[0], "ls") == 0)
      {
        if (file_status == 0)
        {
          printf("Error: File system image must be opened first.\n");
        }

        else
        {
          if (token[1] != NULL && strcmp(token[1], "..") == 0)
          {
            struct DirectoryEntry tempdir[16];
            int i;
            for (i = 0; i < 16; i++)
            {
              if ((dir[i].DIR_Name[0] == 0x2e) && (dir[i].DIR_Name[1] == 0x2e))
              {
                int offset = LBAToOffset(dir[i].DIR_FirstClusterLow);
                fseek(fp, offset, SEEK_SET);
                int i;
                for (i = 0; i < 16; i++)
                {
                  fread(&tempdir[i], 32, 1, fp);
                  if ((tempdir[i].DIR_Attr == 0x01 || tempdir[i].DIR_Attr == 0x10 || tempdir[i].DIR_Attr == 0x20) && ((unsigned char) tempdir[i].DIR_Name[0] != 0xe5))
                  {
                    char temp[11];

                    strncpy(temp, tempdir[i].DIR_Name, 11);
                    temp[11] = '\0';
                    printf("%s\n", temp);
                  }
                }
                break;
              }
            }
          }

          else
          {
            int i;
            for (i = 0; i < 16; i++)
            {
              if ((dir[i].DIR_Attr == 0x01 || dir[i].DIR_Attr == 0x10 || dir[i].DIR_Attr == 0x20) && ((unsigned char) dir[i].DIR_Name[0] != 0xe5))
              {
                char temp[11];
                strncpy(temp, dir[i].DIR_Name, 11);
                temp[11] = '\0';
                printf("%s\n", temp);
              }
            }
          }
        }
      }

      else if (strcmp(token[0], "read") == 0)
      {
        if (file_status == 0)
        {
          printf("Error: File system image must be opened first.\n");
        }
        else
        {
          if (token[1] && token[2] && token[3])
          {
            int i;
            for (i = 0; i < 16; i++)
            {
              char tempname[12];
              strncpy(tempname, token[1], 12);
              bool check = (compare(tempname, dir[i].DIR_Name));
              if ((dir[i].DIR_Attr == 0x01 || dir[i].DIR_Attr == 0x10 || dir[i].DIR_Attr == 0x20) && (dir[i].DIR_Name[0] != 0xe5) && check)
              {
                char write;
                int CurrentSector = dir[i].DIR_FirstClusterLow;
                int CurrentOffest = LBAToOffset(dir[i].DIR_FirstClusterLow);
                int Block = 512;
                int j;
                int Position = atoi(token[2]);
                int NumOfBytes = atoi(token[3]);
                int BytesSoFar = 0;

                for (j = 0; j < dir[i].DIR_FileSize; j++)
                {
                  if (j % Block == 0 && j != 0)
                  {
                    CurrentSector = NextLB(CurrentSector);
                    CurrentOffest = LBAToOffset(CurrentSector);
                  }

                  fseek(fp, CurrentOffest++, SEEK_SET);
                  fread(&write, 1, 1, fp);

                  if (j >= Position && BytesSoFar < NumOfBytes)
                  {
                    BytesSoFar++;
                    printf("%x ", write);
                  }
                }
                printf("\n");
                break;
              }
            }
            if (i == 16)
            {
              printf("Error: FIle not found\n");
            }
          }
        }
      }
    }

    free(working_root);
  }
  return 0;
}