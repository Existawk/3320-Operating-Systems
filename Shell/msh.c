/*
    Name:   Parker Skinner 
    ID:     1001541467
*/

// The MIT License (MIT)
//
// Copyright (c) 2016, 2017, 2020 Trevor Bakker
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

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#define WHITESPACE " \t\n" // We want to split our command line up into tokens 
                           // so we need to define what delimits our tokens.   
                           // In this case  white space                        
                           // will separate the tokens on our command line

#define MAX_COMMAND_SIZE 255 // The maximum command-line size

#define MAX_NUM_ARGUMENTS 11 // Mav shell only supports five arguments

int main()
{
  int pid_list[15];
  int pid_counter = 0;
  char **cmd_history = (char **)malloc(15 * MAX_COMMAND_SIZE);
  int history_counter = 0;
  char *cmd_str = (char *)malloc(MAX_COMMAND_SIZE);

  while (1)
  {
    // Print out the msh prompt
    printf("msh> ");

    // Read the command from the commandline.  The
    // maximum command that will be read is MAX_COMMAND_SIZE
    // This while command will wait here until the user
    // inputs something since fgets returns NULL when there
    // is no input
    while (!fgets(cmd_str, MAX_COMMAND_SIZE, stdin))
      ;

    // Checks if command string begins with a "!"
    // if it does it replaces the command string with one from history
    if (cmd_str[0] == '!')
    {
      int num = atoi(&cmd_str[1]);

      if (history_counter > num)
      {
        cmd_str = strdup(cmd_history[num]);
      }

      else
      {
        printf("Command not in history.\n");
      }
    }

    /* Parse input */
    char *token[MAX_NUM_ARGUMENTS];

    int token_count = 0;

    // Pointer to point to the token
    // parsed by strsep
    char *argument_ptr;

    char *working_str = strdup(cmd_str);

    // we are going to move the working_str pointer so
    // keep track of its original value so we can deallocate
    // the correct amount at the end
    char *working_root = working_str;

    // Tokenize the input stringswith whitespace used as the delimiter
    while (((argument_ptr = strsep(&working_str, WHITESPACE)) != NULL) &&
           (token_count < MAX_NUM_ARGUMENTS))
    {
      token[token_count] = strndup(argument_ptr, MAX_COMMAND_SIZE);
      if (strlen(token[token_count]) == 0)
      {
        token[token_count] = NULL;
      }
      token_count++;
    }

    if (token[0] != NULL)
    {
      // Updates currnet history of input tokens up to 15 entries
      // Once 15 entries are reached the oldest one is removed
      // to make space for the newest
      if (history_counter < 15)
      {
        cmd_history[history_counter] = strdup(cmd_str);
        history_counter++;
      }

      else
      {
        int i;
        for (i = 0; i < 14; i++)
        {
          cmd_history[i] = cmd_history[i + 1];
        }
        cmd_history[14] = strdup(cmd_str);
      }

      // Terminates the program uppon request with status zero
      // using the strings "quit" or "exit"
      if (strcmp(token[0], "quit") == 0 || strcmp(token[0], "exit") == 0)
      {
        free(cmd_history);
        free(working_root);
        exit(0);
      }

      // Prints out the history of past inputs up to 15 entries
      // Once 15 entries are reached the oldest one is removed
      // to make space for the newest
      else if (strcmp(token[0], "history") == 0)
      {
        int i;
        for (i = 0; i < history_counter; i++)
        {
          printf("%d: %s", i, cmd_history[i]);
        }
      }

      // Checks if change directory command is called
      // if it is, chdir() is called with the second token
      // as the input
      else if (strcmp(token[0], "cd") == 0)
      {
        chdir(token[1]);
      }

      // Displays the last 15 Processes created by the shell
      else if (strcmp(token[0], "showpids") == 0)
      {
        int i;
        for (i = 0; i < pid_counter; i++)
        {
          printf("%d: %d\n", i, pid_list[i]);
        }
      }

      // Forks new procees from the current one using execvp
      // Parent process updates pid_list to show new pids
      else
      {
        pid_t pid = fork();
        if (pid == 0)
        {
          // Notice you can add as many NULLs on the end as you want
          int ret = execvp(token[0], token);
          if (ret == -1)
          {
            cmd_str[strlen(cmd_str) - 1] = 0;
            printf("%s: command not found\n", cmd_str);

          }
          return 0;
        }
        else
        {
          int status;
          wait(&status);

          // Updates current pid history up to 15 entries
          // Once 15 entries are reached the oldest one is removed
          // to make space for the newest
          if (pid_counter < 15)
          {
            pid_list[pid_counter] = pid;
            pid_counter++;
          }

          else
          {
            int i;
            for (i = 0; i < pid_counter - 1; i++)
            {
              pid_list[i] = pid_list[i + 1];
            }
            pid_list[pid_counter] = pid;
          }
        }
      }
    }
    free(working_root);
  }
  return 0;
}
