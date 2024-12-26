#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
err_handler(int err_code, char* message)
{
  if (err_code < 0) {
    char* err = strerror(-err_code);
    fprintf(stderr, "\033[37m[\033[0m\033[31mERROR\033[0m\033[37m]\033[0m %s. %s.\n", err, message);
    exit(1);
  }
}

void
errno_handler(char* message)
{
  perror(message);
  exit(1);
}
