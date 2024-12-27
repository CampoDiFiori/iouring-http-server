#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define err_handler(code, ...)                                                 \
  do {                                                                         \
    if ((code) < 0) {                                                          \
      fprintf(stderr,                                                          \
              "\033[37m[\033[0m\033[31mERROR\033[0m\033[37m]\033[0m %s%s%s. "  \
              "At %s:%d\n",                                                    \
              strerror(code), sizeof((char[]){__VA_ARGS__}) == 1 ? "" : ": ",  \
              sizeof((char[]){__VA_ARGS__}) == 1 ? "" : (char[]){__VA_ARGS__}, \
              __FILE__, __LINE__);                                             \
      raise(SIGTRAP);                                                          \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

#define null_handler(ptr, ...)                                                 \
  do {                                                                         \
    if ((ptr) == NULL) {                                                       \
      fprintf(stderr,                                                          \
              "\033[37m[\033[0m\033[31mERROR\033[0m\033[37m]\033[0m %s%s%s. "  \
              "At %s:%d\n",                                                    \
              strerror(errno), sizeof((char[]){__VA_ARGS__}) == 1 ? "" : ": ", \
              sizeof((char[]){__VA_ARGS__}) == 1 ? "" : (char[]){__VA_ARGS__}, \
              __FILE__, __LINE__);                                             \
      raise(SIGTRAP);                                                          \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
