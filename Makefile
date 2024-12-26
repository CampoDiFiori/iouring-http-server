CC = clang
CFLAGS = -g -DDEBUG -Wall -Wextra -luring
SRC_DIR = .
BIN_DIR = bin

.PHONY: clean all

all: $(BIN_DIR)/program

$(BIN_DIR)/program: $(SRC_DIR)/main.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BIN_DIR)
