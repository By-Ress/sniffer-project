CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude
LDFLAGS = -lpcap

SRC = core/sniffer.c
OBJ = $(SRC:.c=.o)
BIN = sniffer

INTERFACE = en0
OUTPUT = logs/packets.pcap

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) -o $(BIN) $(LDFLAGS)

core/%.o: core/%.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(BIN)
	sudo ./$(BIN) $(INTERFACE) $(OUTPUT)

clean:
	rm -f core/*.o $(BIN)
	rm -f logs/* $(BIN)

.PHONY: all clean run
