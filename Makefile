CC ?= clang
CFLAGS = -Iopenssl/include -Wall -Wextra -O3 -DMAC_CYCLES
LDFLAGS = -Lopenssl -lssl -lcrypto
TARGET = bench
SRC = bench.c hal.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)