CC ?= cc
ROOT = ../../..
CORE = $(ROOT)/main/core
SIM_STUBS = $(ROOT)/simulator/platform/esp_idf_stubs

# seedkeeper_sc.c reaches PSA through crypto_utils.c, so link it the way
# main/core/test links test_crypto_utils: simulator ESP-IDF stub headers,
# the core test hardware stub, the host PBKDF2 and -lmbedcrypto.
CFLAGS = -Wall -Wextra -g -I../src -I$(CORE) -I$(ROOT)/main \
	-I$(SIM_STUBS)/include -I$(ROOT)/simulator/platform \
	-include mbedtls_compat.h
SRCS = test_frame.c ../src/sec1210_frame.c $(CORE)/seedkeeper.c \
       $(CORE)/seedkeeper_sc.c $(CORE)/crypto_utils.c $(CORE)/entropy_pool.c \
       $(CORE)/test/stubs/esp_hw_stub.c $(SIM_STUBS)/pbkdf2_sim.c
LIBS = -lmbedcrypto
TARGET = test_frame

all: $(TARGET)

$(TARGET): $(SRCS) $(CORE)/seedkeeper_sc.h $(CORE)/crypto_utils.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LIBS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
