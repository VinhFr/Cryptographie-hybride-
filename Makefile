# Makefile cho project E2EE
CC = gcc
CFLAGS = -Wall -Wextra -g -O2 -pthread
LDFLAGS = -lssl -lcrypto

SRCS = main.c crypto.c network.c
OBJS = $(SRCS:.c=.o)
TARGET = e2ee
DH_PARAMS = dhparams.pem

# DSA key files
SERVER_DSA_PRIV = server_dsa_priv.pem
SERVER_DSA_PUB  = server_dsa_pub.pem
CLIENT_DSA_PRIV = client_dsa_priv.pem
CLIENT_DSA_PUB  = client_dsa_pub.pem

.PHONY: all clean dhparams keys

all: $(DH_PARAMS) $(TARGET)

# Build executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 1. DH parameters (tự động tạo nếu chưa có)
$(DH_PARAMS):
	@echo "🔑 Generating 2048-bit Diffie-Hellman parameters..."
	openssl dhparam -out $@ 2048
	@echo "✅ DH parameters created: $@"

# 2. DSA keypair cho client và server
keys: $(SERVER_DSA_PRIV) $(SERVER_DSA_PUB) $(CLIENT_DSA_PRIV) $(CLIENT_DSA_PUB)

# Server DSA
$(SERVER_DSA_PRIV) $(SERVER_DSA_PUB):
	@echo "🔑 Generating server DSA keypair..."
	openssl dsaparam -out dsaparam_server.pem 2048
	openssl gendsa -out $(SERVER_DSA_PRIV) dsaparam_server.pem
	openssl dsa -in $(SERVER_DSA_PRIV) -pubout -out $(SERVER_DSA_PUB)
	@echo "✅ Server DSA keys generated."

# Client DSA
$(CLIENT_DSA_PRIV) $(CLIENT_DSA_PUB):
	@echo "🔑 Generating client DSA keypair..."
	openssl dsaparam -out dsaparam_client.pem 2048
	openssl gendsa -out $(CLIENT_DSA_PRIV) dsaparam_client.pem
	openssl dsa -in $(CLIENT_DSA_PRIV) -pubout -out $(CLIENT_DSA_PUB)
	@echo "✅ Client DSA keys generated."

# Clean project
clean:
	@echo "🧹 Cleaning project files..."
	rm -f $(OBJS) $(TARGET) $(DH_PARAMS)
	rm -f dsaparam_*.pem
	rm -f $(SERVER_DSA_PRIV) $(SERVER_DSA_PUB) $(CLIENT_DSA_PRIV) $(CLIENT_DSA_PUB)
	@echo "✅ Clean done."
