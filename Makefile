COMMON_FILES = src/LPTF_Net/* src/crypto.cpp
COMMON_LIBRARIES = -lsodium -lcrypto
COMPILER_FLAGS = -Wall -Wextra -Werror

all: server client

server:
	g++ -o server src/server.cpp $(COMMON_FILES) $(COMMON_LIBRARIES) -lpthread $(COMPILER_FLAGS)

client:
	g++ -o client src/client.cpp $(COMMON_FILES) $(COMMON_LIBRARIES) $(COMPILER_FLAGS)

debug:
	g++ -o server src/server.cpp $(COMMON_FILES) $(COMMON_LIBRARIES) -lpthread $(COMPILER_FLAGS) -g3
	g++ -o client src/client.cpp $(COMMON_FILES) $(COMMON_LIBRARIES) $(COMPILER_FLAGS) -g3

clean:
	rm -f server
	rm -f client

fclean:
	rm -f server
	rm -f client
