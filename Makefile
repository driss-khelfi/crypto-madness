COMMON_FILES = src/LPTF_Net/* src/crypto.cpp src/file_utils.cpp
COMMON_LIBRARIES = -lpthread -lsodium -lcrypto -lstdc++fs -std=c++17
COMPILER_FLAGS = -Wall -Wextra -Werror

all: server client

server:
	g++ -o server src/server.cpp $(COMMON_FILES) $(COMMON_LIBRARIES) $(COMPILER_FLAGS)

client:
	g++ -o client src/client.cpp $(COMMON_FILES) $(COMMON_LIBRARIES) $(COMPILER_FLAGS)

debug:
	g++ -o server src/server.cpp $(COMMON_FILES) $(COMMON_LIBRARIES) $(COMPILER_FLAGS) -g3
	g++ -o client src/client.cpp $(COMMON_FILES) $(COMMON_LIBRARIES) $(COMPILER_FLAGS) -g3

clean:
	rm -f server
	rm -f client

fclean:
	rm -f server
	rm -f client

test: tclean
	g++ -o test src/test.cpp $(COMMON_FILES) $(COMMON_LIBRARIES) $(COMPILER_FLAGS)

tclean:
	rm -f test
