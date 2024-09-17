COMMON_FILES = src/LPTF_Net/*
COMPILER_FLAGS = -Wall -Wextra -Werror

all: server client

server:
	g++ -o server src/server.cpp $(COMMON_FILES) -lpthread $(COMPILER_FLAGS)

client:
	g++ -o client src/client.cpp $(COMMON_FILES) $(COMPILER_FLAGS)

clean:
	rm -f server
	rm -f client

fclean:
	rm -f server
	rm -f client
