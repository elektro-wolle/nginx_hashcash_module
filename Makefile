OPENSSL_HOME = /usr/local/Cellar/openssl@1.1/1.1.1l_1

INCLUDES = "-I${OPENSSL_HOME}/include"
LIBS = "-L${OPENSSL_HOME}/lib"

# CC = gcc

bin/nginx_hashcash_module_test: nginx_hashcash_module.h nginx_hashcash_module.c nginx_hashcash_module_test.c
	$(CC) ${INCLUDES} ${LIBS} \
	-o bin/nginx_hashcash_module_test nginx_hashcash_module_test.c nginx_hashcash_module.c \
	-lcmocka -lcrypto

.prepare:
	mkdir -p bin

all: .prepare bin/nginx_hashcash_module_test
	./bin/nginx_hashcash_module_test
