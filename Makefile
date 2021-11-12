OPENSSL_HOME = /usr/local/Cellar/openssl@1.1/1.1.1l_1

INCLUDES = "-I${OPENSSL_HOME}/include"
LIBS = "-L${OPENSSL_HOME}/lib"

# CC = gcc

bin/ngx_module_hashcash_test: ngx_module_hashcash.h ngx_module_hashcash.c ngx_module_hashcash_test.c
	$(CC) ${INCLUDES} ${LIBS} \
	-o bin/ngx_module_hashcash_test ngx_module_hashcash_test.c ngx_module_hashcash.c \
	-lcmocka -lcrypto

.prepare:
	mkdir -p bin

all: .prepare bin/ngx_module_hashcash_test
	./bin/ngx_module_hashcash_test
