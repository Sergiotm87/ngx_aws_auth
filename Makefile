CC=gcc
CFLAGS=-g -I${NGX_PATH}/src/os/unix -I${NGX_PATH}/src/core -I${NGX_PATH}/src/http -I${NGX_PATH}/src/http/modules -I${NGX_PATH}/src/event -I${NGX_PATH}/objs/ -I.

all:

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: all clean test nginx

NGX_OBJS := $(shell find ${NGX_PATH}/objs -name \*.o)

nginx:
	cd ${NGX_PATH} && rm -rf ${NGX_PATH}/objs/src/core/nginx.o && make

test-base:
	strip -N main -o ${NGX_PATH}/objs/src/core/nginx_without_main.o ${NGX_PATH}/objs/src/core/nginx.o \
	&& mv ${NGX_PATH}/objs/src/core/nginx_without_main.o ${NGX_PATH}/objs/src/core/nginx.o \
	&& strip -N ngx_http_aws_auth_module -o ${NGX_PATH}/objs/src/core/nginx_without_main.o ${NGX_PATH}/objs/src/core/nginx.o \
	&& mv ${NGX_PATH}/objs/src/core/nginx_without_main.o ${NGX_PATH}/objs/src/core/nginx.o

test-suite-aws-functions: nginx | test-base
	$(CC) tests/test_suite_aws_functions.c $(CFLAGS) -o test_suite -lcmocka ${NGX_OBJS} -ldl -lpthread -lcrypt -lssl -lpcre -lcrypto -lz \
	&& ./test_suite

test-all: test-suite-aws-functions

clean:
	rm -f *.o test_suite

# vim: ft=make ts=8 sw=8 noet
