LIBMEMCACHED_HOME = /usr/local/opt/libmemcached/
OPENSSL_HOME = /usr/local/opt/openssl@3
NGINX_HOME = $(PWD)/nginx-1.21.4/


INCLUDES = -I${OPENSSL_HOME}/include -I${NGINX_HOME}/src/
LIBS = -L${OPENSSL_HOME}/lib

CFLAGS = -Wall -O
# CC = gcc


.configure_nginx:
	cd nginx-1.21.4 && ./configure --add-dynamic-module="$(PWD)" --with-http_ssl_module --with-cc-opt="-I$(OPENSSL_HOME)/include -I$(LIBMEMCACHED_HOME)/include/" --with-ld-opt="-L$(OPENSSL_HOME)/lib"
#	cd nginx-1.21.4 && ./configure --add-dynamic-module="$(PWD)" --prefix=/usr/local/etc/nginx --sbin-path=/usr/local/sbin/nginx --conf-path=/usr/local/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --http-client-body-temp-path=/var/cache/nginx/client_temp --http-proxy-temp-path=/var/cache/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/nginx/scgi_temp --with-openssl=$(LOCAL_OPENSSL_HOME) --user=www-data --group=www-data --with-http_ssl_module --with-http_realip_module --with-http_addition_module --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_stub_status_module --with-http_auth_request_module --with-threads --with-stream --with-stream_ssl_module --with-http_slice_module --with-mail --with-mail_ssl_module --with-http_v2_module

.build_module:
	cd nginx-1.21.4 && gmake -j8

bin/ngx_http_hashcash_module_test: ngx_http_hashcash_module.c ngx_http_hashcash_module_test.c
	$(CC) $(INCLUDES) ${LIBS} -DUNIT_TEST \
	-o bin/ngx_http_hashcash_module_test ngx_http_hashcash_module_test.c ngx_http_hashcash_module.c \
	-lcmocka -lcrypto

.download:
	wget https://nginx.org/download/nginx-1.21.4.tar.gz
	tar xvzf nginx-1.21.4.tar.gz

.prepare:
	mkdir -p bin

.validate: bin/ngx_http_hashcash_module_test
	./bin/ngx_http_hashcash_module_test

all: .prepare bin/ngx_http_hashcash_module_test .validate .build_module
	
