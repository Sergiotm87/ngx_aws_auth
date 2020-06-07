FROM alpine:3.6

ENV NGINX_VERSION nginx-1.13.4

RUN mkdir -p /tmp/src/${NGINX_VERSION}/ngx_aws_auth
COPY . /tmp/src/${NGINX_VERSION}/ngx_aws_auth

RUN apk --update add openssl-dev git pcre-dev zlib-dev tini wget build-base cmake cmocka-dev && \
     mkdir -p /tmp/src && \
     cd /tmp/src && \
     wget http://nginx.org/download/${NGINX_VERSION}.tar.gz && \
     tar -zxvf ${NGINX_VERSION}.tar.gz && \
     cd /tmp/src/${NGINX_VERSION} && \
#      git clone https://github.com/hexmarkrecords/ngx_aws_auth.git && \
     ./configure \
         --with-http_ssl_module \
#         --with-http_gzip_static_module \
         --add-module=ngx_aws_auth \
         --prefix=/etc/nginx \
         --http-log-path=/var/log/nginx/access.log \
         --error-log-path=/var/log/nginx/error.log \
         --sbin-path=/usr/local/sbin/nginx && \
     make && \
     make install

WORKDIR /tmp/src/${NGINX_VERSION}/ngx_aws_auth

RUN NGX_PATH=/tmp/src/${NGINX_VERSION} && \
    mkdir -p /tmp/src/${NGINX_VERSION}/ngx_aws_auth/vendor/cmocka && \
    cd /tmp/src/${NGINX_VERSION}/ngx_aws_auth/vendor && \
    git clone https://git.cryptomilk.org/projects/cmocka.git --branch=cmocka-1.1.5

COPY ./tests /tmp/src/${NGINX_VERSION}/ngx_aws_auth/tests


RUN cd /tmp/src/${NGINX_VERSION}/ngx_aws_auth && \
    NGX_PATH=/tmp/src/${NGINX_VERSION} make test-all
