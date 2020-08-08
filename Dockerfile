FROM alpine:3.11

ARG WITH_UNIT_TEST

ENV NGINX_VERSION nginx-1.19.1

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
         --with-compat \
         --with-debug \
#         --with-http_ssl_module \
         --add-dynamic-module=ngx_aws_auth \
         --prefix=/etc/nginx \
         --http-log-path=/var/log/nginx/access.log \
         --error-log-path=/var/log/nginx/error.log \
         --sbin-path=/usr/local/sbin/nginx && \
     make && \
     make install && \
     make modules

RUN cp /tmp/src/${NGINX_VERSION}/objs/ngx_http_aws_auth_module.so /root

WORKDIR /tmp/src/${NGINX_VERSION}/ngx_aws_auth

RUN if [ "$WITH_UNIT_TEST" = "true" ] ; then NGX_PATH=/tmp/src/${NGINX_VERSION} && \
    mkdir -p /tmp/src/${NGINX_VERSION}/ngx_aws_auth/vendor/cmocka && \
    cd /tmp/src/${NGINX_VERSION}/ngx_aws_auth/vendor && \
    git clone https://git.cryptomilk.org/projects/cmocka.git --branch=cmocka-1.1.5 \
    ; fi

COPY ./tests /tmp/src/${NGINX_VERSION}/ngx_aws_auth/tests

RUN if [ "$WITH_UNIT_TEST" = "true" ] ; then cd /tmp/src/${NGINX_VERSION}/ngx_aws_auth && \
    NGX_PATH=/tmp/src/${NGINX_VERSION} make test-all \
    ; fi

CMD ["cp", "/root/ngx_http_aws_auth_module.so", "/tmp"]