# ngx_http_encrypt_module

encrypt request url parameters authorization, support MD5, AES, DES（for further update）

## complile

- ./configure --prefix=/usr/local/nginx/ --add-module=/home/sunder/bin/ngx_http_encrypt_module
- make && make install
- start nginx with nginx.conf
- 
## nginx.confg configuration
```
 server {
        listen       80;
        server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        location / {
            encrypt_switch  off;            #on/off
            encrypt_type    md5;            #md5/aes/des
            encrypt_key     DerekSunder;    #your encrypt_key
            encrypt_param   value1 value2 value3;   #param want to encrypt

            root   html;
            index  index.html index.htm;
        }

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
        ...
}
```
> `encrypt_switch`: on/off

> `encrypt_type`: md5/aes/des

> `encrypt_key`: your encrypt_key

> `encrypt_param`: the parameters which you want to encrypt

## module response
the response header will give you a key "Auth-Result"
> `param_error`: wrong or lack of parameters

> `unfaith`: wrong authorization, should check your sign

> `excellent`: authorize success

for example:

![Alt Text](../../pic/request_unauth.png)

header param:
base64_encode(md5(value1=1&value2=3&value3=2&DerekSunder))= ZTM3YjI5OWU3OGY0YTE3ZjY5MDQ1ZDBjNzQ4MjNiZGM=

so the sign param should be "ZTM3YjI5OWU3OGY0YTE3ZjY5MDQ1ZDBjNzQ4MjNiZGM="

![Alt Text](../../pic/request_auth.png)