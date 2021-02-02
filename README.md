# lua-resty-tencent-cos-signature


## Overview

This library implements request signing using the [Tencent QCloud Signature XML
Version][docs] specification. We can use this signature to request objects from
COS an proxy them with Nginx (Openresty or [lua-nginx-module](https://github.com/openresty/lua-nginx-module)).

这个库用用于生成腾讯云 COS 对象储存的[请求签名][docs]，故可用于配置 Nginx (需要安装
Openresty 或者编译 [lua-nginx-module](https://github.com/openresty/lua-nginx-module))
反代理私有仓库。

## Usage

This library uses environment variables as credentials.

使用以下环境变量定义 `ACCESS_KEY_ID` 和 `SECRET_ACCESS_KEY`。

```bash
export COS_ACCESS_KEY_ID=AKIDEXAMPLE
export COS_SECRET_ACCESS_KEY=AKIDEXAMPLE
```

To be accessible in your nginx configuration, these variables should be
declared in `nginx.conf` file.

之后还需要在 `nginx.conf` 中声明。

```nginx
#user  nobody;
worker_processes  1;

pid logs/nginx.pid;

env COS_ACCESS_KEY_ID;
env COS_SECRET_ACCESS_KEY;

# or specify them in Nginx config file only
#env COS_ACCESS_KEY_ID=AKIDEXAMPLE;
#env COS_SECRET_ACCESS_KEY=AKIDEXAMPLE;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /dev/stdout;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    include /etc/nginx/conf.d/*.conf;
}
```

You can then use the library to add COS Signature headers and `proxy_pass` to a
given COS bucket.

之后就可以在 server 块中添加配置了。

```nginx
server {
  listen 80 default_server;

  set $cos_bucket 'example-1200000000';
  set $cos_host $cos_bucket.cos.ap-hongkong.myqcloud.com;

  location / {
    resolver 127.0.0.53 valid=300s;
    resolver_timeout 10s;

    rewrite (.*) /$1 break;

    access_by_lua_block {
      require("resty.cos-signature").cos_set_headers()
    }

    proxy_set_header Host $cos_host;
    proxy_pass http://$cos_host;
  }
}
```

## Installing

It is recommend to install script with [OPM](https://opm.openresty.org/).

建议用 [OPM](https://opm.openresty.org/) 安装。

```bash
opm get mashirozx/lua-resty-tencent-cos-signature
```

## Contributing

Check [CONTRIBUTING.md](CONTRIBUTING.md) for more information.

## License

Copyright 2021 Mashiro

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
