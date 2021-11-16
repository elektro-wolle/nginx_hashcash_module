# nginx hashcash module

Simple nginx module for using the idea behind the [hashcash-algorithm](https://en.wikipedia.org/wiki/Hashcash) as a client-side proof-of-work, to make brute-force a little bit more expensive for an attacker.

## How to use it

Every request is protected by some proof-of-work on the client-side, `sha-256` can be imported via `hash.js`:

```
proofOfWork = function (nonce) {
	var i = 0;
	var check = (new Date().getTime()) + '-' + nonce + '-';
	while (i < 2000000) {
		var sha = hash.sha256().update(check + i).digest('hex');
		if (sha.substring(0, 5) === '00000') {
			return check + i;
		}
		i++;
	}
	return undefined;
}
```

The header is of the form `${epoch-seconds}-${nonce}-${proof}`, therefor setting the `x-hashcash`-Header to 

```
let nonce = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
let promise = fetch(url, {
  method: "GET",
  headers: {
    "x-hashcash": proofOfWork(nonce)
  },
  ...
});
```

If the timestamp is outside the configured `hashcash_max_ttl`, the number of leading zero-bits in `SHA256("${epoch-seconds}-${nonce}-${proof}")` less than `hashcash_min_work` 
or the nonce is already known in `memcached` the request is rejected as soon as possible in a nginx pre-auth filter.

## Building

Prerequisites:

* openssl
* nginx
* libmemcached
* [cmocka](https://cmocka.org/)
* make

Make adjustments to include paths in Makefile:

```
LIBMEMCACHED_HOME = /usr/local/opt/libmemcached/
OPENSSL_HOME = /usr/local/opt/openssl@3
NGINX_VERSION=1.21.4
```

Run build:

```
# only the first time
make .download
make .configure_nginx
# after downloading and configuring
make all
```


## nginx integration

Load module globally:

`nginx.conf`:

```
load_module  /etc/nginx/modules/nginx_hashcash_module.so;
http {
    ...
}
```

And protect some endpoints:

`default.conf`:

```
server { 
    ...

    location /protected  {
        hashcash_min_work 20;
        hashcash_max_ttl 30;
        hashcash_memcache_servers "--SERVER=127.0.0.1:11211";
        hashcash_memcache_prefix "--";        
        ...
    }
    location / {
        ...
    }
}
```

For checking against already used `nonce`s, a `memcached` is used as double spent database. Every valid `nonce` is stored with the prefix `hashcash_memcache_prefix` as a key in `memcached` with an ttl of `hashcash_max_ttl`.
For configuring the servers: [libmemcached](http://docs.libmemcached.org/libmemcached_configuration.html).
