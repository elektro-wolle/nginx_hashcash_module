# nginx hashcash module
WIP simple nginx module for using the hashcash-algorithm as a client-side proof-of-work.

## Idea behind

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

And setting the `If-Match`-Header to 

```
let nonce = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
let promise = fetch(url, {
  method: "GET",
  headers: {
    "If-Match": proofOfWork(nonce)
  },
  ...
});
```

## Building

Prerequisites:

* openssl
* nginx
* [cmocka](https://cmocka.org/)
* make

Run build:

```
CC=gcc OPENSSL_HOME=... NGINX=... make all
```


## nginx integration (yet missing)

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
    listen 443 ssl;
    hash_cash_memcache "--SERVER=localhost:11211 --POOL-MIN=4"; # defaults
    hash_cash_min_work 16;                         # default
    hash_cash_ttl 60;                              # default

    location / {
...
    }

    location /register {
        hash_cash_min_work 20; # make this endpoint more expensive
...
    }
}
```

