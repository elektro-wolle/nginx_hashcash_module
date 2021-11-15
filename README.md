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

And setting the `x-hashcash`-Header to 

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

## Building

Prerequisites:

* openssl
* nginx
* [cmocka](https://cmocka.org/)
* make

Run build:

```
# only the first time
make .download
make .configure_nginx
# after downloading and configuring
make all
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
    ...

    location /protected  {
        hashcash_min_work 20;
        hashcash_max_ttl 30;
        ...
    }
    location / {
        ...
    }
}
```

