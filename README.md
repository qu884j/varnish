# Varnish HTTP Accelerator.

https://www.varnish-cache.org/


## Installation

==> install_varnish_v4.0_Debian-Ubuntu.txt
Install Varnish 4.x on Debian Based Systems 

==> install_varnish_v4.0_From-Source.txt
Compiling Varnish from source

==> install_varnish_v4.0_Redhat-Centos.txt
Install Varnish v4.0 on Redhat Based Systems


## Configurations

Daemon Configurations: varnishd --> /etc/default/varnish

Main VCL Conf: varnish.vcl --> /etc/varnish/default.vcl


## Varnish Cheat Sheet

```
Backend Health Check: 
varnishadm debug.health | grep is

Checking varnish configuration syntax:
varnishd -C -f /etc/varnish/default.vcl

grep varnishlog by url 
varnishlog -c -o RxURL post/123.htm

## Varnish Subroutines

```
# VCL Flow }-->
#
# vcl_init ___> initialize VMODs
# vcl_fini ___> Debug And Clean Up VMODs Or Inlin-C
# HTTP Request ___> vcl_recv
#                     |______> synth <___ [ Return ERROR ]
#                     |______> vcl_pipe   [ Piping Traffic To / From Backend ]
#                     |______> vcl_pass   [ Pass Request Without Caching [ Http POST Or Dynamic Pages ]] ___> vcl_miss
#                     |______> vcl_purge  [ Remove obj from the cache ]
#                     |______> vcl_hash  ___> Lookup ___> [ Calculate HTTP Request hash ___> vcl_hash ]
#                                                                                               |
#                                                                                            in cache ??
#                                 vcl_backend_response ___> <___ vcl_backend_fetch <___ No <___ | ___> Yes ___> vcl_deliver ___> vcl_hit
#                                                          |
#                                                          |_______________________> ERROR ??
#                 vcl_hit <___ vcl_deliver <___ vcl_hash <___ Create Hash <___ No <___ | ___> yes ___> vcl_backend_error ___> vcl_miss(500 ERROR))
#
#
# <--{ VCL Flow
 
# vcl_init
# Called when VCL is loaded, before any requests pass through it. Typically used to initialize VMODs.
# return(ok)
 
# vcl_recv
# Called at the beginning of a request, after the complete request has been received and parsed.
# return(synth(status code, reason), pass, pipe, hash, purge)
 
# vcl_pipe
# Basically, Varnish will degrade into a simple TCP proxy, shuffling bytes back and forth,
# The pipe mode is good If you want to stream objects for example videos.
# return(synth(status code, reason), pass)
 
# vcl_pass
# Called upon entering pass mode. the request is passed on to the backend, 
# and the backends response is passed on to the client, but is not entered into the cache. 
# This is used for dynamic pages that should not be cached return(synth(status code, reason), pass, restart)
 
# vcl_purge
# Called after the purge has been executed
# return(synth(status code, reason), restart)
 
# vcl_hash
# Called after vcl_recv to create a hash value for the request. This is used as a key to look up the object in Varnish.
# return(lookup)
 
# vcl_hit
# Called when a cache lookup is successful.
# return(restart, deliver, synth(status code, reason))
 
# vcl_deliver
# Called before a cached object is delivered to the client.
# return(deliver, restart)
 
# vcl_miss
# Called after a cache lookup if the requested document was not found in the cache
# return(synth(status code, reason), pass, fetch, restart)
 
# vcl_backend_fetch
# Called before sending the backend request
# return(fetch, abandon)
 
# vcl_backend_response
# Called after the response headers has been successfully retrieved from the backend.
# return(deliver, abandon, retry)
 
# vcl_backend_error
# This subroutine is called if we fail the backend fetch.
# subroutine may terminate with calling return(deliver, retry)
 
# vcl_fini
# Called when VCL is discarded only after all requests have exited the VCL. Typically used to clean up VMODs.
# return(ok)

```

## Links
The Varnish Users Guide
https://www.varnish-cache.org/docs/4.0/users-guide/index.html#users-guide-index

The Varnish Reference Manual
https://www.varnish-cache.org/docs/4.0/reference/index.html#reference-index

The Varnish Tutorial
https://www.varnish-cache.org/docs/4.0/tutorial/index.html#tutorial-index

The Varnish Book
https://www.varnish-software.com/static/book/index.html

Varnish Tuning
ttps://www.varnish-software.com/static/book/Tuning.html#storage-backends

Varnish Best Practices
http://kly.no/posts/2010_01_26__Varnish_best_practices__.html
