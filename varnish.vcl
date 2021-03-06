# ~~~~~>
#                        _     _     
# __   ____ _ _ __ _ __ (_)___| |__  
# \ \ / / _` | '__| '_ \| / __| '_ \ 
#  \ V / (_| | |  | | | | \__ \ | | |
#   \_/ \__,_|_|  |_| |_|_|___/_| |_|
#
#
#
# varnish 4.x VCL Template ~> qu884j@gmail.com 
#
# <~~~~~


vcl 4.0;
import directors;
import std;

#############################################################################################################################
# Backends & Health checks
#############################################################################################################################

# Server-1
backend server1 {               # Define Backend Name.
.host = "127.0.0.1";            # Define Backend IP.
.port = "80";                   # Define Backend PORT. 
.probe = {                      # Health Check -->
  .url = "/";                     # HIT/PING This URL.
  .timeout   = 7s;                # How fast the probe must finish (seconds).
  .interval  = 14s;               # How long time to wait between polls (seconds).
  .window    = 2;                 # How many of the latest polls to consider when determining if the backend is healty.
  .threshold = 2;                 # How many of the .window last polls must be good for the backend to be declared healthy.
  .expected_response = 301;       # Expected Response Status Code 404 302 200 etc.
  }                               # <-- Health Checks
.first_byte_timeout     = 10s; # How long to wait before we receive the first byte from our backend ?
.connect_timeout        = 10s; # How long to wait for a backend connection ?
.between_bytes_timeout  = 5s;  # How long to wait between bytes received from our backend ?
}

# Server-2
backend server2 {               # Define Backend Name.
.host = "127.0.0.1";            # Define Backend IP.
.port = "80";                   # Define Backend PORT. 
.probe = {                      # Health Check -->
  .url = "/";                     # HIT/PING This URL.
  .timeout   = 7s;                # How fast the probe must finish (seconds).
  .interval  = 14s;               # How long time to wait between polls (seconds).
  .window    = 2;                 # How many of the latest polls to consider when determining if the backend is healty.
  .threshold = 2;                 # How many of the .window last polls must be good for the backend to be declared healthy.
  .expected_response = 301;       # Expected Response Status Code 404 302 200 etc.
  }                               # <-- Health Checks
.first_byte_timeout     = 10s; # How long to wait before we receive the first byte from our backend ?
.connect_timeout        = 10s; # How long to wait for a backend connection ?
.between_bytes_timeout  = 5s;  # How long to wait between bytes received from our backend ?
}

# Server-3
backend server3 {               # Define Backend Name.
.host = "127.0.0.1";            # Define Backend IP.
.port = "80";                   # Define Backend PORT. 
.probe = {                      # Health Check -->
  .url = "/";                     # HIT/PING This URL.
  .timeout   = 7s;                # How fast the probe must finish (seconds).
  .interval  = 14s;               # How long time to wait between polls (seconds).
  .window    = 2;                 # How many of the latest polls to consider when determining if the backend is healty.
  .threshold = 2;                 # How many of the .window last polls must be good for the backend to be declared healthy.
  .expected_response = 301;       # Expected Response Status Code 404 302 200 etc.
  }                               # <-- Health Checks
.first_byte_timeout     = 10s; # How long to wait before we receive the first byte from our backend ?
.connect_timeout        = 10s; # How long to wait for a backend connection ?
.between_bytes_timeout  = 5s;  # How long to wait between bytes received from our backend ?
}

# API-1
backend api1 {               	# Define Backend Name.
.host = "127.0.0.1";            # Define Backend IP.
.port = "80";                   # Define Backend PORT. 
.probe = {                      # Health Check -->
  .url = "/";                     # HIT/PING This URL.
  .timeout   = 7s;                # How fast the probe must finish (seconds).
  .interval  = 14s;               # How long time to wait between polls (seconds).
  .window    = 2;                 # How many of the latest polls to consider when determining if the backend is healty.
  .threshold = 2;                 # How many of the .window last polls must be good for the backend to be declared healthy.
  .expected_response = 301;       # Expected Response Status Code 404 302 200 etc.
  }                               # <-- Health Checks
.first_byte_timeout     = 10s; # How long to wait before we receive the first byte from our backend ?
.connect_timeout        = 10s; # How long to wait for a backend connection ?
.between_bytes_timeout  = 5s;  # How long to wait between bytes received from our backend ?
}

# API-2
backend api2 {               	# Define Backend Name.
.host = "127.0.0.1";            # Define Backend IP.
.port = "80";                   # Define Backend PORT. 
.probe = {                      # Health Check -->
  .url = "/";                     # HIT/PING This URL.
  .timeout   = 7s;                # How fast the probe must finish (seconds).
  .interval  = 14s;               # How long time to wait between polls (seconds).
  .window    = 2;                 # How many of the latest polls to consider when determining if the backend is healty.
  .threshold = 2;                 # How many of the .window last polls must be good for the backend to be declared healthy.
  .expected_response = 301;       # Expected Response Status Code 404 302 200 etc.
  }                               # <-- Health Checks
.first_byte_timeout     = 10s; # How long to wait before we receive the first byte from our backend ?
.connect_timeout        = 10s; # How long to wait for a backend connection ?
.between_bytes_timeout  = 5s;  # How long to wait between bytes received from our backend ?
}

#############################################################################################################################
# Directors & Load Balancers
#############################################################################################################################

# Round Robin Directors
sub vcl_init {
  new fronts = directors.round_robin();
  fronts.add_backend(server1);
  fronts.add_backend(server2);
  fronts.add_backend(server3);
}

# sub vcl_init {
#  new apis = directors.round_robin();
#  apis.add_backend(api1);
#  apis.add_backend(api2);
# }

# Hash Director
# sub vcl_init {
#  new hash = directors.hash();
#  hash.add_backend(server1, 1.0);
#  hash.add_backend(server2, 1.0);
#  hash.add_backend(server3, 1.0);
# } 

# Random Director
# new random = directors.random();
#  roundrobin.add_backend(server1);
#  roundrobin.add_backend(server2);
#  roundrobin.add_backend(server3);
# }

# Sticky Session --> Load Balancing Based on AWSELB Cookie with round robin fallback
# sub vcl_recv {
# if (req.http.cookie ~ "AWSELB=") {
#  set client.identity = regsub(req.http.Cookie,"^.*?AWSELB=([^;]*);*.*$", "\1");
#  set req.backend_hint = hash.backend(client.identity);
#  } else {
#  set req.backend_hint = roundrobin.backend();
#  }
# }

# Sticky Session Load Balancing Based on JSESSIONID Cookie with round robin fallback
# sub vcl_recv {
# if (req.http.cookie ~ "JSESSIONID=") {
#  set client.identity = regsub(req.http.Cookie,"^.*?JSESSIONID=([^;]*);*.*$", "\1");
#  set req.backend_hint = hash.backend(client.identity);
#  } else {
#  set req.backend_hint = roundrobin.backend();
#  }
# }

# Sticky Session Load Balancing Pure Cookie Based Routing with round robin fallback
# Apache conf [ Header add Set-Cookie "Backend=1; expires=Fri, 01 May 2020 20:56:25 GMT; path=/;" ]
# sub vcl_recv {
# if (req.http.cookie ~ "Backend=") {
#   if (regsub(req.http.Cookie,"^.*?X-Backend=([^;]*);*.*$", "\1") == "1") {
#     set req.backend_hint = server1;
#    }
#   if (regsub(req.http.Cookie,"^.*?X-Backend=([^;]*);*.*$", "\1") == "2") {
#     set req.backend_hint = server2;
#    }
#   if (regsub(req.http.Cookie,"^.*?X-Backend=([^;]*);*.*$", "\1") == "3") {
#     set req.backend_hint = server3;
#    }
#   if (regsub(req.http.Cookie,"^.*?X-Backend=([^;]*);*.*$", "\1") == "4") {
#     set req.backend_hint = server4;
#    }
#   if (regsub(req.http.Cookie,"^.*?X-Backend=([^;]*);*.*$", "\1") == "5") {
#     set req.backend_hint = server5;
#    }
#   if (regsub(req.http.Cookie,"^.*?X-Backend=([^;]*);*.*$", "\1") == "6") {
#     set req.backend_hint = server6;
#    }
#   } else {
#   set req.backend_hint = roundrobin.backend();
#  }
# }

# Send Traffic to the Director based on path 
# sub vcl_recv {
#    if (req.url ~ "^/apiv1/"           || 
#         req.url ~ "^/feed"            ||
#         req.url ~ "^/wsb"             ||
#         req.url ~ "^/services/"  	||
#         req.url ~ "^/Example/rest/"  ) {
#         set req.backend_hint = apis.backend();
#    } else {
#        set req.backend_hint = fronts.backend();
#    }
# }

# Send Traffic to Director RR
sub vcl_recv {
    set req.backend_hint = fronts.backend();
}


#############################################################################################################################
# Cache invalidation ( PURGE | RPURGE | HPURGE )
#############################################################################################################################

# Allow PURGE, RPURGE, and HPURGE Requests From
# acl purgers {
#  "10.0.0.1";      # localhost
#  "172.168.1.0"/24; # 192.168.1.x
#  "192.168.2.0"/24; # 192.168.2.x
# }

# HTTP PURGE Method (Purge single url)
# Example curl -X PURGE -I http://example.com/qubbaj.html
# sub vcl_recv {
# if (req.method == "PURGE") {
#  if (!client.ip ~ purgers) {
#   return (synth(405, "This IP is not allowed to send PURGE requests."));
#  }
#   return (purge);
#   return (synth(200, "Purged."));
#  }
# }

# HTTP [R]PURGE Method (Purge [R]egular Expression's)
# Example curl -X RPURGE -I http://example.com/img/*
# sub vcl_recv {
# if (req.method == "RPURGE") {
#  if (!client.ip ~ purgers) { 
#   return (synth(405, "This IP is not allowed to send RPURGE requests."));
#  }
#   ban("req.http.host == " +req.http.host+" && req.url ~ "+req.url);
#   return (synth(200, "Purged."));
#  }
# }

# HPURGE Purge via Backend Header 
# Allow the Backend to purge content after events using the backend response header
# sub vcl_backend_response {
#   if (beresp.http.HPURGE) {
#   ban("req.url ~ " + beresp.http.HPURGE);
#   }
# }

#############################################################################################################################
# User Login
#############################################################################################################################

# PIPE LOGIN and LOGOUT Requests allow the backend to return Set-Cookie only on login and logout
# sub vcl_recv {
#  if (req.http.url ~ "/logout" || req.http.url ~ "/login" || req.http.url ~ "/etc" ) {
#    return(pipe);
#  }
# }

# Remove Backend response cookies if the request is not Login/Logout
# sub vcl_backend_response {
#  if (bereq.http.url !~ "login" || bereq.http.url !~ "logout" ) {
#    unset beresp.http.set-cookie;
#  }
# }

# Remove Client Cookies if the main Cookie is not exist for example JSESSIONID
# sub vcl_recv {
#  if (req.http.cookie !~ "PHPSESSID") {
#    unset req.http.cookie;
#  }
# }

#############################################################################################################################
# No Cache URLS
#############################################################################################################################

# Pass directly to backend (do not cache) requests for the following paths/pages.
# sub vcl_recv {
# if (req.url ~ "^/status\.php$" ||
#   req.url ~ "^/update\.php$"   ||
#   req.url ~ "^/admin"          ||
#   req.url ~ "^/admin/.*$"      ||
#   req.url ~ "^/user"           ||
#   req.url ~ "^/user/.*$"       ||
#   req.url ~ "^/node/.*/edit$"  ||
#   req.url ~ "^.*/ahah/.*$") {
#   return (pass);
#  }
# }


############################################################################################################################
# Enable cache for static file
#############################################################################################################################
# Remove Backend Cookies for the static resources
# sub vcl_backend_response {
#    if (bereq.url ~ "\.(bmp|bz2|css|doc|eot|flv|gif|gz|ico|jpeg|jpg|js|less|mp[34]|pdf|png|rar|rtf|swf|tar|tgz|txt|wav|woff|xml|zip)") {
#       unset beresp.http.Set-Cookie;
#   }
# }

# Remove Client Cookies for the static resources
# sub vcl_recv {
#    if (req.url ~ "\.(bmp|bz2|css|doc|eot|flv|gif|gz|ico|jpeg|jpg|js|less|mp[34]|pdf|png|rar|rtf|swf|tar|tgz|txt|wav|woff|xml|zip)") {
#       unset req.http.Cookie;
#    }
# }

# Override the baseline TTLs on certain filetypes
#  sub vcl_backend_response {
#   if (bereq.url ~ "(css|js)") {
#     set beresp.ttl = 31536000s;
#     set beresp.http.Cache-Control = "max-age=31536000, public";
#   } 
# }

# Override the baseline TTLs for URl/*
#  sub vcl_backend_response {
#   if (bereq.url ~ "/URL/") {
#     set beresp.ttl = 3600s;
#     set beresp.http.Cache-Control = "max-age=3600, public";
#   }
# }

# Set 6000 sec cache if unset for static files
# sub vcl_backend_response {
#  if (beresp.ttl <= 0s && bereq.url ~ "^[^?]*\.(bmp|bz2|css|doc|eot|flv|gif|gz|ico|jpeg|jpg|js|less|mp[34]|pdf|png|rar|rtf|swf|tar|tgz|txt|wav|woff|xml|zip)(\?.*)?$") {
#     set beresp.ttl = 6000s;
#     set beresp.uncacheable = true;
#     return (deliver);
#   }
# }

#############################################################################################################################
# Hashing Data
#############################################################################################################################
sub vcl_hash {
  hash_data(req.url); # Hash On URL
  if (req.http.host) {
    hash_data(req.http.host);
   } else {
    hash_data(server.ip);
   }
  if (req.http.Cookie) {
    hash_data(req.http.Cookie);
  }
}


#############################################################################################################################
# Grace Mode:- return expired objects if the backend is not healthy and extend all the ttl to 24 hours + the original ttl
#############################################################################################################################

# Enable Grace on Client Request
sub vcl_recv {
  set req.http.grace = "none";
}

# Enable Grace on Backend responce
sub vcl_backend_response {
  set beresp.grace = 24h;
}

# Main Grace
sub vcl_hit {
  if (obj.ttl >= 0s) {
    # normal hit
    return (deliver);
  }
  # look at the stale obj's.
  if (std.healthy(req.backend_hint)) {
    # Backend is healthy. Limit age to 10s.
    if (obj.ttl + 10s > 0s) {
      set req.http.grace = "normal(limited)";
      return (deliver);
    } else {
      # No candidate for grace. Fetch a fresh object.
      return(fetch);
   }
  } else {
    # backend is sick - use full grace
    if (obj.ttl + obj.grace > 0s) {
      set req.http.grace = "full";
      return (deliver);
    } else {
     # no graced object.
    return (fetch);
   }
  }
}

#############################################################################################################################
# Generic URLs Manipulation
#############################################################################################################################

# Remove Google Analytics parameters
sub vcl_recv {
if (req.url ~ "(\?|&)(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=") {
  set req.url = regsuball(req.url, "&(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "");
  set req.url = regsuball(req.url, "\?(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "?");
  set req.url = regsub(req.url, "\?&", "?");
  set req.url = regsub(req.url, "\?$", "");
  }
}

# Remove Javascript hashtags
sub vcl_recv {
  if (req.url ~ "\#") {
  set req.url = regsub(req.url, "\#.*$", "");
  }
}

#############################################################################################################################
# Generic Cookies Manipulation
#############################################################################################################################
sub vcl_recv {
  
  # If Cookie 
  if (req.http.Cookie ~ "(\?|&)(has_js|__utm|_ga|utmctr|utmcmd|utmccn|__qc|__atuvc)=") {
  
  # Remove the "has_js" cookie
  set req.http.Cookie = regsuball(req.http.Cookie, "has_js=[^;]+(; )?", "");
  
  # Remove any Google Analytics based cookies
  set req.http.Cookie = regsuball(req.http.Cookie, "__utm.=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "_ga=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "_cb_ls=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "_em_vt=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "__gfp_64b=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "__gads=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "_ga=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "utmctr=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "utmcmd.=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "utmccn.=[^;]+(; )?", "");
  
  # Remove the Quant Capital cookies (added by some plugin, all __qca)
  set req.http.Cookie = regsuball(req.http.Cookie, "__qc.=[^;]+(; )?", "");
  
  # Remove the AddThis cookies
  set req.http.Cookie = regsuball(req.http.Cookie, "__atuvc=[^;]+(; )?", "");
  
  # Remove a ";" prefix in the cookie if present
  set req.http.Cookie = regsuball(req.http.Cookie, "^;\s*", "");
  }
}

# Remove Blank Cookies
# sub vcl_recv {
#  if (req.http.cookie ~ "^\s*$") {
#    unset req.http.cookie;
#  }
# }

#############################################################################################################################
# Clean up Varnish Resp (Remove Debugging and unused headers)
#############################################################################################################################
sub vcl_deliver {
 unset resp.http.X-Varnish;
 unset resp.http.Via;
 unset resp.http.Server;
 unset resp.http.X-Powered-By;
 unset resp.http.ETag;
 unset resp.http.X-Drupal-Cache;
 unset resp.http.Link;
}

#############################################################################################################################
# Disable CDN Caching if the Backend responce with X-NOCDN Header Content will be cached on varnish only!
#############################################################################################################################
# X-NoCDN Custom Header
# sub vcl_deliver {
#   if ( resp.http.X-NoCDN == "true") {
#     set resp.http.Cache-Control = "no-cache, max-age=0";
#   }
# } 

#############################################################################################################################
# Normalize Stuff
#############################################################################################################################
sub vcl_recv {

  # Return correct hostname to the backend 
  # set req.http.host = regsub(req.http.host, "^name\-elb\-105212312\.us\-east\-1\.elb\.amazonaws\.com", "site.com");

  # Normalize the header, remove the port
  # set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");

  # PIPE Non-RFC2616 HTTP Methods
  if (req.method != "GET" &&
      req.method != "HEAD" &&
      req.method != "PUT" &&
      req.method != "POST" &&
      req.method != "TRACE" &&
      req.method != "OPTIONS" &&
      req.method != "PATCH" &&
      req.method != "DELETE") {
      /* Non-RFC2616 or CONNECT which is weird. */
    return (pipe);
  }

  # Only cache GET or HEAD requests. This makes sure the POST requests are always passed.
  if (req.method != "GET" && req.method != "HEAD") {
    return (pass);
  }

  # X-Forwarded-For
  if (req.restarts == 0) {
    if (req.http.X-Forwarded-For) {
      set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
    } else {
      set req.http.X-Forwarded-For = client.ip;
    }
  }

# Normalize Accept-Encoding header
  if (req.http.Accept-Encoding) {
    if (req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg)$") {
      # No point in compressing these
      unset req.http.Accept-Encoding;
    } elsif (req.http.Accept-Encoding ~ "gzip") {
      set req.http.Accept-Encoding = "gzip";
    } elsif (req.http.Accept-Encoding ~ "deflate") {
      set req.http.Accept-Encoding = "deflate";
    } else {
      # unkown algorithm
      unset req.http.Accept-Encoding;
    }
  }
}

#############################################################################################################################
# ESI:- Edge Side Includes
#############################################################################################################################

# Send Surrogate-Capability headers to announce ESI support to backend
# sub vcl_recv {
#  set req.http.Surrogate-Capability = "key=ESI/1.0";
# }

# Pause ESI request and remove Surrogate-Control header
# sub vcl_backend_response {
#  if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
#   unset beresp.http.Surrogate-Control;
#   set beresp.do_esi = true;
#  }
# }

#############################################################################################################################
# Debuging
#############################################################################################################################

# Cache Status Header (HIT Or MISS.) ~~> 
sub vcl_deliver {
if (obj.hits > 0) {
 set resp.http.X-Cache = "HIT";
 } else {
 set resp.http.X-Cache = "MISS";
 }
}

# Header To Track Varnish ID ~~>
sub vcl_deliver {
  set resp.http.X-Node-ID = "Varnish 1";
}

# MISS Request If Debug header exist ~~>
sub vcl_recv {
  if (req.http.Debug) {
    return (pass);
  }
}

# Cookie Debugging ~~->
# sub vcl_backend_response {
#   if (bereq.http.Debug) {
#     set beresp.http.X-Cookie-Client-to-Varnish = bereq.http.Cookie;
#     set beresp.http.X-Cookie-Backend-to-Varnish = beresp.http.set-cookie;
#     set beresp.http.X-Cookie-Varnish-to-Backend = bereq.http.Cookie;
#    
#     # JSESSIONID Value
#     set beresp.http.X-Cookie-Varnish-to-Backend = regsub(bereq.http.Cookie,"^.*?JSESSIONID=([^;]*);*.*$", "\1");
#     set beresp.http.X-Cookie-Backend-to-Varnish = regsub(beresp.http.set-cookie,"^.*?JSESSIONID=([^;]*);*.*$", "\1");
#     set beresp.http.X-Site = regsuball(beresp.http.set-cookie, "(^|; ) *JSESSIONID.=[^;]+;? *", "\1");
#   }
# }

# Debug chaching Status ~~~~>
sub vcl_backend_response {

  # Varnish determined the object was not cacheable
  if (!(beresp.ttl > 0s)) {
    set beresp.http.X-Cacheable = "NO:Not Cacheable, ttl <0s";
    set beresp.http.X-ttl = beresp.ttl;
    # return(hit_for_pass);
  }
  elseif (bereq.http.Cookie) {
    set beresp.http.X-Cacheable = "NO:Got cookie";
    set beresp.http.X-Cookie = beresp.http.Cookie;
    # return(hit_for_pass);
  }
  elseif (beresp.http.Cache-Control ~ "private") {
    set beresp.http.X-Cacheable = "NO:Cache-Control=private";
    # return(hit_for_pass);
  }
  elseif (beresp.http.Cache-Control ~ "no-cache" || beresp.http.Pragma ~ "no-cache") {
    set beresp.http.X-Cacheable = "Refetch forced by user";
    # return(hit_for_pass);
  # You are extending the lifetime of the object artificially
  }
  elseif (beresp.ttl < 1s) {
    set beresp.ttl   = 5s;
    set beresp.grace = 5s;
    set beresp.http.X-Cacheable = "YES:FORCED";
  # Varnish determined the object was cacheable
  } else {
    set beresp.http.X-Cacheable = "YES";
    set beresp.http.X-ttl = beresp.ttl;
  }
}

# Debug Grace
# sub vcl_deliver {
#     set resp.http.grace = req.http.grace;
# }

#############################################################################################################################
# Errors
#############################################################################################################################
# Overwrite Errors With Custom Html Code
# sub vcl_backend_error {
#       set beresp.http.Content-Type = "text/html; charset=utf-8";
#       set beresp.http.Retry-After = "5";
#       synthetic( {"<!DOCTYPE html>
#       <html>
#         <head>
#         <meta charset="UTF-8">
#         <meta content="" name="description">
#         <meta content="" name="author">
#         <meta http-equiv="refresh" content="5"; url=http://"} + bereq.http.host + bereq.url + {" />
#         <title>"} + beresp.status + " " + beresp.reason + {"</title>
#         </head>
#         <body>
#         <div style="text-align: center; background: none repeat scroll 0% 0% rgb(244, 244, 244); border-radius: 10px; border-right: 1px solid rgb(170, 170, 170); border-style: solid; border-color: rgb(204, 0, 0) rgb(170, 170, 170) rgb(170, 170, 170); -moz-border-top-colors: none; -moz-border-right-colors: none; -moz-border-bottom-colors: none; -moz-border-left-colors: none; border-image: none; height: auto; width: 50%; margin: 7% auto; border-width: 5px 1px 1px;">
#         <h3 style="padding-top: 10px; color: rgb(204, 0, 0);">VA-502 Error</h3>
#         <p style="margin: 7px 128px;">The server encountered a temporary error and could not complete your request, This page will retry automatically within 5 secounds please wait.</p>
#         <p>ERROR-ID: "} + bereq.xid + {"</p>
#         </div>
#    </body>
# </html>
#   "} );
#   return (deliver);
# }

#############################################################################################################################
# No-Cache For 50x Errors
#############################################################################################################################

# if backend return 50x send to vcl_deliver with no-cache and set ttl =0 
# sub vcl_backend_response {
#   if (beresp.status == 500 || beresp.status == 502 || beresp.status == 503 ) {
#     set beresp.http.Cache-Control = "no-cache, no-store, max-age=0, must-revalidate";
#     set beresp.ttl = 0s;
#     return (deliver);
#   }
# }

# if status = 502 || 503 || 500 send to vcl_synth
# sub vcl_deliver {
#   if (resp.status == 500 || resp.status == 502 || resp.status == 503) {
#     return (synth(751, "502"));
#  }
# }

# sub vcl_synth {
#         set resp.status = 502;
#         set resp.http.Cache-Control = "no-cache, no-store, max-age=0, must-revalidate";
#   synthetic( {"<!DOCTYPE html>
#         <html>
#         <head>
#         <meta charset="UTF-8">
#         <meta content="" name="description">
#         <meta content="" name="author">
#         <meta http-equiv="refresh" content="5"; url=http://"} + req.http.host + req.url + {" />
#         <title>"} + resp.status + " " + resp.reason + {"</title>
#         </head>
#         <body>
#         <div style="text-align: center; background: none repeat scroll 0% 0% rgb(244, 244, 244); border-radius: 10px; border-right: 1px solid rgb(170, 170, 170); border-style: solid; border-color: rgb(204, 0, 0) rgb(170, 170, 170) rgb(170, 170, 170); -moz-border-top-colors: none; -moz-border-right-colors: none; -moz-border-bottom-colors: none; -moz-border-left-colors: none; border-image: none; height: auto; width: 50%; margin: 7% auto; border-width: 5px 1px 1px;">
#         <h3 style="padding-top: 10px; color: rgb(204, 0, 0);">AP-502 Error</h3>
#         <p style="margin: 7px 128px;">The server encountered a temporary error and could not complete your request, This page will retry automatically within 5 secounds please wait.</p>
#         <p>ERROR-ID: "} + req.xid + {"</p>
#         </div>
#         </body>
#       </html>
#    "} );
#    return (deliver);
# }

