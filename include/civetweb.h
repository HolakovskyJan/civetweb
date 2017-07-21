/* Copyright (c) 2013-2017 the Civetweb developers
 * Copyright (c) 2004-2013 Sergey Lyubka
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef CIVETWEB_HEADER_INCLUDED
#define CIVETWEB_HEADER_INCLUDED

#define CIVETWEB_VERSION "1.10"
#define CIVETWEB_VERSION_MAJOR (1)
#define CIVETWEB_VERSION_MINOR (10)
#define CIVETWEB_VERSION_PATCH (0)

#ifndef CIVETWEB_API
#if defined(_WIN32)
#if defined(CIVETWEB_DLL_EXPORTS)
#define CIVETWEB_API __declspec(dllexport)
#elif defined(CIVETWEB_DLL_IMPORTS)
#define CIVETWEB_API __declspec(dllimport)
#else
#define CIVETWEB_API
#endif
#elif __GNUC__ >= 4
#define CIVETWEB_API __attribute__((visibility("default")))
#else
#define CIVETWEB_API
#endif
#endif

#include <stdio.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/* Initialize this library. This should be called once before any other
 * function from this library. This function is not guaranteed to be
 * thread safe.
 * Parameters:
 *   features: bit mask for features to be initialized.
 * Return value:
 *   initialized features
 *   0: error
 */
CIVETWEB_API unsigned mg_init_library(unsigned features);


/* Un-initialize this library.
 * Return value:
 *   0: error
 */
CIVETWEB_API unsigned mg_exit_library(void);


struct mg_context;    /* Handle for the HTTP service itself */
struct mg_connection; /* Handle for the individual connection */


/* Maximum number of headers */
#define MG_MAX_HEADERS (64)

struct mg_header {
	const char *name;  /* HTTP header name */
	const char *value; /* HTTP header value */
};


/* This structure contains information about the HTTP request. */
struct mg_request_info {
	const char *request_method; /* "GET", "POST", etc */
	const char *request_uri;    /* URL-decoded URI (absolute or relative,
				     * as in the request) */
	const char *local_uri;      /* URL-decoded URI (relative). Can be NULL
				     * if the request_uri does not address a
				     * resource at the server host. */
	const char *http_version; /* E.g. "1.0", "1.1" */
	const char *query_string; /* URL part after '?', not including '?', or
				     NULL */
	const char *remote_user;  /* Authenticated user, or NULL if no auth
				     used */
	char remote_addr[48];     /* Client's IP address as a string. */

	long long content_length; /* Length (in bytes) of the request body,
				     can be -1 if no length was given. */
	int remote_port;          /* Client's port */
	int is_ssl;               /* 1 if SSL-ed, 0 if not */
	void *user_data;          /* User data pointer passed to mg_start() */
	void *conn_data;          /* Connection-specific user data */

	int num_headers; /* Number of HTTP headers */
	struct mg_header
	    http_headers[MG_MAX_HEADERS]; /* Allocate maximum headers */

	struct client_cert *client_cert; /* Client certificate information */

	const char *acceptedWebSocketSubprotocol; /* websocket subprotocol,
						   * accepted during handshake */
};


/* This structure contains information about the HTTP request. */
/* This structure may be extended in future versions. */
struct mg_response_info {
	int status_code;          /* E.g. 200 */
	const char *status_text;  /* E.g. "OK" */
	const char *http_version; /* E.g. "1.0", "1.1" */

	long long content_length; /* Length (in bytes) of the request body,
				     can be -1 if no length was given. */

	int num_headers; /* Number of HTTP headers */
	struct mg_header
	    http_headers[MG_MAX_HEADERS]; /* Allocate maximum headers */
};


/* Client certificate information (part of mg_request_info) */
struct client_cert {
	const char *subject;
	const char *issuer;
	const char *serial;
	const char *finger;
};


/* This structure needs to be passed to mg_start(), to let civetweb know
   which callbacks to invoke. For a detailed description, see
   https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md */
struct mg_callbacks {
	/* Called when civetweb has received new HTTP request.
	   If the callback returns one, it must process the request
	   by sending valid HTTP headers and a body. Civetweb will not do
	   any further processing. Otherwise it must return zero.
	   Note that since V1.7 the "begin_request" function is called
	   before an authorization check. If an authorization check is
	   required, use a request_handler instead.
	   Return value:
	     0: civetweb will process the request itself. In this case,
		the callback must not send any data to the client.
	     1-999: callback already processed the request. Civetweb will
		    not send any data after the callback returned. The
		    return code is stored as a HTTP status code for the
		    access log. */
	int (*begin_request)(struct mg_connection *);

	/* Called when civetweb has finished processing request. */
	void (*end_request)(const struct mg_connection *, int reply_status_code);

	/* Called when civetweb is about to log a message. If callback returns
	   non-zero, civetweb does not log anything. */
	int (*log_message)(const struct mg_connection *, const char *message);

	/* Called when civetweb is about to log access. If callback returns
	   non-zero, civetweb does not log anything. */
	int (*log_access)(const struct mg_connection *, const char *message);

	/* Called when civetweb initializes SSL library.
	   Parameters:
	     user_data: parameter user_data passed when starting the server.
	   Return value:
	     0: civetweb will set up the SSL certificate.
	     1: civetweb assumes the callback already set up the certificate.
	    -1: initializing ssl fails. */
	int (*init_ssl)(void *ssl_context, void *user_data);

	/* Called when civetweb is closing a connection.  The per-context mutex is
	   locked when this is invoked.  This is primarily useful for noting when
	   a websocket is closing and removing it from any application-maintained
	   list of clients.
	   Using this callback for websocket connections is deprecated: Use
	   mg_set_websocket_handler instead. */
	void (*connection_close)(const struct mg_connection *);

#if defined(MG_USE_OPEN_FILE)
	/* Note: The "file in memory" feature is a deletion candidate, since
	 * it complicates the code, and does not add any value compared to
	 * "mg_add_request_handler".
	 * See this discussion thread:
	 * https://groups.google.com/forum/#!topic/civetweb/h9HT4CmeYqI
	 * If you disagree, if there is any situation this is indeed useful
	 * and cannot trivially be replaced by another existing feature,
	 * please contribute to this discussion during the next 3 month
	 * (till end of April 2017), otherwise this feature might be dropped
	 * in future releases. */

	/* Called when civetweb tries to open a file. Used to intercept file open
	   calls, and serve file data from memory instead.
	   Parameters:
	      path:     Full path to the file to open.
	      data_len: Placeholder for the file size, if file is served from
			memory.
	   Return value:
	     NULL: do not serve file from memory, proceed with normal file open.
	     non-NULL: pointer to the file contents in memory. data_len must be
	       initialized with the size of the memory block. */
	const char *(*open_file)(const struct mg_connection *,
				 const char *path,
				 size_t *data_len);
#endif

	/* Called when civetweb is about to serve Lua server page, if
	   Lua support is enabled.
	   Parameters:
	     lua_context: "lua_State *" pointer. */
	void (*init_lua)(const struct mg_connection *, void *lua_context);

	/* Called when civetweb is about to send HTTP error to the client.
	   Implementing this callback allows to create custom error pages.
	   Parameters:
	     status: HTTP error status code.
	   Return value:
	     1: run civetweb error handler.
	     0: callback already handled the error. */
	int (*http_error)(struct mg_connection *, int status);

	/* Called after civetweb context has been created, before requests
	   are processed.
	   Parameters:
	     ctx: context handle */
	void (*init_context)(const struct mg_context *ctx);

	/* Called when a new worker thread is initialized.
	   Parameters:
	     ctx: context handle
	     thread_type:
	       0 indicates the master thread
	       1 indicates a worker thread handling client connections
	       2 indicates an internal helper thread (timer thread)
	       */
	void (*init_thread)(const struct mg_context *ctx, int thread_type);

	/* Called when civetweb context is deleted.
	   Parameters:
	     ctx: context handle */
	void (*exit_context)(const struct mg_context *ctx);
};


/* This structure can be passed to mg_start(), to configure civetweb */
struct mg_config
{
	/* Access-Control-Allow-Headers header field, used for cross-origin resource
	   sharing (CORS) pre-flight requests.
	   See the [Wikipedia page on CORS](http://en.wikipedia.org/wiki/Cross-origin_resource_sharing).
	   
	   If set to an empty string, pre-flights will not allow additional headers.
	   If set to "*", the pre-flight will allow whatever headers have been requested.
	   If set to a comma separated list of valid HTTP headers, the pre-flight will return
	   exactly this list as allowed headers.
	   If set in any other way, the result is unspecified. */
	char *access_control_allow_headers;

	/* Access-Control-Allow-Methods header field, used for cross-origin resource
	   sharing (CORS) pre-flight requests.
	   See the [Wikipedia page on CORS](http://en.wikipedia.org/wiki/Cross-origin_resource_sharing). */
	char *access_control_allow_methods;

	/* Access-Control-Allow-Origin header field, used for cross-origin resource
	   sharing (CORS).
	   See the [Wikipedia page on CORS](http://en.wikipedia.org/wiki/Cross-origin_resource_sharing). */
	char *access_control_allow_origin;

	/* An Access Control List (ACL) allows restrictions to be put on the list of IP
	   addresses which have access to the web server. In the case of the Civetweb
	   web server, the ACL is a comma separated list of IP subnets, where each
	   subnet is pre-pended by either a `-` or a `+` sign. A plus sign means allow,
	   where a minus sign means deny. If a subnet mask is omitted, such as `-1.2.3.4`,
	   this means to deny only that single IP address.
	   
	   Subnet masks may vary from 0 to 32, inclusive. The default setting is to allow
	   all accesses. On each request the full list is traversed, and
	   the last match wins. Examples:

	   -0.0.0.0/0,+192.168/16    deny all accesses, only allow 192.168/16 subnet

	   To learn more about subnet masks, see the
	   [Wikipedia page on Subnetwork](http://en.wikipedia.org/wiki/Subnetwork). */
	char *access_control_list;

	/* Send additional HTTP response header line for every request.
	   The full header line including key and value must be specified,
	   excluding the carriage return line feed. To send multiple headers,
	   they must be separated by \r\n characters. */
	char *additional_header;

	/* Authorization realm used for HTTP digest authentication.
	
	   When using absolute URLs, verify the host is identical to
	   the authentication_domain. If set, requests to absolute
	   URLs will only be processed if they are directed to the
	   domain. If NULL, absolute URLs to any host will be accepted. */
	char *authentication_domain;

	/* URL encoded request strings are decoded in the server, unless it is disabled
	   by setting this option to 1. */
	int disable_url_decode;

	/* Enables setting linger option before closing sockets. If set to 0
	   no linger option will be configured. */
	int enable_linger;

	/* Idle timeout in milliseconds between two requests in one keep-alive connection.
	   If keep alive is enabled, multiple requests using the same connection 
	   are possible. This reduces the overhead for opening and closing connections
	   when loading several resources from one server, but it also blocks one port
	   and one thread at the server during the lifetime of this connection.
	   Unfortunately, browsers do not close the keep-alive connection after loading
	   all resources required to show a website.
	   The server closes a keep-alive connection, if there is no additional request
	   from the client during this timeout.
	   If set to -1, keep alive is turned off.
	   If set to 0, default value 500 is used.
	   Any positive value is used as timeout in ms. */
	int keep_alive_timeout;

	/* Set TCP socket linger timeout before closing sockets (SO_LINGER option).
	   The configured value is a timeout in milliseconds. Setting the value to 0
	   will yield in abortive close (if the socket is closed from the server side).
	   Setting the value to -1 will turn off linger.
	   
	   Note: For consistency with other timeouts, the value is configured in
	   milliseconds. However, the TCP socket layer usually only offers a timeout in 
	   seconds, so the value should be an integer multiple of 1000. */
	int linger_timeout;

	/* Comma-separated list of ports to listen on. If the port is SSL, a
	   letter `s` must be appended, for example, `80,443s` will open
	   port 80 and port 443, and connections on port 443 will be SSL-ed.
	   For non-SSL ports, it is allowed to append letter `r`, meaning 'redirect'.
	   Redirect ports will redirect all their traffic to the first configured
	   SSL port. For example, if `listening_ports` is `80r,443s`, then all
	   HTTP traffic coming at port 80 will be redirected to HTTPS port 443.
	   
	   It is possible to specify an IP address to bind to. In this case,
	   an IP address and a colon must be pre-pended to the port number.
	   For example, to bind to a loopback interface on port 80 and to
	   all interfaces on HTTPS port 443, use `127.0.0.1:80,443s`.
	   
	   If the server is built with IPv6 support, `[::]:8080` can be used to
	   listen to IPv6 connections to port 8080. IPv6 addresses of network
	   interfaces can be specified as well,
	   e.g. `[::1]:8080` for the IPv6 loopback interface.
	   
	   [::]:80 will bind to port 80 IPv6 only. In order to use port 80 for
	   all interfaces, both IPv4 and IPv6, use either the configuration
	   `80,[::]:80` (create one socket for IPv4 and one for IPv6 only),
	   or `+80` (create one socket for both, IPv4 and IPv6). 
	   The `+`-notation to use IPv4 and IPv6 will only work in no network
	   interface is specified. Depending on your operating system version
	   and IPv6 network environment, some configurations might not work
	   as expected, so you have to test to find the configuration most 
	   suitable for your needs. In case `+80` does not work for your
	   environment, you need to use `80,[::]:80`.
	   
	   It is possible to use network interface addresses (e.g., `192.0.2.3:80`,
	   `[2001:0db8::1234]:80`). To get a list of available network interface
	   addresses, use `ipconfig` (in a `cmd` window in Windows) or `ifconfig` 
	   (in a Linux shell).
	   Alternatively, you could use the hostname for an interface. Check the 
	   hosts file of your operating system for a proper hostname 
	   (for Windows, usually found in C:\Windows\System32\drivers\etc\, 
	   for most Linux distributions: /etc/hosts). E.g., to bind the IPv6 
	   local host, you could use `ip6-localhost:80`. This translates to 
	   `[::1]:80`. Beside the hosts file, there are several other name
	   resolution services. Using your hostname might bind you to the
	   localhost or an external interface. You could also try `hostname.local`,
	   if the proper network services are installed (Zeroconf, mDNS, Bonjour, 
	   Avahi). When using a hostname, you need to test in your particular network
	   environment - in some cases, you might need to resort to a fixed IP address. */
	char *listening_ports;

	/* Size of buffer allocated for every request in bytes.
	
	   If set to 0, default value of 16384 will be used. */
	int max_request_size;

	/* Size of buffer allocated for websocket request in bytes.
	
	   If set to 0, default value of 2147418112 will be used. */
	size_t max_websocket_request_size;

	/* Number of worker threads. Civetweb handles each incoming connection in a
	   separate thread. Therefore, the value of this option is effectively the number
	   of concurrent HTTP connections Civetweb can handle.
	   
	   If set to 0, default value of 50 will be used. */
	int num_threads;

	/* Timeout for network read and network write operations, in milliseconds.
	   If a client intends to keep long - running connection, either increase this
	   value or (better)use keep - alive messages.
	   If set to -1, indefinite timeout is used.
	   If set to 0, default value 30000 is used.
	   Any positive value is used as timeout in ms. */
	int request_timeout;

	/* Path to a .pem file containing trusted certificates. The file may contain
	   more than one certificate. */
	char *ssl_ca_file;

	/* Name of a directory containing trusted CA certificates. Each file in the
	   directory must contain only a single CA certificate. The files must be named
	   by the subject name’s hash and an extension of “.0”. If there is more than one
	   certificate with the same subject name they should have extensions ".0", ".1",
	   ".2" and so on respectively. */
	char *ssl_ca_path;

	/* Path to the SSL certificate file. This option is only required when at least
	   one of the listening_ports is SSL. The file must be in PEM format,
	   and it must have both, private key and certificate, see for example
	   [ssl_cert.pem](https://github.com/civetweb/civetweb/blob/master/resources/ssl_cert.pem)
	   A description how to create a certificate can be found in doc/OpenSSL.md */
	char *ssl_certificate;

	char *ssl_certificate_chain;

	/* List of ciphers to present to the client. Entries should be separated by
	   colons, commas or spaces.
	   
	   ALL           All available ciphers
	   ALL:!eNULL    All ciphers excluding NULL ciphers
	   AES128:!MD5   AES 128 with digests other than MD5
	   
	   See [this entry](https://www.openssl.org/docs/manmaster/apps/ciphers.html) in
	   OpenSSL documentation for full list of options and additional examples. */
	char *ssl_cipher_list;

	/* Enable client's certificate verification by the server. */
	int ssl_do_verify_peer;

	/* Enables peer verification to be optional. Only works if ssl_do_verify_peer
	   is not set to 0. */
	int ssl_do_verify_peer_optional;

	/* Disables loading of default trusted certificates locations set at openssl
	   compile time. */
	int ssl_no_default_verify_paths;

	/* Sets the minimal accepted version of SSL/TLS protocol according to the table:

	   Protocols | Value
	   ------------ | -------------
	   SSL2+SSL3+TLS1.0+TLS1.1+TLS1.2  | 0
	   SSL3+TLS1.0+TLS1.1+TLS1.2  | 1
	   TLS1.0+TLS1.1+TLS1.2 | 2
	   TLS1.1+TLS1.2 | 3
	   TLS1.2 | 4 */
	int ssl_protocol_version;

	/* Enables the use of short lived certificates. This will allow for the certificates
	   and keys specified in `ssl_certificate`, `ssl_ca_file` and `ssl_ca_path` to be
	   exchanged and reloaded while the server is running.
	   
	   In an automated environment it is advised to first write the new pem file to
	   a different filename and then to rename it to the configured pem file name to
	   increase performance while swapping the certificate.
	   
	   Disk IO performance can be improved when keeping the certificates and keys stored
	   on a tmpfs (linux) on a system with very high throughput. */
	int ssl_short_trust;

	/* Sets maximum depth of certificate chain. If client's certificate chain is longer
	   than the depth set here connection is refused. */
	int ssl_verify_depth;

	/* Set the `Strict-Transport-Security` header, and set the `max-age` value.
	   This instructs web browsers to interact with the server only using HTTPS,
	   never by HTTP. If set, it will be sent for every request handled directly
	   by the server, except callbacks. They must send HTTP headers on their own.
	   
	   The time is specified in seconds. If set to 0, no `Strict-Transport-Security`
	   header will be sent. */
	int strict_http_max_age;

	/* Enable TCP_NODELAY socket option on client connections.

	   If set the socket option will disable Nagle's algorithm on the connection
	   which means that packets will be sent as soon as possible instead of waiting
	   for a full buffer or timeout to occur.
	   
	   0      Keep the default: Nagel's algorithm enabled
	   other  Disable Nagle's algorithm for all sockets */
	int tcp_nodelay;

	/* Limit download speed for clients. throttle is a comma-separated
	   list of key=value pairs, where key could be:

	   *                   limit speed for all connections
	   x.x.x.x/mask        limit speed for specified subnet
	   uri_prefix_pattern  limit speed for given URIs

	   The value is a number of bytes per second, optionally
	   followed by a `k` or `m` character, meaning kilobytes and
	   megabytes respectively. A limit of 0 means unlimited rate. The
	   last matching rule wins. Examples:

	   *=1k,10.0.0.0/8=0   limit all accesses to 1 kilobyte per second,
			       but give connections the from 10.0.0.0/8 subnet
			       unlimited speed

	   /downloads/=5k      limit accesses to all URIs in `/downloads/` to
			       5 kilobytes per second. All other accesses are
			       unlimited. */
	char *throttle;

	/* Same as request_timeout but for websockets. If set to 0, request_timeout
	   will be used instead.
	   If set to -1, indefinite timeout is used.
	   If set to 0, default value 30000 is used.
	   Any positive value is used as timeout in ms. */
	int websocket_timeout;
};


/* Start web server.

   Parameters:
     callbacks: mg_callbacks structure with user-defined callbacks.
     options: NULL terminated list of option_name, option_value pairs that
	      specify Civetweb configuration parameters.

   Side-effects: on UNIX, ignores SIGCHLD and SIGPIPE signals. If custom
      processing is required for these, signal handlers must be set up
      after calling mg_start().


   Example:
     const char *options[] = {
       "document_root", "/var/www",
       "listening_ports", "80,443s",
       NULL
     };
     struct mg_context *ctx = mg_start(&my_func, NULL, options);

   Refer to https://github.com/civetweb/civetweb/blob/master/docs/UserManual.md
   for the list of valid option and their possible values.

   Return:
     web server context, or NULL on error. */
CIVETWEB_API struct mg_context *mg_start(const struct mg_callbacks *callbacks,
					 void *user_data,
					 struct mg_config *configuration_options);


/* Stop the web server.

   Must be called last, when an application wants to stop the web server and
   release all associated resources. This function blocks until all Civetweb
   threads are stopped. Context pointer becomes invalid. */
CIVETWEB_API void mg_stop(struct mg_context *);


/* mg_request_handler

   Called when a new request comes in.  This callback is URI based
   and configured with mg_set_request_handler().

   Parameters:
      conn: current connection information.
      cbdata: the callback data configured with mg_set_request_handler().
   Returns:
      0: the handler could not handle the request, so fall through.
      1 - 999: the handler processed the request. The return code is
	       stored as a HTTP status code for the access log. */
typedef int (*mg_request_handler)(struct mg_connection *conn, void *cbdata);


/* mg_set_request_handler

   Sets or removes a URI mapping for a request handler.
   This function uses mg_lock_context internally.

   URI's are ordered and prefixed URI's are supported. For example,
   consider two URIs: /a/b and /a
	   /a   matches /a
	   /a/b matches /a/b
	   /a/c matches /a

   Parameters:
      ctx: server context
      uri: the URI (exact or pattern) for the handler
      handler: the callback handler to use when the URI is requested.
	       If NULL, an already registered handler for this URI will
	       be removed.
	       The URI used to remove a handler must match exactly the
	       one used to register it (not only a pattern match).
      cbdata: the callback data to give to the handler when it is called. */
CIVETWEB_API void mg_set_request_handler(struct mg_context *ctx,
					 const char *uri,
					 mg_request_handler handler,
					 void *cbdata);


/* Callback types for websocket handlers in C/C++.

   mg_websocket_connect_handler
       Is called when the client intends to establish a websocket connection,
       before websocket handshake.
       Return value:
	 0: civetweb proceeds with websocket handshake.
	 1: connection is closed immediately.

   mg_websocket_ready_handler
       Is called when websocket handshake is successfully completed, and
       connection is ready for data exchange.

   mg_websocket_data_handler
       Is called when a data frame has been received from the client.
       Parameters:
	 bits: first byte of the websocket frame, see websocket RFC at
	       http://tools.ietf.org/html/rfc6455, section 5.2
	 data, data_len: payload, with mask (if any) already applied.
       Return value:
	 1: keep this websocket connection open.
	 0: close this websocket connection.

   mg_connection_close_handler
       Is called, when the connection is closed.*/
typedef int (*mg_websocket_connect_handler)(const struct mg_connection *,
					    void *);
typedef void (*mg_websocket_ready_handler)(struct mg_connection *, void *);
typedef int (*mg_websocket_data_handler)(struct mg_connection *,
					 int,
					 char *,
					 size_t,
					 void *);
typedef void (*mg_websocket_close_handler)(const struct mg_connection *,
					   void *);

/* struct mg_websocket_subprotocols
 *
 * List of accepted subprotocols
 */
struct mg_websocket_subprotocols {
	int nb_subprotocols;
	char **subprotocols;
};

/* mg_set_websocket_handler

   Set or remove handler functions for websocket connections.
   This function works similar to mg_set_request_handler - see there. */
CIVETWEB_API void
mg_set_websocket_handler(struct mg_context *ctx,
			 const char *uri,
			 mg_websocket_connect_handler connect_handler,
			 mg_websocket_ready_handler ready_handler,
			 mg_websocket_data_handler data_handler,
			 mg_websocket_close_handler close_handler,
			 void *cbdata);

/* mg_set_websocket_handler

   Set or remove handler functions for websocket connections.
   This function works similar to mg_set_request_handler - see there. */
CIVETWEB_API void mg_set_websocket_handler_with_subprotocols(
    struct mg_context *ctx,
    const char *uri,
    struct mg_websocket_subprotocols *subprotocols,
    mg_websocket_connect_handler connect_handler,
    mg_websocket_ready_handler ready_handler,
    mg_websocket_data_handler data_handler,
    mg_websocket_close_handler close_handler,
    void *cbdata);


/* mg_authorization_handler

   Callback function definition for mg_set_auth_handler

   Parameters:
      conn: current connection information.
      cbdata: the callback data configured with mg_set_request_handler().
   Returns:
      0: access denied
      1: access granted
 */
typedef int (*mg_authorization_handler)(struct mg_connection *conn,
					void *cbdata);


/* mg_set_auth_handler

   Sets or removes a URI mapping for an authorization handler.
   This function works similar to mg_set_request_handler - see there. */
CIVETWEB_API void mg_set_auth_handler(struct mg_context *ctx,
				      const char *uri,
				      mg_authorization_handler handler,
				      void *cbdata);


/* Get context from connection. */
CIVETWEB_API struct mg_context *
mg_get_context(const struct mg_connection *conn);


/* Get user data passed to mg_start from context. */
CIVETWEB_API void *mg_get_user_data(const struct mg_context *ctx);


/* Set user data for the current connection. */
CIVETWEB_API void mg_set_user_connection_data(struct mg_connection *conn,
					      void *data);


/* Get user data set for the current connection. */
CIVETWEB_API void *
mg_get_user_connection_data(const struct mg_connection *conn);


/* Get a formatted link corresponding to the current request

   Parameters:
      conn: current connection information.
      buf: string buffer (out)
      buflen: length of the string buffer
   Returns:
      <0: error
      >=0: ok */
CIVETWEB_API int
mg_get_request_link(const struct mg_connection *conn, char *buf, size_t buflen);


struct mg_server_ports {
	int protocol;    /* 1 = IPv4, 2 = IPv6, 3 = both */
	int port;        /* port number */
	int is_ssl;      /* https port: 0 = no, 1 = yes */
	int is_redirect; /* redirect all requests: 0 = no, 1 = yes */
	int _reserved1;
	int _reserved2;
	int _reserved3;
	int _reserved4;
};


/* Get the list of ports that civetweb is listening on.
   The parameter size is the size of the ports array in elements.
   The caller is responsibility to allocate the required memory.
   This function returns the number of struct mg_server_ports elements
   filled in, or <0 in case of an error. */
CIVETWEB_API int mg_get_server_ports(const struct mg_context *ctx,
				     int size,
				     struct mg_server_ports *ports);


/* Return information associated with the request.
 * Use this function to implement a server and get data about a request
 * from a HTTP/HTTPS client.
 * Note: Before CivetWeb 1.10, this function could be used to read
 * a response from a server, when implementing a client, although the
 * values were never returned in appropriate mg_request_info elements.
 * It is strongly advised to use mg_get_response_info for clients.
 */
CIVETWEB_API const struct mg_request_info *
mg_get_request_info(const struct mg_connection *);


/* Return information associated with a HTTP/HTTPS response.
 * Use this function in a client, to check the response from
 * the server. */
CIVETWEB_API const struct mg_response_info *
mg_get_response_info(const struct mg_connection *);


/* Send data to the client.
   Return:
    0   when the connection has been closed
    -1  on error
    >0  number of bytes written on success */
CIVETWEB_API int mg_write(struct mg_connection *, const void *buf, size_t len);


/* Send data to a websocket client wrapped in a websocket frame.  Uses
   mg_lock_connection to ensure that the transmission is not interrupted,
   i.e., when the application is proactively communicating and responding to
   a request simultaneously.

   Send data to a websocket client wrapped in a websocket frame.
   This function is available when civetweb is compiled with -DUSE_WEBSOCKET

   Return:
    0   when the connection has been closed
    -1  on error
    >0  number of bytes written on success */
CIVETWEB_API int mg_websocket_write(struct mg_connection *conn,
				    int opcode,
				    const char *data,
				    size_t data_len);


/* Blocks until unique access is obtained to this connection. Intended for use
   with websockets only.
   Invoke this before mg_write or mg_printf when communicating with a
   websocket if your code has server-initiated communication as well as
   communication in direct response to a message. */
CIVETWEB_API void mg_lock_connection(struct mg_connection *conn);
CIVETWEB_API void mg_unlock_connection(struct mg_connection *conn);


/* Lock server context.  This lock may be used to protect resources
   that are shared between different connection/worker threads. */
CIVETWEB_API void mg_lock_context(struct mg_context *ctx);
CIVETWEB_API void mg_unlock_context(struct mg_context *ctx);


/* Opcodes, from http://tools.ietf.org/html/rfc6455 */
enum {
	WEBSOCKET_OPCODE_CONTINUATION = 0x0,
	WEBSOCKET_OPCODE_TEXT = 0x1,
	WEBSOCKET_OPCODE_BINARY = 0x2,
	WEBSOCKET_OPCODE_CONNECTION_CLOSE = 0x8,
	WEBSOCKET_OPCODE_PING = 0x9,
	WEBSOCKET_OPCODE_PONG = 0xa
};


/* Macros for enabling compiler-specific checks for printf-like arguments. */
#undef PRINTF_FORMAT_STRING
#if defined(_MSC_VER) && _MSC_VER >= 1400
#include <sal.h>
#if defined(_MSC_VER) && _MSC_VER > 1400
#define PRINTF_FORMAT_STRING(s) _Printf_format_string_ s
#else
#define PRINTF_FORMAT_STRING(s) __format_string s
#endif
#else
#define PRINTF_FORMAT_STRING(s) s
#endif

#ifdef __GNUC__
#define PRINTF_ARGS(x, y) __attribute__((format(printf, x, y)))
#else
#define PRINTF_ARGS(x, y)
#endif


/* Send data to the client using printf() semantics.
   Works exactly like mg_write(), but allows to do message formatting. */
CIVETWEB_API int mg_printf(struct mg_connection *,
			   PRINTF_FORMAT_STRING(const char *fmt),
			   ...) PRINTF_ARGS(2, 3);


/* Send a part of the message body, if chunked transfer encoding is set.
 * Only use this function after sending a complete HTTP request or response
 * header with "Transfer-Encoding: chunked" set. */
CIVETWEB_API int mg_send_chunk(struct mg_connection *conn,
			       const char *chunk,
			       unsigned int chunk_len);


/* Send HTTP error reply. */
CIVETWEB_API void mg_send_http_error(struct mg_connection *conn,
				     int status_code,
				     PRINTF_FORMAT_STRING(const char *fmt),
				     ...) PRINTF_ARGS(3, 4);


/* Read data from the remote end, return number of bytes read.
   Return:
     0     connection has been closed by peer. No more data could be read.
     < 0   read error. No more data could be read from the connection.
     > 0   number of bytes read into the buffer. */
CIVETWEB_API int mg_read(struct mg_connection *, void *buf, size_t len);


/* Get the value of particular HTTP header.

   This is a helper function. It traverses request_info->http_headers array,
   and if the header is present in the array, returns its value. If it is
   not present, NULL is returned. */
CIVETWEB_API const char *mg_get_header(const struct mg_connection *,
				       const char *name);


/* Get a value of particular form variable.

   Parameters:
     data: pointer to form-uri-encoded buffer. This could be either POST data,
	   or request_info.query_string.
     data_len: length of the encoded data.
     var_name: variable name to decode from the buffer
     dst: destination buffer for the decoded variable
     dst_len: length of the destination buffer

   Return:
     On success, length of the decoded variable.
     On error:
	-1 (variable not found).
	-2 (destination buffer is NULL, zero length or too small to hold the
	    decoded variable).

   Destination buffer is guaranteed to be '\0' - terminated if it is not
   NULL or zero length. */
CIVETWEB_API int mg_get_var(const char *data,
			    size_t data_len,
			    const char *var_name,
			    char *dst,
			    size_t dst_len);


/* Get a value of particular form variable.

   Parameters:
     data: pointer to form-uri-encoded buffer. This could be either POST data,
	   or request_info.query_string.
     data_len: length of the encoded data.
     var_name: variable name to decode from the buffer
     dst: destination buffer for the decoded variable
     dst_len: length of the destination buffer
     occurrence: which occurrence of the variable, 0 is the first, 1 the
		 second...
		this makes it possible to parse a query like
		b=x&a=y&a=z which will have occurrence values b:0, a:0 and a:1

   Return:
     On success, length of the decoded variable.
     On error:
	-1 (variable not found).
	-2 (destination buffer is NULL, zero length or too small to hold the
	    decoded variable).

   Destination buffer is guaranteed to be '\0' - terminated if it is not
   NULL or zero length. */
CIVETWEB_API int mg_get_var2(const char *data,
			     size_t data_len,
			     const char *var_name,
			     char *dst,
			     size_t dst_len,
			     size_t occurrence);


/* Fetch value of certain cookie variable into the destination buffer.

   Destination buffer is guaranteed to be '\0' - terminated. In case of
   failure, dst[0] == '\0'. Note that RFC allows many occurrences of the same
   parameter. This function returns only first occurrence.

   Return:
     On success, value length.
     On error:
	-1 (either "Cookie:" header is not present at all or the requested
	    parameter is not found).
	-2 (destination buffer is NULL, zero length or too small to hold the
	    value). */
CIVETWEB_API int mg_get_cookie(const char *cookie,
			       const char *var_name,
			       char *buf,
			       size_t buf_len);


/* Convenience function -- create detached thread.
   Return: 0 on success, non-0 on error. */
typedef void *(*mg_thread_func_t)(void *);
CIVETWEB_API int mg_start_thread(mg_thread_func_t f, void *p);


/* Get text representation of HTTP status code. */
CIVETWEB_API const char *
mg_get_response_code_text(const struct mg_connection *conn, int response_code);


/* Return CivetWeb version. */
CIVETWEB_API const char *mg_version(void);


/* URL-decode input buffer into destination buffer.
   0-terminate the destination buffer.
   form-url-encoded data differs from URI encoding in a way that it
   uses '+' as character for space, see RFC 1866 section 8.2.1
   http://ftp.ics.uci.edu/pub/ietf/html/rfc1866.txt
   Return: length of the decoded data, or -1 if dst buffer is too small. */
CIVETWEB_API int mg_url_decode(const char *src,
			       int src_len,
			       char *dst,
			       int dst_len,
			       int is_form_url_encoded);


/* URL-encode input buffer into destination buffer.
   returns the length of the resulting buffer or -1
   is the buffer is too small. */
CIVETWEB_API int mg_url_encode(const char *src, char *dst, size_t dst_len);


/* MD5 hash given strings.
   Buffer 'buf' must be 33 bytes long. Varargs is a NULL terminated list of
   ASCIIz strings. When function returns, buf will contain human-readable
   MD5 hash. Example:
     char buf[33];
     mg_md5(buf, "aa", "bb", NULL); */
CIVETWEB_API char *mg_md5(char buf[33], ...);


/* Print error message to the opened error log stream.
   This utilizes the provided logging configuration.
     conn: connection (not used for sending data, but to get perameters)
     fmt: format string without the line return
     ...: variable argument list
   Example:
     mg_cry(conn,"i like %s", "logging"); */
CIVETWEB_API void mg_cry(const struct mg_connection *conn,
			 PRINTF_FORMAT_STRING(const char *fmt),
			 ...) PRINTF_ARGS(2, 3);


/* utility methods to compare two buffers, case insensitive. */
CIVETWEB_API int mg_strcasecmp(const char *s1, const char *s2);
CIVETWEB_API int mg_strncasecmp(const char *s1, const char *s2, size_t len);


enum { TIMEOUT_INFINITE = -1 };


/* Check which features where set when the civetweb library has been compiled.
   The function explicitly addresses compile time defines used when building
   the library - it does not mean, the feature has been initialized using a
   mg_init_library call.
   mg_check_feature can be called anytime, even before mg_init_library has
   been called.

   Parameters:
     feature: specifies which feature should be checked
       The value is a bit mask. The individual bits are defined as:
	 2  support HTTPS (NO_SSL not set)
	 8  support IPv6 (USE_IPV6 set)
	16  support WebSocket (USE_WEBSOCKET set)
       The result is undefined, if bits are set that do not represent a
       defined feature (currently: feature >= 512).
       The result is undefined, if no bit is set (feature == 0).

   Return:
     If feature is available, the corresponding bit is set
     If feature is not available, the bit is 0
*/
CIVETWEB_API unsigned mg_check_feature(unsigned feature);


/* Get information on the system. Useful for support requests.
   Parameters:
     buffer: Store system information as string here.
     buflen: Length of buffer (including a byte required for a terminating 0).
   Return:
     Available size of system information, exluding a terminating 0.
     The information is complete, if the return value is smaller than buflen.
   Note:
     It is possible to determine the required buflen, by first calling this
     function with buffer = NULL and buflen = NULL. The required buflen is
     one byte more than the returned value.
*/
CIVETWEB_API int mg_get_system_info(char *buffer, int buflen);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CIVETWEB_HEADER_INCLUDED */
