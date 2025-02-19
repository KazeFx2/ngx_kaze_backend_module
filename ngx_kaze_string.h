#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stddef.h>
#include <sys/types.h>
#include <stdarg.h>
#include <netinet/in.h>

#pragma once
typedef enum
{
    NGX_K_CONTENT_JSON = 0,
    NGX_K_CONTENT_TXT
} ngx_kaze_content_type;

typedef struct
{
    ngx_str_t key;
    ngx_str_t val;
    time_t max_age;
    ngx_uint_t secure : 1;
    ngx_uint_t http_only : 1;
    ngx_str_t domain;
    ngx_str_t path;
} ngx_kaze_cookie_s, ngx_kaze_cookie_t;

#define NGX_K_COOKIE_PADDING 0, 0, 0, ngx_null_string, ngx_null_string

#define toPort(addr) htons(((struct sockaddr_in *)addr)->sin_port)

#define toIP(addr) inet_ntoa(((struct sockaddr_in *)addr)->sin_addr)

#define ngx_kaze_port(req) toPort(req->connection->listening->sockaddr)

#define ngx_kaze_ip_client(req) toIP(req->connection->sockaddr)

#define ngx_kaze_port_client(req) toPort(req->connection->sockaddr)

/*returns the length of str if find failed*/
size_t ngx_kaze_str_find(ngx_str_t *str, u_char a);

size_t ngx_kaze_str_rfind(ngx_str_t *str, u_char a);

size_t ngx_kaze_str_rfind_start(ngx_str_t *str, u_char a, size_t start);

ngx_str_t ngx_kaze_str_cat(ngx_pool_t *pool, ngx_str_t *a, ngx_str_t *b);

ngx_str_t ngx_kaze_str_ncat(ngx_pool_t *pool, ngx_uint_t n, ...);

ngx_str_t ngx_kaze_str_n_arycat(ngx_pool_t *pool, ngx_uint_t n, ngx_str_t *str_ary);

ngx_int_t ngx_kaze_str_cmp(ngx_str_t *a, ngx_str_t *b);

ngx_int_t ngx_kaze_str_cmp_chr(ngx_str_t *a, char *b);

ngx_int_t ngx_kaze_set_content_type(ngx_http_request_t *r, ngx_kaze_content_type ty);

ngx_int_t ngx_kaze_set_content_type(ngx_http_request_t *r, ngx_kaze_content_type ty);

ngx_int_t ngx_kaze_heads_add(ngx_http_request_t *r, const u_char *key, const u_char *val);

ngx_int_t ngx_kaze_heads_str_add(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *val);

ngx_str_t ngx_kaze_itoa(ngx_pool_t *pool, ngx_int_t val);

ngx_int_t ngx_kaze_heads_add_cookie(ngx_http_request_t *r, ngx_kaze_cookie_t *cookie);

ngx_list_t *ngx_kaze_heads_in_parser_cookie(ngx_http_request_t *r);

ngx_int_t ngx_kaze_heads_add_ncookie(ngx_http_request_t *r, size_t n, ngx_kaze_cookie_t *cookie);

ngx_str_t ngx_kaze_str_lowcase(ngx_pool_t *pool, ngx_str_t *str);

ngx_list_t *ngx_kaze_heads_in_parser_args(ngx_http_request_t *r);

ngx_str_t ngx_kaze_str_url_decode(ngx_pool_t *pool, ngx_str_t *in);

ngx_str_t ngx_kaze_list_find_key(ngx_list_t *list, ngx_str_t *key);

ngx_str_t ngx_kaze_list_find_key_chr(ngx_list_t *list, char *key);

ngx_str_t ngx_kaze_heads_host(ngx_http_request_t *r);

static inline ngx_str_t ngx_kaze_heads_uri(ngx_http_request_t *r)
{
    return r->uri;
}

ngx_str_t ngx_kaze_heads_url(ngx_http_request_t *r);

ngx_int_t ngx_kaze_out_str(ngx_http_request_t *r, ngx_chain_t *out, ngx_str_t *str);

u_char *ngx_kaze_stoc(ngx_pool_t *pool, ngx_str_t *str);

ngx_str_t ngx_kaze_ctos(ngx_pool_t *pool, const u_char *str);

ngx_str_t ngx_kaze_find_replace(ngx_pool_t *pool, ngx_str_t *str, char a, char b, ngx_uint_t end);

ngx_int_t ngx_kaze_rand_str(size_t length, char *buf, ngx_uint_t end);

ngx_str_t ngx_str_set_fmt(ngx_pool_t *pool, size_t max_buf, const char *fmt, ...);

size_t ngx_kaze_str_find_str_start(ngx_str_t *src, ngx_str_t *tar, size_t start);

size_t ngx_kaze_str_rfind_str_start(ngx_str_t *src, ngx_str_t *tar, size_t start);

ngx_str_t ngx_kaze_heads_all(ngx_http_request_t *r);