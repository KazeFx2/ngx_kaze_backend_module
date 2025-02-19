#ifndef _NGX_KAZE_FILE_H_INCLUDED_
#define _NGX_KAZE_FILE_H_INCLUDED_

#ifndef _NGX_HTTP_H_INCLUDED_
#include <ngx_http.h>
#endif

#ifndef _NGX_CORE_H_INCLUDED_
#include <ngx_core.h>
#endif

#ifndef _NGX_CONFIG_H_INCLUDED_
#include <ngx_config.h>
#endif

#ifndef _NGX_CONF_FILE_H_INCLUDED_
#include <ngx_conf_file.h>
#endif

#include "ngx_k_string.h"

ngx_int_t ngx_file_is_dir(ngx_log_t *log, ngx_str_t *path);

ngx_int_t ngx_file_is_rwx(ngx_log_t *log, ngx_str_t *path);

ngx_int_t ngx_file_is_exist(ngx_log_t *log, ngx_str_t *path);

ngx_int_t ngx_file_create_or_add(ngx_log_t *log, ngx_str_t *path, FILE **fd);
#endif