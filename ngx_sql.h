#ifndef _NGX_KAZE_SQL_H_INCLUDED_
#define _NGX_KAZE_SQL_H_INCLUDED_

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

#ifndef _NGX_KAZE_BK_H_INCLUDED_
#include "ngx_kaze_bk.h"
#endif

ngx_int_t ngx_sql_configure_check(ngx_log_t *log, ngx_http_kaze_backend_conf_t *kbcf, MYSQL **mysql);

ngx_int_t ngx_sql_tables_check(ngx_log_t *log, MYSQL *mysql, ngx_http_kaze_backend_conf_t *kbcf);

#endif