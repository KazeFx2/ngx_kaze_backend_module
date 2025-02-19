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

#ifndef _NGX_KAZE_SQL_H_INCLUDED_
#include "ngx_sql.h"
#endif

#include "ngx_k_file.h"

#include "ngx_kaze_string.h"

#define ptr_offset(ptr, opt) (void *)((uintptr_t)ptr + (opt))

#define NGX_K_N_CHAR 38

#define toPort(addr) htons(((struct sockaddr_in *)addr)->sin_port)

#define toIP(addr) inet_ntoa(((struct sockaddr_in *)addr)->sin_addr)

#define ngx_kaze_port(req) toPort(req->connection->listening->sockaddr)

#define ngx_kaze_ip_client(req) toIP(req->connection->sockaddr)

#define ngx_kaze_port_client(req) toPort(req->connection->sockaddr)

#define ngx_http_kaze_char_indx(ch, indx) \
    switch ((ch))                         \
    {                                     \
    case '0':                             \
    case '1':                             \
    case '2':                             \
    case '3':                             \
    case '4':                             \
    case '5':                             \
    case '6':                             \
    case '7':                             \
    case '8':                             \
    case '9':                             \
        (indx) = ((ch) - '0');            \
        break;                            \
    case 'a':                             \
    case 'b':                             \
    case 'c':                             \
    case 'd':                             \
    case 'e':                             \
    case 'f':                             \
    case 'g':                             \
    case 'h':                             \
    case 'i':                             \
    case 'j':                             \
    case 'k':                             \
    case 'l':                             \
    case 'm':                             \
    case 'n':                             \
    case 'o':                             \
    case 'p':                             \
    case 'q':                             \
    case 'r':                             \
    case 's':                             \
    case 't':                             \
    case 'u':                             \
    case 'v':                             \
    case 'w':                             \
    case 'x':                             \
    case 'y':                             \
    case 'z':                             \
        (indx) = ((ch) - 'a' + 10);       \
        break;                            \
    case '.':                             \
        (indx) = 36;                      \
        break;                            \
    default:                              \
        (indx) = -1;                      \
        break;                            \
    }

#define ngx_null_directive                                              \
    {                                                                   \
        ngx_null_string, ngx_null_string, -1, ngx_null_string, -1, NULL \
    }

#define string_is_null(str) (((str)->data == NULL) && ((str)->len == 0))

#define directive_is_null(de) (string_is_null(&(de)->directive) && string_is_null(&(de)->root) && ((de)->range == NGX_HTTP_K_DIRECTIVE_R_NONE) && string_is_null(&(de)->host) && ((de)->type == NGX_HTTP_K_DIRECTIVE_NONE) && ((de)->func == NULL))

#define check_run                                                   \
    for (i = 0; i < array->nelts; i++)                              \
    {                                                               \
        if (ngx_kaze_str_cmp(&directive, &start[i].directive) == 0) \
        {                                                           \
            if (start[i].type == NGX_HTTP_K_DIRECTIVE_FUN)          \
            {                                                       \
                if (start[i].func)                                  \
                {                                                   \
                    rc = start[i].func(kbcf, r);                    \
                    return rc;                                      \
                }                                                   \
                else                                                \
                {                                                   \
                    continue;                                       \
                }                                                   \
            }                                                       \
        }                                                           \
    }

/*解析server块主机名*/
static char *
ngx_http_kaze_backend_srv_conf_post_handler_pt(ngx_conf_t *cf,
                                               void *data, void *conf);
/*解析loc块位置&根目录*/
static char *ngx_http_kaze_backend_loc_conf_post_handler_pt(ngx_conf_t *cf,
                                                            void *data, void *conf);
/*配置读取完成后的初始化*/
static ngx_int_t ngx_http_kaze_backend_init(ngx_conf_t *cf);
/*创建main配置块*/
static void *ngx_http_kaze_backend_create_main_conf(ngx_conf_t *cf);
/*创建server配置块*/
static void *ngx_http_kaze_backend_create_srv_conf(ngx_conf_t *cf);
/*创建location配置块*/
static void *ngx_http_kaze_backend_create_loc_conf(ngx_conf_t *cf);
/*合并main/server配置块*/
char *ngx_http_kaze_backend_merge_srv(ngx_conf_t *cf, void *prev, void *conf);
/*合并server/location配置块*/
char *ngx_http_kaze_backend_merge_loc(ngx_conf_t *cf, void *prev, void *conf);
/*模块初始化*/
static ngx_int_t ngx_http_kaze_backend_init_module(ngx_cycle_t *cycle);
/*进程初始化*/
static ngx_int_t ngx_http_kaze_backend_init_process(ngx_cycle_t *cycle);
/*进程退出*/
static void ngx_http_kaze_backend_exit_process(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_kaze_backend_ip_record(ngx_http_request_t *r);

static ngx_int_t ngx_http_kaze_backend_main(ngx_http_request_t *r);

static ngx_conf_post_t ngx_http_kaze_backend_srv_flag_post = {
    ngx_http_kaze_backend_srv_conf_post_handler_pt};

static ngx_conf_post_t ngx_http_kaze_backend_loc_flag_post = {
    ngx_http_kaze_backend_loc_conf_post_handler_pt};

/*模块配置项*/
static ngx_command_t ngx_http_kaze_backend_cmds[] = {
    /*是否启用模块（全局）*/
    {ngx_string("enable_backend"),                    /*name*/
     NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,              /*type*/
     ngx_conf_set_flag_slot,                          /*set*/
     NGX_HTTP_MAIN_CONF_OFFSET,                       /*conf*/
     offsetof(ngx_http_kaze_backend_conf_t, enabled), /*offset*/
     NULL},                                           /*post*/
    /*是否记录IP（全局）*/
    {ngx_string("ip_record"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_kaze_backend_conf_t, record_ip),
     NULL},
    /*IP记录文件名（全局）*/
    {ngx_string("ip_record_filename"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_kaze_backend_conf_t,
              record_ip_file.filename),
     NULL},
    /*IP数据表*/
    {ngx_string("sql_ip_name"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_kaze_backend_conf_t, db_ip_name),
     NULL},
    /*是否在该服务块启用*/
    {ngx_string("enable_srv"),
     NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_SRV_CONF_OFFSET,
     offsetof(ngx_http_kaze_backend_srv_conf_t, backend_enabled),
     &ngx_http_kaze_backend_srv_flag_post},
    /*是否将该位置块启用为资源路径*/
    {ngx_string("enable_src"),
     NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_kaze_backend_loc_conf_t, src_enabled),
     &ngx_http_kaze_backend_loc_flag_post},
    /*SQL用户名*/
    {ngx_string("sql_username"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_kaze_backend_conf_t, db_usr),
     NULL},
    /*SQL密码*/
    {ngx_string("sql_password"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_kaze_backend_conf_t, db_passwd),
     NULL},
    /*SQL主机地址*/
    {ngx_string("sql_host"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_kaze_backend_conf_t, db_host.hostname),
     NULL},
    /*SQL端口号*/
    {ngx_string("sql_port"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_kaze_backend_conf_t, db_host.port),
     NULL},
    /*SQL数据库名*/
    {ngx_string("sql_db_name"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_kaze_backend_conf_t, db_name),
     NULL},
    /*用户数据表*/
    {ngx_string("sql_usr_name"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_kaze_backend_conf_t, db_usr_name),
     NULL},
    /*资源数据表*/
    {ngx_string("sql_src_name"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_MAIN_CONF_OFFSET,
     offsetof(ngx_http_kaze_backend_conf_t, db_src_name),
     NULL},
    ngx_null_command};

/*自定义指令及处理函数*/
static ngx_http_kaze_backend_directives_t ngx_custom_directives[] = {
    {
        ngx_string("/test"),        /*directive*/
        ngx_null_string,            /*root*/
        NGX_HTTP_K_DIRECTIVE_R_SPE, /*range*/
        ngx_string("localhost"),    /*host*/
        NGX_HTTP_K_DIRECTIVE_FUN,   /*type*/
        NULL                        /*function*/
    },
    ngx_null_directive};

/*模块上下文*/
ngx_http_module_t ngx_http_kaze_backend_ctx = {
    NULL,                       /* preConfiguration */
    ngx_http_kaze_backend_init, /* postConfiguration */

    ngx_http_kaze_backend_create_main_conf, /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_http_kaze_backend_create_srv_conf, /* create server configuration */
    ngx_http_kaze_backend_merge_srv,       /* merge server configuration */

    ngx_http_kaze_backend_create_loc_conf, /* create location configuration */
    ngx_http_kaze_backend_merge_loc        /* merge location configuration */
};

/*模块结构体*/
ngx_module_t ngx_http_kaze_backend = {
    NGX_MODULE_V1,
    &ngx_http_kaze_backend_ctx,         /* module context */
    ngx_http_kaze_backend_cmds,         /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    ngx_http_kaze_backend_init_module,  /* init module */
    ngx_http_kaze_backend_init_process, /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    ngx_http_kaze_backend_exit_process, /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING};

static char *ngx_http_kaze_backend_srv_conf_post_handler_pt(ngx_conf_t *cf,
                                                            void *data, void *conf)
{
    // ngx_http_conf_ctx_t *hcct;
    // ngx_http_core_srv_conf_t *cscf;
    // ngx_http_kaze_backend_srv_conf_t *kbsc = ptr_offset(conf, -offsetof(ngx_http_kaze_backend_srv_conf_t, backend_enabled));
    // if (!kbsc->backend_enabled)
    //     return NGX_CONF_OK;
    // hcct = cf->ctx;
    // cscf = hcct->srv_conf[ngx_http_core_module.ctx_index];
    // ngx_uint_t i;
    // ngx_http_server_name_t *start = cscf->server_names.elts;
    // ngx_str_t *names = ngx_array_push_n(kbsc->server_names, cscf->server_names.nelts);
    // if (start == NULL)
    //     return NGX_CONF_ERROR;
    // for (i = 0; i < cscf->server_names.nelts; i++)
    // {
    //     names[i] = start[i].name;
    //     ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[server_names]%V", &names[i]);
    // }
    return NGX_CONF_OK;
}

static char *ngx_http_kaze_backend_loc_conf_post_handler_pt(ngx_conf_t *cf,
                                                            void *data, void *conf)
{
    ngx_http_conf_ctx_t *hcct;
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_kaze_backend_loc_conf_t *kblc = ptr_offset(conf, -offsetof(ngx_http_kaze_backend_loc_conf_t, src_enabled));
    if (!kblc->src_enabled)
        return NGX_CONF_OK;
    hcct = cf->ctx;
    clcf = hcct->loc_conf[ngx_http_core_module.ctx_index];
    kblc->loc = clcf->name;
    kblc->root = clcf->root;
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[location]loc: %V, root: %V", &kblc->loc, &kblc->root);
    return NGX_CONF_OK;
}

static ngx_http_kaze_backend_host_name_tree_node_t *__ngx_http_host_tree_add(ngx_log_t *log, ngx_pool_t *pool, ngx_http_kaze_backend_host_name_tree_node_t *start, ngx_str_t *host)
{
    ngx_uint_t pos = 0;
    ngx_int_t index = -1;
    u_char tmp = 0;
    while (pos < host->len)
    {
        if (start->next == NULL)
        {
            start->next = ngx_palloc(pool, sizeof(void *) * NGX_K_N_CHAR);
            if (start->next == NULL)
                return NULL;
            ngx_memzero(start->next, sizeof(void *) * NGX_K_N_CHAR);
        }
        tmp = host->data[pos];
        ngx_http_kaze_char_indx(tmp, index);
        if (index == -1)
        {
            if ('A' <= tmp && tmp <= 'Z')
            {
                ngx_log_error(NGX_LOG_EMERG, log, 0, "illegal upper character '%c' in server_name \"%V\", capitalized character is not allowed", tmp, host);
                return NULL;
            }
            else
            {
                ngx_log_error(NGX_LOG_EMERG, log, 0, "illegal character '%c' in server_name \"%V\"", tmp, host);
                return NULL;
            }
        }
        if (start->next[index] == NULL)
        {
            start->next[index] = ngx_palloc(pool, sizeof(ngx_http_kaze_backend_host_name_tree_node_t));
            if (start->next[index] == NULL)
                return NULL;
            ngx_memzero(start->next[index], sizeof(ngx_http_kaze_backend_host_name_tree_node_t));
        }
        start->next[NGX_K_N_CHAR - 1] = (void *)0x1;
        start = start->next[index];
        pos++;
    }
    return start;
}

static ngx_int_t ngx_http_host_check(ngx_log_t *log, ngx_pool_t *pool, ngx_str_t *host)
{
    ngx_str_t *d = host;
    u_char *new = NULL;
    ngx_uint_t pos = 0, i = 0;
    for (; pos < d->len; pos++)
    {
        if ('A' <= d->data[pos] && d->data[pos] <= 'Z')
        {
            if (new == NULL)
            {
                new = ngx_palloc(pool, d->len);
                if (new == NULL)
                    return NGX_ERROR;
                for (; i < pos; i++)
                    new[i] = d->data[i];
            }
            if (new)
                new[pos] = d->data[pos] - 'A' + 'a';
        }
        else if (new)
        {
            new[pos] = d->data[pos];
        }
    }
    if (new)
        d->data = new;
    return NGX_OK;
}

static ngx_int_t ngx_http_directive_check(ngx_log_t *log, ngx_pool_t *pool, ngx_str_t *direct)
{
    ngx_str_t *d = direct;
    u_char *new = NULL;
    ngx_uint_t i = 0;
    if (d->len == 0)
    {
        d->data = ngx_palloc(pool, 1);
        if (d->data == NULL)
            return NGX_ERROR;
        d->data[0] = '/';
        d->len = 1;
    }
    else if (d->data[0] != '/')
    {
        new = ngx_palloc(pool, d->len + 1);
        if (new == NULL)
            return NGX_ERROR;
        new[0] = '/';
        for (; i < d->len; i++)
            new[i + 1] = d->data[i];
        d->data = new;
        d->len++;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_host_tree_add(ngx_log_t *log, ngx_pool_t *pool, ngx_http_kaze_backend_host_name_tree_node_t *start, ngx_str_t *host)
{
    start = __ngx_http_host_tree_add(log, pool, start, host);
    if (start == NULL)
        return NGX_ERROR;
    return NGX_OK;
}

static ngx_array_t *ngx_http_host_tree_find(ngx_log_t *log, ngx_pool_t *pool, ngx_http_kaze_backend_host_name_tree_node_t *start, ngx_str_t *host, ngx_int_t create)
{
    ngx_uint_t pos = 0;
    u_char tmp = 0;
    ngx_int_t index = -1;
    while (pos < host->len)
    {
        if (start == NULL || start->next == NULL)
            return NULL;
        tmp = host->data[pos];
        ngx_http_kaze_char_indx(tmp, index);
        if (index == -1)
            return NULL;
        if (start->next[index] == NULL)
            return NULL;
        start = start->next[index];
        pos++;
    }
    if (create && start->directives == NULL)
    {
        start->directives = ngx_array_create(pool, 5, sizeof(ngx_http_kaze_backend_directives_t));
    }
    return start->directives;
}

static ngx_int_t ngx_http_tree_trav(ngx_http_location_tree_node_t *node, ngx_conf_t *cf, ngx_int_t mi, ngx_http_kaze_backend_srv_conf_t *kbsc, ngx_http_kaze_backend_conf_t *kbcf)
{
    ngx_int_t rc;
    if (node)
    {
        ngx_http_core_loc_conf_t *clcf = node->exact ? node->exact : node->inclusive;
        ngx_http_kaze_backend_loc_conf_t *kblc = clcf->loc_conf[mi];
        if (kblc->src_enabled == 0x1)
        {
            ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[cpi sub loc]name: %V, %p", &clcf->name, kblc);
            ngx_str_t *start = kbsc->server_names->elts;
            ngx_uint_t i = 0;
            ngx_array_t *direc;
            ngx_http_kaze_backend_directives_t *d_s;
            if (kblc->root.len != 0)
            {
                rc = ngx_file_is_dir(cf->log, &kblc->root);
                if (rc != NGX_OK)
                    return NGX_ERROR;
                rc = ngx_file_is_rwx(cf->log, &kblc->root);
                if (rc != NGX_OK)
                    return NGX_ERROR;
            }
            else
            {
                // TODO
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "no root was specified in location block while \"enable_src\" is \"on\"");
                return NGX_ERROR;
            }
            for (; i < kbsc->server_names->nelts; i++)
            {
                direc = ngx_http_host_tree_find(cf->log, cf->pool, &kbcf->hosts, &start[i], 1);
                ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[tree tarv]%p", direc);
                d_s = ngx_array_push(direc);
                if (d_s == NULL)
                    return NGX_ERROR;
                d_s->directive = kblc->loc;
                d_s->root = kblc->root;
                d_s->func = NULL;
                d_s->host = start[i];
                d_s->range = NGX_HTTP_K_DIRECTIVE_R_SPE;
                d_s->type = NGX_HTTP_K_DIRECTIVE_SRC;
            }
        }
        if (ngx_http_tree_trav(node->left, cf, mi, kbsc, kbcf) != NGX_OK)
            return NGX_ERROR;
        if (ngx_http_tree_trav(node->right, cf, mi, kbsc, kbcf) != NGX_OK)
            return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_host_tree_add_insert(ngx_conf_t *cf, ngx_http_kaze_backend_host_name_tree_node_t *start, ngx_http_kaze_backend_directives_t *direct)
{
    if (ngx_http_host_check(cf->log, cf->pool, &direct->host) != NGX_OK)
        return NGX_ERROR;
    if (ngx_http_directive_check(cf->log, cf->pool, &direct->directive) != NGX_OK)
        return NGX_ERROR;
    start = __ngx_http_host_tree_add(cf->log, cf->pool, start, &direct->host);
    if (start == NULL)
        return NGX_ERROR;
    if (start->directives == NULL)
    {
        start->directives = ngx_array_create(cf->pool, 5, sizeof(ngx_http_kaze_backend_directives_t));
    }
    ngx_http_kaze_backend_directives_t *elt = ngx_array_push(start->directives);
    if (elt == NULL)
        return NGX_ERROR;
    *elt = *direct;
    return NGX_OK;
}

static ngx_int_t ngx_http_kaze_backend_init(ngx_conf_t *cf)
{
    ngx_http_conf_ctx_t *nhct = cf->ctx;
    ngx_http_core_main_conf_t *cmcf = nhct->main_conf[ngx_http_core_module.ctx_index];
    ngx_array_t srv_array = cmcf->servers;
    ngx_http_core_srv_conf_t **start = srv_array.elts, *tmp_cscf;
    ngx_http_core_loc_conf_t *clcf;
    ngx_uint_t i, j, mi = ngx_http_kaze_backend.ctx_index;
    ngx_int_t rc;
    ngx_http_kaze_backend_conf_t *kbcf = nhct->main_conf[mi];
    ngx_http_handler_pt *h;
    if (kbcf->enabled != 0x1)
    {
        return NGX_OK;
    }
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[configure post init]");
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[configure post init]main: %p, main_srv: %p, main_loc: %p", nhct->main_conf[mi], nhct->srv_conf[mi], nhct->loc_conf[mi]);
    for (i = 0; i < srv_array.nelts; i++)
    {
        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[configure post init]srv_pos: %d", i);
        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[cpi srv pointer]%p", start[i]->ctx->srv_conf[mi]);
        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[cpi loc pointer]%p", start[i]->ctx->loc_conf[mi]);
        clcf = start[i]->ctx->loc_conf[ngx_http_core_module.ctx_index];
        ngx_http_kaze_backend_srv_conf_t *kbsc = start[i]->ctx->srv_conf[mi];
        if (kbsc->backend_enabled != 0x1)
        {
            continue;
        }
        tmp_cscf = start[i]->ctx->srv_conf[ngx_http_core_module.ctx_index];
        kbcf->srv_counter += 1;
        ngx_http_server_name_t *names_start = tmp_cscf->server_names.elts;
        ngx_str_t *sc_names_start = kbsc->server_names->elts;
        if (ngx_array_push_n(kbsc->server_names, tmp_cscf->server_names.nelts) == NULL)
            return NGX_ERROR;
        for (j = 0; j < tmp_cscf->server_names.nelts; j++)
        {
            ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "%V", &names_start[j].name);
            sc_names_start[j] = names_start[j].name;
            rc = ngx_http_host_tree_add(cf->log, cf->pool, &kbcf->hosts, &names_start[j].name);
            if (rc != NGX_OK)
                return NGX_ERROR;
        }
        ngx_http_location_tree_node_t *node = clcf->static_locations;
        rc = ngx_http_tree_trav(node, cf, mi, kbsc, kbcf);
        if (rc != NGX_OK)
            return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[configure post init end]");
    if (kbcf->srv_counter == 0)
    {
        kbcf->enabled = 0x0;
        return NGX_OK;
    }
    for (i = 0;; i++)
    {
        if (directive_is_null(&ngx_custom_directives[i]))
            break;
        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[directives]");
        if (ngx_custom_directives[i].range == NGX_HTTP_K_DIRECTIVE_R_SPE)
        {
            rc = ngx_http_host_tree_add_insert(cf, &kbcf->hosts, &ngx_custom_directives[i]);
            if (rc != NGX_OK)
                return NGX_ERROR;
        }
        else
        {
            ngx_http_kaze_backend_directives_t *elt = ngx_array_push(kbcf->directives);
            if (elt == NULL)
                return NGX_ERROR;
            *elt = ngx_custom_directives[i];
        }
    }
    if (kbcf->db_host.port == NGX_CONF_UNSET)
        kbcf->db_host.port = 3306;
    rc = ngx_sql_configure_check(cf->log, kbcf, &kbcf->sql);
    if (rc != NGX_OK)
        return NGX_ERROR;
    rc = ngx_sql_tables_check(cf->log, kbcf->sql, kbcf);
    if (rc != NGX_OK)
        return NGX_ERROR;
    if (kbcf->record_ip == 0x1 && kbcf->record_ip_file.filename.len > 0)
    {
        rc = ngx_file_create_or_add(cf->log, &kbcf->record_ip_file.filename, &kbcf->record_ip_file.fd);
        if (rc != NGX_OK)
            return NGX_ERROR;

        h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
        if (h == NULL)
        {
            return NGX_ERROR;
        }
        *h = ngx_http_kaze_backend_ip_record;
        // TODO
    }
    else
    {
        kbcf->record_ip = 0x0;
    }

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }
    *h = ngx_http_kaze_backend_main;
    return NGX_OK;
}

static void *
ngx_http_kaze_backend_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_kaze_backend_conf_t *kbcf = ngx_palloc(cf->pool, sizeof(ngx_http_kaze_backend_conf_t));
    if (kbcf == NULL)
        return NULL;
    ngx_memzero(kbcf, sizeof(ngx_http_kaze_backend_conf_t));
    kbcf->directives = ngx_array_create(cf->pool, 5, sizeof(ngx_http_kaze_backend_directives_t));
    if (kbcf->directives == NULL)
    {
        ngx_pfree(cf->pool, kbcf);
        return NULL;
    }
    kbcf->db_host.port = NGX_CONF_UNSET;
    kbcf->enabled = NGX_CONF_UNSET;
    kbcf->record_ip = NGX_CONF_UNSET;
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[create main]pointer: %p", kbcf);
    return kbcf;
}

static void *ngx_http_kaze_backend_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_kaze_backend_srv_conf_t *kbsc = ngx_palloc(cf->pool, sizeof(ngx_http_kaze_backend_srv_conf_t));
    if (kbsc == NULL)
        return NULL;
    ngx_memzero(kbsc, sizeof(ngx_http_kaze_backend_srv_conf_t));
    kbsc->server_names = ngx_array_create(cf->pool, 5, sizeof(ngx_str_t));
    kbsc->backend_enabled = NGX_CONF_UNSET;
    if (kbsc->server_names == NULL)
    {
        ngx_pfree(cf->pool, kbsc);
        return NULL;
    }
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[create srv]pointer: %p", kbsc);
    return kbsc;
}

static void *ngx_http_kaze_backend_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_kaze_backend_loc_conf_t *kblc = ngx_palloc(cf->pool, sizeof(ngx_http_kaze_backend_loc_conf_t));
    if (kblc == NULL)
        return NULL;
    ngx_memzero(kblc, sizeof(ngx_http_kaze_backend_loc_conf_t));
    kblc->src_enabled = NGX_CONF_UNSET;
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[create loc]pointer: %p", kblc);
    return kblc;
}

char *ngx_http_kaze_backend_merge_srv(ngx_conf_t *cf, void *prev, void *conf)
{
    ngx_http_kaze_backend_conf_t *kbcf = ngx_http_get_module_main_conf(((ngx_http_conf_ctx_t *)cf->ctx), ngx_http_kaze_backend);
    ngx_http_kaze_backend_srv_conf_t *kbsc = conf;
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[emerg srv]prev: %p, conf: %p", kbcf, kbsc);
    if (!kbcf->enabled)
        kbsc->backend_enabled = 0x0;
    else if (kbsc->backend_enabled)
        kbcf->srv_counter++;
    return NGX_CONF_OK;
}

char *ngx_http_kaze_backend_merge_loc(ngx_conf_t *cf, void *prev, void *conf)
{
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_kaze_backend_init_module(ngx_cycle_t *cycle)
{
    return NGX_OK;
}

static ngx_int_t ngx_http_kaze_backend_init_process(ngx_cycle_t *cycle)
{
    return NGX_OK;
}

static void ngx_http_kaze_backend_exit_process(ngx_cycle_t *cycle)
{
}

/*
ip                  v
host              v
uri                 v
time              v
method        v
parm            v
heads           v
result            v
*/
static ngx_int_t ngx_http_kaze_backend_ip_record(ngx_http_request_t *r)
{
    // TODO
    ngx_str_t uri = ngx_kaze_heads_uri(r),
              host = ngx_kaze_heads_host(r),
              heads = ngx_kaze_heads_all(r);
    time_t t = ngx_time();
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "IP: %s, Port: %d, Host: %V, URI: %V, Method: %V, Time: %l, Parm: %V, Heads: %V, Result: %d\n", ngx_kaze_ip_client(r), ngx_kaze_port_client(r), &host, &uri, &r->method_name, t, &r->args, &heads, r->headers_out.status);
    return NGX_DECLINED;
}

static ngx_int_t ngx_http_kaze_backend_main(ngx_http_request_t *r)
{
    ngx_http_kaze_backend_conf_t *kbcf = ngx_http_get_module_main_conf(r, ngx_http_kaze_backend);
    ngx_str_t host = ngx_kaze_heads_host(r),
              uri = ngx_kaze_heads_uri(r),
              end = ngx_string("/"), directive;
    size_t len = ngx_kaze_str_find_str_start(&uri, &end, 1);
    len = len == uri.len ? len : len + 1;
    directive.data = uri.data;
    directive.len = len;
    ngx_array_t *array = kbcf->directives;
    ngx_http_kaze_backend_directives_t *start = array->elts;
    ngx_uint_t i;
    ngx_int_t rc;
    check_run;
    ngx_array_t *array = ngx_http_host_tree_find(r->connection->log, r->connection->pool, &kbcf->hosts, &host, 0);
    if (array == NULL)
        return NGX_DECLINED;
    ngx_http_kaze_backend_directives_t *start = array->elts;
    check_run;
    return NGX_DECLINED;
}