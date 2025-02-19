#include "ngx_kaze_sql.h"
#include <time.h>

extern ngx_module_t ngx_http_kaze_backend;

typedef struct
{
    ngx_str_t *sql_usrname;
    ngx_str_t *sql_passwd;
    ngx_str_t *sql_host;
    ngx_str_t *sql_port;
    ngx_str_t *sql_db_name;
    ngx_str_t *sql_usr_table;
    ngx_str_t *sql_usr_au_table;
    ngx_list_t *sql_src_names;
    ngx_list_t *server_names_main;
    ngx_list_t *server_names;
    MYSQL *sql;
} ngx_http_kaze_backend_conf_t;

typedef struct
{
    ngx_str_t real_loc;
    ngx_str_t url_loc;
    ngx_str_t table_name;
} ngx_http_kaze_backend_src_name_t;

typedef struct
{
    ngx_str_t cmd;
    ngx_int_t (*func)(ngx_http_kaze_backend_conf_t *aacf, ngx_http_request_t *r, ngx_chain_t *out);
} ngx_http_kaze_backend_cmd_t;

#define ngx_http_kaze_null_cmd \
    {                          \
        ngx_null_string,       \
            NULL               \
    }

static char *
ngx_http_kaze_backend_conf_parser(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_kaze_backend_create_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_kaze_backend_init(ngx_conf_t *cf);
static ngx_uint_t ngx_http_kaze_backend_find_url(ngx_http_kaze_backend_conf_t *aacf, ngx_str_t host, ngx_str_t url);
static ngx_int_t ngx_http_kaze_backend_init_process(ngx_cycle_t *cycle);
static void ngx_http_kaze_backend_exit_process(ngx_cycle_t *cycle);
static char *ngx_http_kaze_backend_arg_fill(ngx_pool_t *pool, ngx_str_t *cmd_args, ngx_str_t **tar);
static ngx_int_t ngx_http_kaze_backend_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_kaze_backend_acc_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_kaze_backend_init_module(ngx_cycle_t *cycle);
static ngx_uint_t ngx_http_kaze_backend_acc_find_url(ngx_http_kaze_backend_conf_t *aacf, ngx_str_t url, ngx_str_t *tb_name);
static ngx_uint_t ngx_http_kaze_backend_get_permission(ngx_http_request_t *r, ngx_http_kaze_backend_conf_t *aacf);
static ngx_int_t ngx_kaze_login(ngx_http_kaze_backend_conf_t *aacf, ngx_http_request_t *r, ngx_chain_t *out);
static ngx_int_t ngx_kaze_upload(ngx_http_kaze_backend_conf_t *aacf, ngx_http_request_t *r, ngx_chain_t *out);
static ngx_int_t ngx_kaze_test(ngx_http_kaze_backend_conf_t *aacf, ngx_http_request_t *r, ngx_chain_t *out);
static ngx_int_t ngx_http_kaze_backend_get_file_permission(ngx_http_kaze_backend_conf_t *aacf, ngx_str_t *tb_n, ngx_str_t *uri, ngx_uint_t *r, ngx_uint_t *w, ngx_uint_t *x, ngx_uint_t *reserve);

static ngx_command_t ngx_http_kaze_backend_cmds[] = {
    {ngx_string("sql_username"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_http_kaze_backend_conf_parser,
     NGX_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},
    {ngx_string("sql_password"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_http_kaze_backend_conf_parser,
     NGX_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},
    {ngx_string("sql_host"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_http_kaze_backend_conf_parser,
     NGX_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},
    {ngx_string("sql_port"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_http_kaze_backend_conf_parser,
     NGX_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},
    {ngx_string("sql_db_name"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_http_kaze_backend_conf_parser,
     NGX_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},
    {ngx_string("sql_user_table"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
     ngx_http_kaze_backend_conf_parser,
     NGX_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},
    {ngx_string("sql_src"),
     NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
     ngx_http_kaze_backend_conf_parser,
     NGX_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},
    {ngx_string("backend_server_name"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
     ngx_http_kaze_backend_conf_parser,
     NGX_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},
    ngx_null_command};

static ngx_http_module_t ngx_http_kaze_backend_ctx = {
    NULL,                       /* preConfiguration */
    ngx_http_kaze_backend_init, /* postConfiguration */

    ngx_http_kaze_backend_create_conf, /* create main configuration */
    NULL,                              /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

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

static ngx_http_kaze_backend_cmd_t ngx_http_kaze_backend_k_cmds[] = {
    {ngx_string("/login"),
     ngx_kaze_login},
    {ngx_string("/src/get"),
     ngx_kaze_test},
    {ngx_string("/file"),
     ngx_kaze_upload},
    ngx_http_kaze_null_cmd};

static ngx_int_t
ngx_kaze_login(ngx_http_kaze_backend_conf_t *aacf, ngx_http_request_t *r, ngx_chain_t *out)
{
    ngx_list_t *args = ngx_kaze_heads_in_parser_args(r);
    if (args == NULL)
        return NGX_ERROR;

    ngx_str_t tmp = ngx_kaze_list_find_key_chr(args, "user");
    ngx_str_t tmp_passwd = ngx_kaze_list_find_key_chr(args, "passwd");
    char passwd[21];
    uint permission, uid;

    ngx_str_t res_json;
    ngx_int_t rc;
    if (tmp.len == 0 || ngx_kaze_sql_passwd_permit_uid_chr(aacf->sql, (char *)aacf->sql_usr_table->data, &tmp, passwd, &permission, &uid, 0) == NGX_NONE)
    {
        ngx_str_set(&res_json, "{status: 'error', info: 'no user'}");
    }
    else
    {
        if (ngx_kaze_str_cmp_chr(&tmp_passwd, passwd) == 0)
        {
            res_json = ngx_str_set_fmt(r->pool, 100, "{status: 'ok', permission_level: %d, uid: %d}", permission, uid);
        }
        else
        {
            ngx_str_set(&res_json, "{status: 'error', info: 'wrong password'}");
        }
    }
    char *au = ngx_palloc(r->pool, 129);
    long int t = time(NULL);
    uint32_t addr = ((struct sockaddr_in *)r->connection->sockaddr)->sin_addr.s_addr;
    while (1)
    {
        ngx_kaze_rand_str(128, au, 1);
        rc = ngx_kaze_sql_qurey_key_val_exist(aacf->sql, (char *)aacf->sql_usr_au_table->data, "authority", au);
        if (rc == NGX_ERROR)
            return NGX_ERROR;
        if (rc == NGX_NONE)
        {
            char uid_s[10];
            sprintf(uid_s, "%d", uid);
            rc = ngx_kaze_sql_qurey_key_val_exist(aacf->sql, (char *)aacf->sql_usr_au_table->data, "uid", uid_s);
            if (rc == NGX_ERROR)
                return rc;
            if (rc == NGX_NONE)
            {
                rc = sql_kaze_add_row_str(aacf->sql, (char *)aacf->sql_usr_au_table->data, "%d, '%ts', %ld, %d",
                                          "uid", "authority", "time", "ip",
                                          uid, au, t, addr);
            }
            else
            {
                rc = sql_kaze_execute_fmt(aacf->sql, "update %s set authority='%ts', time=%ld, ip=%d where uid=%d", aacf->sql_usr_au_table->data, au, t, addr, uid);
            }
            if (rc == SQL_K_ERROR)
                return NGX_ERROR;
            break;
        }
    }

    ngx_kaze_cookie_t cookie = {
        ngx_string("authority"),
        {128, (u_char *)au},
        0,
        1,
        1,
        ngx_null_string,
        ngx_null_string};

    rc = ngx_kaze_heads_add_cookie(r, &cookie);
    if (rc != NGX_OK)
        return rc;

    if (ngx_kaze_set_content_type(r, NGX_K_CONTENT_JSON) != NGX_OK)
        return NGX_ERROR;

    if (ngx_kaze_out_str(r, out, &res_json) == NGX_ERROR)
        return NGX_ERROR;

    r->headers_out.status = NGX_HTTP_OK;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
        return rc;

    if ((rc = ngx_http_discard_request_body(r)) != NGX_OK)
        return rc;
    return NGX_OK;
}

static void ngx_http_kaze_backend_body_handler(ngx_http_request_t *r)
{
    ngx_int_t rc = NGX_HTTP_OK;
    // ngx_http_kaze_backend_conf_t *aacf = ngx_http_get_module_ctx(r, ngx_http_kaze_backend);
    size_t n;
    ngx_str_t content_type = ngx_kaze_list_find_key_chr(&r->headers_in.headers, "Content-Type");
    ngx_str_t boundary = {content_type.len - ngx_kaze_str_rfind(&content_type, '=') - 1, content_type.data + ngx_kaze_str_rfind(&content_type, '=') + 1};
    r->read_event_handler = ngx_http_kaze_backend_body_handler;
    u_char *buffer = ngx_palloc(r->pool, r->headers_in.content_length_n);
    ngx_array_t *data_array = ngx_array_create(r->pool, 5, sizeof(ngx_table_elt_t));
    if (buffer == NULL || data_array == NULL)
    {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto end;
    }
    size_t pos = 0, i = 0, j = 0;
    for (;;)
    {
        ngx_chain_t tmp = *(r->request_body->bufs);
        while (1)
        {
            n = tmp.buf->last - tmp.buf->pos;
            ngx_memcpy(&buffer[pos], tmp.buf->pos, n);
            pos += n;
            tmp.buf->pos += n;
            if (!tmp.next)
                break;
            tmp = *(tmp.next);
        }
        r->request_body->bufs = NULL;
        if (!r->reading_body)
            break;
        rc = ngx_http_read_unbuffered_request_body(r);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
            goto end;
        if (r->request_body->bufs == NULL)
            break;
    }
    ngx_str_t data = {pos, buffer};
    ngx_str_t name_ = ngx_string("name=\"");
    ngx_str_t last_name = ngx_null_string;
    size_t begin = ngx_kaze_str_find_str_start(&data, &boundary, 0);
    pos = ngx_kaze_str_find_str_start(&data, &name_, begin + boundary.len) + name_.len;
    size_t end = ngx_kaze_str_find_str_start(&data, &boundary, pos);
    size_t array_pos = 0;
    while (end != data.len)
    {
        ngx_str_t name = {end - pos, &data.data[pos]};
        name.len = ngx_kaze_str_rfind(&name, '"');
        u_char *tmp = name.data + name.len + 1;
        size_t len = end - pos - name.len - 1;
        while (*tmp == ' ' || *tmp == 0x0d || *tmp == 0x0a)
        {
            tmp++, len--;
        }
        ngx_str_t value = {len, tmp};
        value.len = ngx_kaze_str_rfind(&value, 0x0d);
        ngx_str_t blk_name = name;
        blk_name.len = ngx_kaze_str_rfind(&blk_name, '_');
        ngx_str_t item_name = {name.len - blk_name.len - 1,
                               &blk_name.data[blk_name.len + 1]};
        if (name.len == blk_name.len)
            item_name.len = 0, item_name.data = NULL;
        ngx_table_elt_t *
            tb;
        if (ngx_kaze_str_cmp_chr(&blk_name, "submit") == 0)
        {
            tb = ngx_array_push(data_array);
            tb->key = blk_name;
            tb->value = value;
        }
        else if (last_name.len == 0 && last_name.data == NULL)
        {
            tb = ngx_array_push(data_array);
            tb->key = blk_name;
            tb->value.len = 0;
            tb->value.data = (u_char *)ngx_array_create(r->pool, 5, sizeof(ngx_table_elt_t));
            ngx_table_elt_t *add = ngx_array_push((ngx_array_t *)tb->value.data);
            add->key = item_name;
            add->value = value;
            last_name = blk_name;
        }
        else if (ngx_kaze_str_cmp(&last_name, &blk_name) == 0)
        {
            ngx_table_elt_t *add = ngx_array_push((ngx_array_t *)((ngx_table_elt_t *)data_array->elts)[array_pos].value.data);
            add->key = item_name;
            add->value = value;
        }
        else
        {
            tb = ngx_array_push(data_array);
            tb->key = blk_name;
            tb->value.len = 0;
            tb->value.data = (u_char *)ngx_array_create(r->pool, 5, sizeof(ngx_table_elt_t));
            ngx_table_elt_t *add = ngx_array_push((ngx_array_t *)tb->value.data);
            add->key = item_name;
            add->value = value;
            last_name = blk_name;
            array_pos++;
        }
        begin = end;
        pos = ngx_kaze_str_find_str_start(&data, &name_, begin + boundary.len) + name_.len;
        end = ngx_kaze_str_find_str_start(&data, &boundary, pos);
    }
    ngx_table_elt_t *ary_s = data_array->elts;
    for (i = 0; i < data_array->nelts; i++)
    {
        if (ngx_kaze_str_cmp_chr(&ary_s[i].key, "submit") == 0)
        {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "[SUBMIT]\nVAL: %V\n", &ary_s[i].value);
        }
        else
        {
            ngx_array_t *el_a = (ngx_array_t *)ary_s[i].value.data;
            ngx_table_elt_t *el_s = el_a->elts;
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "[%V]\n", &ary_s[i].key);
            for (j = 0; j < el_a->nelts; j++)
            {
                ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "KEY: %V, VAL: %V\n", &el_s[j].key, &el_s[j].value);
            }
        }
    }

end:
    ngx_http_finalize_request(r, rc);
}

static ngx_int_t
ngx_kaze_upload(ngx_http_kaze_backend_conf_t *aacf, ngx_http_request_t *r, ngx_chain_t *out)
{
    if (r->method == NGX_HTTP_POST)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "Get POST\n");
    }
    else
        return NGX_HTTP_NOT_ALLOWED;

    ngx_list_t *cookies = ngx_kaze_heads_in_parser_cookie(r);
    if (cookies == NULL)
        return NGX_ERROR;

    ngx_list_t *args = ngx_kaze_heads_in_parser_args(r);
    if (args == NULL)
        return NGX_ERROR;

    ngx_http_read_client_request_body(r, ngx_http_kaze_backend_body_handler);

    return NGX_DONE;
}

static ngx_int_t
ngx_kaze_test(ngx_http_kaze_backend_conf_t *aacf, ngx_http_request_t *r, ngx_chain_t *out)
{
    ngx_list_t *cookies = ngx_kaze_heads_in_parser_cookie(r);
    if (cookies == NULL)
        return NGX_ERROR;

    ngx_list_t *args = ngx_kaze_heads_in_parser_args(r);
    if (args == NULL)
        return NGX_ERROR;

    ngx_str_t tmp = ngx_kaze_list_find_key_chr(args, "user");
    ngx_str_t tmp_passwd = ngx_kaze_list_find_key_chr(args, "passwd");
    ngx_str_t passwd;

    ngx_str_t res_json;
    ngx_int_t rc;

    ngx_uint_t i = 0;
    ngx_list_part_t *start = &args->part;
    while (1)
    {
        ngx_table_elt_t *tmp = start->elts;
        for (i = 0; i < start->nelts; i++)
        {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "Key: %V, Val: %V\n", &tmp[i].key, &tmp[i].value);
        }
        if (!(start->next))
            break;
        else
            start = start->next;
    }

    if (tmp.len == 0 || ngx_kaze_sql_passwd(aacf->sql, r->pool, (char *)aacf->sql_usr_table->data, &tmp, &passwd, 0) == NGX_NONE)
    {
        ngx_str_set(&res_json, "No user");
    }
    else
    {
        if (ngx_kaze_str_cmp(&tmp_passwd, &passwd) == 0)
        {
            ngx_str_set(&res_json, "OK");
        }
        else
        {
            ngx_str_set(&res_json, "Wrong passwd");
        }
    }

    if (ngx_kaze_set_content_type(r, NGX_K_CONTENT_TXT) != NGX_OK)
        return NGX_ERROR;

    if (ngx_kaze_out_str(r, out, &res_json) == NGX_ERROR)
        return NGX_ERROR;

    r->headers_out.status = NGX_HTTP_OK;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
        return rc;

    if ((rc = ngx_http_discard_request_body(r)) != NGX_OK)
        return rc;
    return NGX_OK;
}

static ngx_uint_t
ngx_http_kaze_backend_find_url(ngx_http_kaze_backend_conf_t *aacf, ngx_str_t host, ngx_str_t url)
{
    ngx_uint_t match = 0, i = 0;
    ngx_list_part_t *start = &aacf->server_names_main->part;
    while (1)
    {
        ngx_str_t *tmp = start->elts;
        for (i = 0; i < start->nelts; i++)
        {
            if (ngx_kaze_str_cmp(&host, &tmp[i]) == 0)
            {
                match = 1;
                break;
            }
        }
        if (match || !(start->next))
            break;
        else
            start = start->next;
    }
    if (!match)
    {
        start = &aacf->server_names->part;
        while (1)
        {
            ngx_str_t *tmp = start->elts;
            for (i = 0; i < start->nelts; i++)
            {
                if (ngx_kaze_str_cmp(&url, &tmp[i]) == 0)
                {
                    match = 1;
                    break;
                }
            }
            if (match || !(start->next))
                break;
            else
                start = start->next;
        }
    }
    return match;
}

static ngx_uint_t
ngx_http_kaze_backend_acc_find_url(ngx_http_kaze_backend_conf_t *aacf, ngx_str_t url, ngx_str_t *tb_name)
{
    ngx_uint_t match = 0, i = 0;
    ngx_str_t url_ = url;
    url_.len = 0;
    while (url_.len != url.len && i != 2)
    {
        if (url_.data[url_.len] == '/')
            i++;
        url_.len++;
    }
    if (i == 2)
        url_.len--;
    ngx_list_part_t *start = &aacf->sql_src_names->part;
    while (1)
    {
        ngx_http_kaze_backend_src_name_t *tmp = start->elts;
        for (i = 0; i < start->nelts; i++)
        {
            if (ngx_kaze_str_cmp(&url_, &tmp[i].url_loc) == 0)
            {
                *tb_name = tmp[i].table_name;
                match = 1;
                break;
            }
        }
        if (match || !(start->next))
            break;
        else
            start = start->next;
    }
    return match;
}

static void *
ngx_http_kaze_backend_create_conf(ngx_conf_t *cf)
{
    ngx_http_kaze_backend_conf_t *kbcf = ngx_palloc(cf->pool, sizeof(ngx_http_kaze_backend_conf_t));
    if (!kbcf)
        return NULL;
    ngx_memzero(kbcf, sizeof(ngx_http_kaze_backend_conf_t));
    kbcf->server_names_main = ngx_list_create(cf->pool, 5, sizeof(ngx_str_t));
    if (kbcf->server_names_main == NULL)
        return NULL;
    kbcf->server_names = ngx_list_create(cf->pool, 5, sizeof(ngx_str_t));
    if (kbcf->server_names == NULL)
        return NULL;
    kbcf->sql_src_names = ngx_list_create(cf->pool, 5, sizeof(ngx_http_kaze_backend_src_name_t));
    if (kbcf->sql_src_names == NULL)
        return NULL;
    return kbcf;
}

static char *
ngx_http_kaze_backend_arg_fill(ngx_pool_t *pool, ngx_str_t *cmd_args, ngx_str_t **tar)
{
    size_t len = cmd_args[1].len;
    u_char *data = cmd_args[1].data;
    if (!(*tar))
    {
        *tar = ngx_palloc(pool, sizeof(ngx_str_t));
        if (!(*tar))
            return NGX_CONF_ERROR;
    }
    u_char *new = ngx_palloc(pool, len + 1);
    ngx_memcpy(new, data, len);
    new[len] = 0;
    (*tar)->data = new;
    (*tar)->len = len;
    return NGX_CONF_OK;
}

static char *
ngx_http_kaze_backend_conf_parser(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_kaze_backend_conf_t *aacf = conf;
    if (aacf == NULL)
        return NGX_CONF_ERROR;
    ngx_str_t *cmd_args = (ngx_str_t *)cf->args->elts;
    if (cmd_args->len == 12 && cmd_args->data[4] == 'u')
    {
        if (ngx_http_kaze_backend_arg_fill(cf->pool, cmd_args, &aacf->sql_usrname) != NGX_CONF_OK)
            return NGX_CONF_ERROR;
    }
    else if (cmd_args->len == 12 && cmd_args->data[4] == 'p')
    {
        if (ngx_http_kaze_backend_arg_fill(cf->pool, cmd_args, &aacf->sql_passwd) != NGX_CONF_OK)
            return NGX_CONF_ERROR;
    }
    else if (cmd_args->data[4] == 'h')
    {
        if (ngx_http_kaze_backend_arg_fill(cf->pool, cmd_args, &aacf->sql_host) != NGX_CONF_OK)
            return NGX_CONF_ERROR;
    }
    else if (cmd_args->data[4] == 'p')
    {
        if (ngx_http_kaze_backend_arg_fill(cf->pool, cmd_args, &aacf->sql_port) != NGX_CONF_OK)
            return NGX_CONF_ERROR;
    }
    else if (cmd_args->data[4] == 'd')
    {
        if (ngx_http_kaze_backend_arg_fill(cf->pool, cmd_args, &aacf->sql_db_name) != NGX_CONF_OK)
            return NGX_CONF_ERROR;
    }
    else if (cmd_args->data[4] == 'u')
    {
        if (ngx_http_kaze_backend_arg_fill(cf->pool, cmd_args, &aacf->sql_usr_table) != NGX_CONF_OK)
            return NGX_CONF_ERROR;
        ngx_str_t au_add = ngx_string("_authority");
        size_t len = aacf->sql_usr_table->len + au_add.len + 1;
        u_char *data = ngx_palloc(cf->pool, len);
        if (data == NULL)
            return NGX_CONF_ERROR;
        ngx_memcpy(data, aacf->sql_usr_table->data, aacf->sql_usr_table->len);
        ngx_memcpy(data + aacf->sql_usr_table->len, au_add.data, au_add.len);
        data[len] = 0;
        aacf->sql_usr_au_table = ngx_palloc(cf->pool, sizeof(ngx_str_t));
        if (!aacf->sql_usr_au_table)
            return NGX_CONF_ERROR;
        aacf->sql_usr_au_table->data = data;
        aacf->sql_usr_au_table->len = len;
    }
    else if (cmd_args->data[4] == 's')
    {
        ngx_http_conf_ctx_t *hcct;
        ngx_http_core_loc_conf_t *hclc;
        ngx_http_core_srv_conf_t *cscf;
        hcct = cf->ctx;
        hclc = hcct->loc_conf[ngx_http_core_module.ctx_index];
        cscf = hcct->srv_conf[ngx_http_core_module.ctx_index];
        ngx_str_t loc = hclc->name;
        ngx_str_t root = hclc->root;
        ngx_uint_t i;
        ngx_http_server_name_t *start = cscf->server_names.elts;
        for (i = 0; i < cscf->server_names.nelts; i++)
        {
            ngx_http_kaze_backend_src_name_t *add;
            add = ngx_list_push(aacf->sql_src_names);
            if (add == NULL)
                return NGX_CONF_ERROR;
            size_t len = root.len + loc.len;
            u_char *data = ngx_palloc(cf->pool, len + 1);
            if (data == NULL)
                return NGX_CONF_ERROR;
            ngx_memcpy(data, root.data, root.len);
            ngx_memcpy(data + root.len, loc.data, loc.len);
            data[len] = 0;
            add->real_loc.data = data;
            add->real_loc.len = len;
            if (access((char *)data, F_OK) != 0)
            {
                if (mkdir((char *)data, 0777) == -1)
                {
                    ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "create src dir '%V' failed.", &add->real_loc);
                    return NGX_CONF_ERROR;
                }
            }
            else
            {
                if (opendir((char *)data) == NULL)
                {
                    ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "'%V' is a file or nginx do not have permission to access.", &add->real_loc);
                    return NGX_CONF_ERROR;
                }
                else if (access((char *)data, W_OK | X_OK) != 0)
                {
                    ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "nginx do not have permission to access dir '%V'.", &add->real_loc);
                    return NGX_CONF_ERROR;
                }
            }
            len = start[i].name.len + loc.len;
            data = ngx_palloc(cf->pool, len + 1);
            if (data == NULL)
                return NGX_CONF_ERROR;
            ngx_memcpy(data, start[i].name.data, start[i].name.len);
            ngx_memcpy(data + start[i].name.len, loc.data, loc.len);
            data[len] = 0;
            add->url_loc.data = data;
            add->url_loc.len = len;

            add->table_name = ngx_kaze_find_replace(cf->pool, &add->real_loc, '/', '_', 1);

            ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "[sql_src]url: %V -> real: %V", &add->url_loc, &add->real_loc);
        }
    }
    else
    {
        ngx_http_conf_ctx_t *hcct;
        ngx_http_core_loc_conf_t *hclc;
        hcct = cf->ctx;
        hclc = hcct->loc_conf[ngx_http_core_module.ctx_index];
        ngx_str_t loc = hclc->name;
        ngx_uint_t i;
        for (i = 1; i < cf->args->nelts; i++)
        {
            ngx_str_t var = {
                cmd_args[i].len,
                cmd_args[i].data,
            };
            size_t total_len = var.len + loc.len;
            u_char *cat = ngx_palloc(cf->pool, sizeof(u_char) * total_len);
            ngx_memcpy(cat, var.data, var.len);
            ngx_memcpy(cat + var.len, loc.data, loc.len);
            ngx_str_t *add;
            if (loc.len != 0)
                add = ngx_list_push(aacf->server_names);
            else
                add = ngx_list_push(aacf->server_names_main);
            if (add == NULL)
                return NGX_CONF_ERROR;
            add->data = cat;
            add->len = total_len;
        }
    }
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_kaze_backend_handler(ngx_http_request_t *r)
{
    ngx_http_kaze_backend_conf_t *aacf = ngx_http_get_module_main_conf(r, ngx_http_kaze_backend);

    if (aacf == NULL)
        return NGX_DECLINED;

    if (!(r->method & (NGX_HTTP_POST | NGX_HTTP_GET | NGX_HTTP_HEAD)))
        return NGX_HTTP_NOT_ALLOWED;

    ngx_str_t uri = ngx_kaze_heads_uri(r),
              host = ngx_kaze_heads_host(r),
              url = ngx_kaze_str_cat(r->pool, &host, &uri);

    if (!ngx_http_kaze_backend_find_url(aacf, host, url))
        return NGX_DECLINED;

    ngx_chain_t out;
    size_t i;

    ngx_http_kaze_backend_cmd_t cmd;
    ngx_int_t rc;
    for (i = 0;; i++)
    {
        cmd = ngx_http_kaze_backend_k_cmds[i];
        if (cmd.cmd.len == 0 && cmd.cmd.data == NULL && cmd.func == NULL)
            return NGX_DECLINED;
        if (ngx_kaze_str_cmp(&uri, &cmd.cmd) == 0)
        {
            if (cmd.func)
            {
                if ((rc = cmd.func(aacf, r, &out)) == NGX_OK)
                    break;
                else
                    return rc;
            }
        }
    }
    return ngx_http_output_filter(r, &out);
}

static ngx_uint_t
ngx_http_kaze_backend_get_permission(ngx_http_request_t *r, ngx_http_kaze_backend_conf_t *aacf)
{
    ngx_list_t *cookies = ngx_kaze_heads_in_parser_cookie(r);
    if (cookies == NULL)
        return 8;
    ngx_str_t au = ngx_kaze_list_find_key_chr(cookies, "authority");
    if (au.len == 0)
        return 8;
    ngx_int_t rc;
    char au_s[129], uid_s[10], t_s[15], ip_s[12], name_s[31], perm[5];
    ngx_memcpy(au_s, au.data, 128);
    au_s[128] = 0;
    rc = sql_kaze_query_key_vals(aacf->sql, (char *)aacf->sql_usr_au_table->data, "authority", au_s, 3, "uid", "time", "ip", uid_s, t_s, ip_s);
    if (rc == SQL_K_ERROR)
        return 8;
    rc = sql_kaze_query_key_vals(aacf->sql, (char *)aacf->sql_usr_table->data, "uid", uid_s, 2, "username", "permission", name_s, perm);
    if (rc == SQL_K_ERROR)
        return 8;
    return ngx_atoi((u_char *)perm, strlen(perm));
}

static ngx_int_t
ngx_http_kaze_backend_get_file_permission(ngx_http_kaze_backend_conf_t *aacf, ngx_str_t *tb_n, ngx_str_t *uri, ngx_uint_t *r, ngx_uint_t *w, ngx_uint_t *x, ngx_uint_t *reserve)
{
    char uri_s[STR_MAX_BUFF];
    ngx_memcpy(uri_s, uri->data, uri->len);
    uri_s[uri->len] = 0;
    ngx_int_t rc;
    rc = ngx_kaze_sql_qurey_key_val_exist(aacf->sql, (char *)tb_n->data, "filename", uri_s);
    if (rc == NGX_ERROR)
        return rc;
    if (rc == NGX_NONE)
    {
        *r = *w = *x = *reserve = 1;
        rc = sql_kaze_add_row_str(aacf->sql, (char *)tb_n->data, "'%ts', %d, %d, %d, %d",
                                  "filename", "r", "w", "x", "reserve",
                                  uri_s, 1, 1, 1, 1);
        if (rc == SQL_K_ERROR)
            return NGX_ERROR;
    }
    else
    {
        char r_s[2], w_s[2], x_s[2], reserve_s[2];
        rc = sql_kaze_query_key_vals(aacf->sql, (char *)tb_n->data, "filename", uri_s, 4, "r", "w", "x", "reserve", r_s, w_s, x_s, reserve_s);
        if (rc == SQL_K_ERROR)
            return NGX_ERROR;
        *r = ngx_atoi((u_char *)r_s, 1);
        *w = ngx_atoi((u_char *)w_s, 1);
        *x = ngx_atoi((u_char *)x_s, 1);
        *reserve = ngx_atoi((u_char *)reserve_s, 1);
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_kaze_backend_acc_handler(ngx_http_request_t *r)
{
    ngx_http_kaze_backend_conf_t *aacf = ngx_http_get_module_main_conf(r, ngx_http_kaze_backend);

    if (aacf == NULL)
        return NGX_DECLINED;

    // if (!(r->method & (NGX_HTTP_POST | NGX_HTTP_GET | NGX_HTTP_HEAD)))
    //     return NGX_HTTP_NOT_ALLOWED;

    ngx_str_t uri = ngx_kaze_heads_uri(r),
              host = ngx_kaze_heads_host(r),
              url = ngx_kaze_str_cat(r->pool, &host, &uri),
              tb_n;
    ngx_int_t rc;

    if (!ngx_http_kaze_backend_acc_find_url(aacf, url, &tb_n))
        return NGX_DECLINED;

    // u_char *name;
    size_t root;
    ngx_str_t path = ngx_null_string;
    ngx_http_map_uri_to_path(r, &path, &root, 0);

    if (access((char *)path.data, F_OK) != 0)
        return NGX_HTTP_NOT_FOUND;

    ngx_uint_t permission = ngx_http_kaze_backend_get_permission(r, aacf), r_, w, x, reserve;
    rc = ngx_http_kaze_backend_get_file_permission(aacf, &tb_n, &uri, &r_, &w, &x, &reserve);

    if (rc == NGX_ERROR)
        return rc;
    if (r_ < permission)
        return NGX_HTTP_FORBIDDEN;

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_kaze_backend_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);

    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_http_kaze_backend_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_http_kaze_backend_acc_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_http_kaze_backend_init_module(ngx_cycle_t *cycle)
{
    srand(time(NULL));

    ngx_http_kaze_backend_conf_t *aacf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_kaze_backend);
    ngx_uint_t i = 0;
    MYSQL *sql_t = sql_kaze_init((char *)aacf->sql_host->data,
                                 (char *)aacf->sql_usrname->data,
                                 (char *)aacf->sql_passwd->data,
                                 (char *)aacf->sql_db_name->data,
                                 ngx_atoi(aacf->sql_port->data, aacf->sql_port->len));
    if (sql_t == NULL)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "sql init failed with host: '%V', usr: '%V', passwd: '%V', database: '%V', port: '%V'.", aacf->sql_host, aacf->sql_usrname, aacf->sql_passwd, aacf->sql_db_name, aacf->sql_port);
        return NGX_ERROR;
    }
    ngx_list_part_t *start = &aacf->sql_src_names->part;
    while (1)
    {
        ngx_http_kaze_backend_src_name_t *tmp = start->elts;
        for (i = 0; i < start->nelts; i++)
        {
            if (ngx_kaze_sql_table_exist(sql_t, cycle->pool, &tmp[i].table_name, 1) != NGX_OK)
            {
                if (ngx_kaze_sql_dir_table_create(sql_t, cycle->pool, &tmp[i].table_name, 1) != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "create src table '%V' failed.", &tmp[i].table_name);
                    return NGX_ERROR;
                }
            }
        }
        if (!(start->next))
            break;
        else
            start = start->next;
    }
    if (ngx_kaze_sql_table_exist(sql_t, cycle->pool, aacf->sql_usr_table, 1) != NGX_OK)
    {
        if (ngx_kaze_sql_usr_table_create(sql_t, cycle->pool, aacf->sql_usr_table, 1) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "create user table '%V' failed.", aacf->sql_usr_table);
            return NGX_ERROR;
        }
        char pass[11];
        ngx_kaze_rand_str(10, pass, 1);
        if (ngx_kaze_sql_usr_add(sql_t, (char *)aacf->sql_usr_table->data, "admin", pass, 1) != SQL_K_OK)
        {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "create admin user faild.");
            return NGX_ERROR;
        }
        else
        {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "create admin user: 'admin', pass: '%s'.", pass);
        }
    }
    if (ngx_kaze_sql_table_exist(sql_t, cycle->pool, aacf->sql_usr_au_table, 1) != NGX_OK)
    {
        if (ngx_kaze_sql_usr_au_table_create(sql_t, cycle->pool, aacf->sql_usr_au_table, 1) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "create user authority table '%V' failed.", aacf->sql_usr_au_table);
            return NGX_ERROR;
        }
    }
    sql_kaze_close(sql_t);
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "master init.");
    return NGX_OK;
}

static ngx_int_t
ngx_http_kaze_backend_init_process(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "Running process init.");
    ngx_http_kaze_backend_conf_t *aacf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_kaze_backend);
    if (!aacf)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Module conf null!");
        return NGX_ERROR;
    }

    aacf->sql = sql_kaze_init((char *)aacf->sql_host->data,
                              (char *)aacf->sql_usrname->data,
                              (char *)aacf->sql_passwd->data,
                              (char *)aacf->sql_db_name->data,
                              ngx_atoi(aacf->sql_port->data, aacf->sql_port->len));
    if (aacf->sql == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "Mysql init failed!");
        return NGX_ERROR;
    }
    return NGX_OK;
}
static void
ngx_http_kaze_backend_exit_process(ngx_cycle_t *cycle)
{
    ngx_http_kaze_backend_conf_t *aacf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_kaze_backend);
    if (aacf)
    {
        if (aacf->sql)
        {
            sql_kaze_close(aacf->sql);
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "Mysql closed.");
        }
    }
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "Running process exit.");
}
