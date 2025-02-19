#include "ngx_sql.h"
#include <mysql/mysql.h>
#include "ngx_k_string.h"

#define USR "users"

#define STR_MAX_BUFF 1024

#define CREATE_USR "CREATE TABLE `%s` (\n"                                                                  \
                   "  `uid` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT 'UID',\n"                       \
                   "  `nickname` char(24) NOT NULL COMMENT '昵称',\n"                                     \
                   "  `passwd` char(64) NOT NULL COMMENT '密码',\n"                                       \
                   "  `email` char(30) DEFAULT NULL COMMENT '邮箱',\n"                                    \
                   "  `portrait` char(16) DEFAULT NULL COMMENT '头像',\n"                                 \
                   "  `create_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n" \
                   "  `last_time` timestamp NULL DEFAULT NULL COMMENT '最后登录时间',\n"              \
                   "  `last_ip` int unsigned DEFAULT NULL COMMENT '最后登录IP',\n"                      \
                   "  `token` char(16) DEFAULT NULL COMMENT 'Token',\n"                                     \
                   "  `token_time` timestamp NULL DEFAULT NULL COMMENT 'Token过期时间',\n"              \
                   "  `permission` tinyint unsigned NOT NULL DEFAULT '255' COMMENT '权限',\n"             \
                   "  PRIMARY KEY (`uid`),\n"                                                               \
                   "  UNIQUE KEY `nickname` (`nickname`),\n"                                                \
                   "  UNIQUE KEY `email` (`email`)\n"                                                       \
                   ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb3"

#define CREATE_SRC "CREATE TABLE `%s` (\n"                                                                \
                   "  `host` char(30) NOT NULL COMMENT '主机名',\n"                                    \
                   "  `directive` char(30) NOT NULL COMMENT '指令',\n"                                  \
                   "  `file` char(128) NOT NULL COMMENT '文件',\n"                                      \
                   "  `type` char(10) NOT NULL COMMENT '类型',\n"                                       \
                   "  `last_modify` timestamp NOT NULL COMMENT '最后修改时间',\n"                   \
                   "  `md5` char(16) NOT NULL COMMENT 'MD5',\n"                                           \
                   "  `permisson_r` tinyint unsigned NOT NULL DEFAULT '1' COMMENT '读权限',\n"         \
                   "  `permisson_w` tinyint unsigned NOT NULL DEFAULT '1' COMMENT '写权限',\n"         \
                   "  `permisson_reserve` tinyint unsigned NOT NULL DEFAULT '1' COMMENT '保留权限'\n" \
                   ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb3"

#define CREATE_IP "CREATE TABLE `%s` (\n"                                       \
                  "  `ip` int unsigned NOT NULL COMMENT '访问IP',\n"          \
                  "  `host` char(30) NOT NULL COMMENT '访问主机名',\n"     \
                  "  `uri` varchar(1024) NOT NULL COMMENT '路径',\n"          \
                  "  `time` timestamp NOT NULL COMMENT '时间',\n"             \
                  "  `method` char(10) NOT NULL COMMENT '方法',\n"            \
                  "  `parm` varchar(1024) DEFAULT NULL COMMENT '变量',\n"     \
                  "  `heads` varchar(1024) DEFAULT NULL COMMENT '头参数',\n" \
                  "  `result` char(10) NOT NULL COMMENT '结果'\n"             \
                  ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb3"

static inline ngx_int_t
ngx_sql_execute(ngx_log_t *log, MYSQL *sql, const char *cmd)
{
    if (!sql)
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "[sql_query]error in null sql ptr");
        return NGX_ERROR;
    }
    if (mysql_query(sql, cmd))
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "[sql_query]error in command \"%s\"", cmd);
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t ngx_sql_solve_res(ngx_log_t *log, MYSQL *sql, ngx_int_t (*func)(ngx_log_t *, uint64_t, uint64_t, MYSQL_RES *, void *), void *data)
{
    if (sql == NULL)
        return NGX_ERROR;
    MYSQL_RES *res;
    uint64_t r, f;
    ngx_int_t rc = NGX_OK;
    res = mysql_store_result(sql);
    if (res == NULL)
        return NGX_ERROR;
    r = mysql_num_rows(res);
    f = mysql_num_fields(res);
    if (func)
    {
        rc = func(log, r, f, res, data);
    }
    mysql_free_result(res);
    return rc;
}

ngx_int_t ngx_sql_execute_fmt(ngx_log_t *log, MYSQL *sql, const char *fmt, ...)
{
    char vals[STR_MAX_BUFF];
    va_list list;
    va_start(list, fmt);
    size_t i = 0, j = 0, pos = 0;
    uint8_t pt = 0,
            st = 0;
    char tmp_f[10];
    /*
    none = 0,
    h = 1,
    hh,
    l = 3,
    ll = 4,
    j = 5,
    z = 6,
    t = 7,
    L = 8
    */
    while (fmt[pos] != 0)
    {
        if (fmt[pos] == '%')
        {
            if (fmt[pos + 1] == 0)
                break;
            if (fmt[pos + 1] == '%')
            {
                vals[i++] = '%';
            }
            else
            {
                tmp_f[i++] = '%';
                pt = 1;
            }
        }
        else if (pt)
        {
            switch (fmt[pos])
            {
            case 'c':
            case 's':
            {
                tmp_f[i++] = fmt[pos];
                tmp_f[i] = 0;
                if (st == 7)
                {
                    tmp_f[i - 2] = tmp_f[i - 1];
                    tmp_f[i - 1] = tmp_f[i];
                    char t_buf[STR_MAX_BUFF];
                    if (fmt[pos] == 'c')
                    {
                        sprintf(t_buf, tmp_f, va_arg(list, int));
                    }
                    else
                    {
                        sprintf(t_buf, tmp_f, va_arg(list, char *));
                    }
                    size_t length = strlen(t_buf);
                    for (i = 0; i < length; i++)
                    {
                        vals[j++] = t_buf[i];
                        if (t_buf[i] == '\'')
                        {
                            vals[j++] = t_buf[i];
                        }
                    }
                }
                else
                {
                    if (fmt[pos] == 'c')
                    {
                        sprintf(&vals[j], tmp_f, va_arg(list, int));
                    }
                    else
                    {
                        sprintf(&vals[j], tmp_f, va_arg(list, char *));
                    }
                    j = strlen(vals);
                }
                pt = i = st = 0;
            }
            break;
            case 'd':
            case 'i':
            case 'u':
            case 'o':
            case 'x':
            case 'X':
                tmp_f[i++] = fmt[pos];
                tmp_f[i] = 0;
                switch (st)
                {
                case 1:
                case 2:
                    sprintf(&vals[j], tmp_f, va_arg(list, int));
                    break;
                case 3:
                case 5:
                case 6:
                case 7:
                    sprintf(&vals[j], tmp_f, va_arg(list, unsigned long));
                    break;
                case 4:
                    sprintf(&vals[j], tmp_f, va_arg(list, unsigned long long));
                    break;
                case 8:
                case 0:
                default:
                    sprintf(&vals[j], tmp_f, va_arg(list, unsigned int));
                    break;
                }
                j = strlen(vals);
                pt = i = st = 0;
                break;
            case 'n':
                tmp_f[i++] = fmt[pos];
                tmp_f[i] = 0;
                switch (st)
                {
                case 1:
                    sprintf(&vals[j], tmp_f, va_arg(list, unsigned short *));
                    break;
                case 2:
                    sprintf(&vals[j], tmp_f, va_arg(list, unsigned char *));
                    break;
                case 3:
                case 5:
                case 6:
                case 7:
                    sprintf(&vals[j], tmp_f, va_arg(list, unsigned long *));
                    break;
                case 4:
                    sprintf(&vals[j], tmp_f, va_arg(list, unsigned long long *));
                    break;
                case 8:
                case 0:
                default:
                    sprintf(&vals[j], tmp_f, va_arg(list, unsigned int *));
                    break;
                }
                j = strlen(vals);
                pt = i = st = 0;
                break;
            case 'a':
            case 'A':
            case 'e':
            case 'E':
            case 'f':
            case 'F':
            case 'g':
            case 'G':
                tmp_f[i++] = fmt[pos];
                tmp_f[i] = 0;
                switch (st)
                {
                case 8:
                    sprintf(&vals[j], tmp_f, va_arg(list, long double));
                    break;
                case 0:
                case 3:
                default:
                    sprintf(&vals[j], tmp_f, va_arg(list, double));
                    break;
                }
                j = strlen(vals);
                pt = i = st = 0;
                break;
            case 'p':
                tmp_f[i++] = fmt[pos];
                tmp_f[i] = 0;
                sprintf(&vals[j], tmp_f, va_arg(list, void *));
                j = strlen(vals);
                pt = i = st = 0;
                break;
            case 'h':
                if (st == 1)
                    st++;
                else
                    st = 1;
                tmp_f[i++] = fmt[pos];
                break;
            case 'l':
                if (st == 3)
                    st++;
                else
                    st = 3;
                tmp_f[i++] = fmt[pos];
                break;
            case 'j':
                st = 5;
                tmp_f[i++] = fmt[pos];
                break;
            case 'z':
                st = 6;
                tmp_f[i++] = fmt[pos];
                break;
            case 't':
                st = 7;
                tmp_f[i++] = fmt[pos];
                break;
            case 'L':
                st = 8;
                tmp_f[i++] = fmt[pos];
                break;
            default:
                tmp_f[i++] = fmt[pos];
                break;
            }
        }
        else
            vals[j++] = fmt[pos];
        pos++;
    }
    vals[j] = 0;
    va_end(list);
    if (ngx_sql_execute(log, sql, vals) != NGX_OK)
        return NGX_ERROR;
    return NGX_OK;
}

ngx_int_t
ngx_sql_configure_check(ngx_log_t *log, ngx_http_kaze_backend_conf_t *kblog, MYSQL **mysql)
{
    MYSQL *sql;
    sql = mysql_init(NULL);
    if (!sql)
        return NGX_ERROR;
    char *host, *usr, *pswd, *db_name;
    ngx_str2str(&kblog->db_host.hostname, host);
    ngx_str2str(&kblog->db_usr, usr);
    ngx_str2str(&kblog->db_passwd, pswd);
    ngx_str2str(&kblog->db_name, db_name);
    if (!(sql = mysql_real_connect(sql, host, usr, pswd, db_name, kblog->db_host.port, NULL, 0)))
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "Error in connecting to mysql with host: \"%s\", username: \"%s\", password: \"%s\", database name: \"%s\", port: \"%d\".\n Please check it.", host, usr, pswd, db_name, kblog->db_host.port);
        *mysql = NULL;
        return NGX_ERROR;
    }
    *mysql = sql;
    return NGX_OK;
}

ngx_int_t ngx_sql_test_res(ngx_log_t *log, uint64_t r, uint64_t f, MYSQL_RES *res, void *d)
{
    uint64_t i, j;
    for (i = 0; i < r; i++)
    {
        MYSQL_ROW row = mysql_fetch_row(res);
        for (j = 0; j < f; j++)
        {
            if (row[j] == NULL)
            {
                ngx_log_error(NGX_LOG_NOTICE, log, 0, "[row %d]null", i);
            }
            else
            {
                ngx_log_error(NGX_LOG_NOTICE, log, 0, "[row %d]%s", i, row[j]);
            }
        }
    }
    return NGX_OK;
}

static inline ngx_int_t __ngx_sql_exist_inner(ngx_log_t *log, uint64_t r, uint64_t f, MYSQL_RES *res, void *d)
{
    uint64_t *re = d;
    *re = r;
    return NGX_OK;
}

ngx_int_t ngx_sql_drop_res(ngx_log_t *log, MYSQL *mysql)
{
    MYSQL_RES *res = mysql_store_result(mysql);
    if (res == NULL)
        return NGX_OK;
    mysql_free_result(res);
    return NGX_OK;
}

ngx_int_t ngx_sql_table_exist(ngx_log_t *log, MYSQL *mysql, char *name)
{
    ngx_int_t rc;
    rc = ngx_sql_execute_fmt(log, mysql, "show tables like '%ts'", name);
    if (rc != NGX_OK)
    {
        return NGX_ERROR;
    }
    uint64_t r;
    rc = ngx_sql_solve_res(log, mysql, __ngx_sql_exist_inner, &r);
    if (rc != NGX_OK)
        return NGX_ERROR;
    if (r == 0)
        return NGX_NONE;
    return NGX_OK;
}

ngx_int_t _ngx_sql_table_cmp_inner(ngx_log_t *log, uint64_t r, uint64_t f, MYSQL_RES *res, void *d)
{
    struct
    {
        char *name;
        int type;
    } *data = d;
    if (r != 1 || f != 2)
        return NGX_ERROR;
    MYSQL_ROW row = mysql_fetch_row(res);
    char *a = row[1];
    char b[STR_MAX_BUFF];
    if (data->type == 0)
        sprintf(b, CREATE_USR, data->name);
    else
        sprintf(b, CREATE_SRC, data->name);
    size_t pos_a = 0, pos_b = 0, pos_key = 0;
    char key[] = "COMMENT";
    while (a[pos_a] != '\0' || b[pos_b] != '\0')
    {
        if (a[pos_a] != b[pos_b])
            return NGX_NONE;
        if (a[pos_a] == key[pos_key])
        {
            pos_key++;
            if (key[pos_key] == '\0')
            {
                int ct = 0;
                while (a[pos_a] != '\'' || ct++ != 1)
                {
                    pos_a++;
                }
                ct = 0;
                while (b[pos_b] != '\'' || ct++ != 1)
                {
                    pos_b++;
                }
            }
        }
        else
            pos_key = 0;
        pos_a++, pos_b++;
    }
    return NGX_OK;
}

/*type: 0-usr
            1-src
            2-ip*/
ngx_int_t ngx_sql_create_table(ngx_log_t *log, MYSQL *mysql, char *name, int type)
{
    ngx_int_t rc;
    switch (type)
    {
    case 0:
        rc = ngx_sql_execute_fmt(log, mysql, CREATE_USR, name);
        break;
    case 1:
        rc = ngx_sql_execute_fmt(log, mysql, CREATE_SRC, name);
        break;
    case 2:
        rc = ngx_sql_execute_fmt(log, mysql, CREATE_IP, name);
        break;
    default:
        rc = NGX_ERROR;
        break;
    }
    if (rc != NGX_OK)
        return NGX_ERROR;
    ngx_sql_drop_res(log, mysql);
    return NGX_OK;
}

/*type: 0-usr
            1-src
            2-ip*/
ngx_int_t _ngx_sql_table_c(ngx_log_t *log, MYSQL *mysql, char *name, int type)
{
    static char *prompt[] = {
        "user_table",
        "src_table",
        "ip_table"};
    ngx_int_t rc;
    struct
    {
        char *name;
        int type;
    } data = {name, type};
    rc = ngx_sql_table_exist(log, mysql, name);
    if (rc == NGX_NONE)
    {
        rc = ngx_sql_create_table(log, mysql, name, type);
        if (rc != NGX_OK)
            return NGX_ERROR;
        return NGX_OK;
    }
    else
    {
        rc = ngx_sql_execute_fmt(log, mysql, "show create table %ts", name);
        if (rc != NGX_OK)
            return NGX_ERROR;
        rc = ngx_sql_solve_res(log, mysql, _ngx_sql_table_cmp_inner, &data);
        if (rc == NGX_ERROR)
            return NGX_ERROR;
        if (rc == NGX_NONE)
        {
            ngx_log_error(NGX_LOG_EMERG, log, 0, "[table check \"%s\"]failed, exist different table with the same name \"%s\"", prompt[type], name);
            return NGX_ERROR;
        }
        return NGX_OK;
    }
    return NGX_OK;
}

ngx_int_t ngx_sql_tables_check(ngx_log_t *log, MYSQL *mysql, ngx_http_kaze_backend_conf_t *kblog)
{
    ngx_int_t rc;
    char *usr, *src;
    ngx_str2str(&kblog->db_usr_name, usr);
    ngx_str2str(&kblog->db_src_name, src);
    ngx_log_error(NGX_LOG_NOTICE, log, 0, "[tables check]");
    rc = _ngx_sql_table_c(log, mysql, usr, 0);
    if (rc != NGX_OK)
        return NGX_ERROR;
    rc = _ngx_sql_table_c(log, mysql, src, 1);
    if (rc != NGX_OK)
        return NGX_ERROR;
    return NGX_OK;
}
