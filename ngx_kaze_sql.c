#include "ngx_kaze_sql.h"

ngx_int_t ngx_kaze_sql_passwd(MYSQL *sql, ngx_pool_t *pool, const char *table, ngx_str_t *username, ngx_str_t *out_passwd, ngx_uint_t end)
{
    char buf[21];
    ngx_int_t rc;
    if (!end)
    {
        char *usr = (char *)ngx_kaze_stoc(pool, username);
        if (*usr == 0)
            return NGX_ERROR;
        rc = sql_kaze_query_key_val(sql, table, "username", usr, "passwd", buf, sizeof(buf));
    }
    else
        rc = sql_kaze_query_key_val(sql, table, "username", (char *)username->data, "passwd", buf, sizeof(buf));
    *out_passwd = ngx_kaze_ctos(pool, (u_char *)buf);
    if (rc != SQL_K_OK)
        return NGX_NONE;
    return NGX_OK;
}

ngx_int_t ngx_kaze_sql_passwd_permit_uid_chr(MYSQL *sql, const char *table, ngx_str_t *username, char *out_passwd, uint *permit, uint *uid, ngx_uint_t end)
{
    ngx_int_t rc;
    char perm[5] = "8";
    char uid_s[10] = "0";
    if (!end)
    {
        char usr[username->len + 1];
        ngx_memcpy(usr, username->data, username->len);
        usr[username->len] = 0;
        if (*usr == 0)
            return NGX_ERROR;
        rc = sql_kaze_query_key_vals(sql, table, "username", usr, 3, "passwd", "permission", "uid", out_passwd, perm, uid_s);
    }
    else
        rc = sql_kaze_query_key_vals(sql, table, "username", (char *)username->data, 3, "passwd", "permission", "uid", out_passwd, perm, uid_s);
    *permit = ngx_atoi((u_char *)perm, strlen(perm));
    *uid = ngx_atoi((u_char *)uid_s, strlen(uid_s));
    if (rc != SQL_K_OK)
        return NGX_NONE;
    return NGX_OK;
}

ngx_int_t ngx_kaze_sql_usr_registered(MYSQL *sql, ngx_pool_t *pool, const char *table, ngx_str_t *username, ngx_uint_t end)
{
    ngx_int_t rc;
    if (!end)
    {
        char *usr = (char *)ngx_kaze_stoc(pool, username);
        if (*usr == 0)
            return NGX_ERROR;
        rc = sql_kaze_query_key_val(sql, table, "username", usr, "passwd", NULL, 0);
    }
    else
    {
        rc = sql_kaze_query_key_val(sql, table, "username", (char *)username->data, "passwd", NULL, 0);
    }
    if (rc != SQL_K_OK)
        return NGX_NONE;
    return NGX_OK;
}

ngx_int_t ngx_kaze_sql_qurey_key_val_exist(MYSQL *sql, const char *table, const char *key, const char *val)
{
    ngx_int_t rc;
    rc = sql_kaze_execute_fmt(sql, "select * from %s where %s='%s';", table, key, val);
    if (rc == SQL_K_ERROR)
        return NGX_ERROR;
    MYSQL_RES *res = mysql_store_result(sql);
    if (res == NULL)
        return NGX_ERROR;
    size_t r = mysql_num_rows(res);
    mysql_free_result(res);
    if (r > 0)
        return NGX_OK;
    return NGX_NONE;
}

ngx_int_t ngx_kaze_sql_table_exist(MYSQL *sql, ngx_pool_t *pool, ngx_str_t *dir, ngx_uint_t end)
{
    ngx_int_t rc;
    if (!end)
    {
        char *dir_ = (char *)ngx_kaze_stoc(pool, dir);
        if (*dir_ == 0)
            return NGX_ERROR;
        rc = sql_kaze_table_exist(sql, dir_);
    }
    else
        rc = sql_kaze_table_exist(sql, (char *)dir->data);
    if (rc != SQL_K_OK)
        return NGX_NONE;
    return NGX_OK;
}

ngx_int_t ngx_kaze_sql_table_create(MYSQL *sql, ngx_pool_t *pool, const char *cmd, ngx_str_t *dir, ngx_uint_t end)
{
    ngx_int_t rc;
    if (!end)
    {
        char *dir_ = (char *)ngx_kaze_stoc(pool, dir);
        if (*dir_ == 0)
            return NGX_ERROR;
        rc = sql_kaze_execute_fmt(sql, cmd, dir_);
    }
    else
        rc = sql_kaze_execute_fmt(sql, cmd, dir->data);
    if (rc != SQL_K_OK)
        return NGX_ERROR;
    return NGX_OK;
}
