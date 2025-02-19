#include "ngx_k_file.h"

#include <sys/stat.h>
#include <unistd.h>

ngx_int_t ngx_file_is_dir(ngx_log_t *log, ngx_str_t *path)
{
    struct stat st;
    int rc;
    char *_path;
    ngx_str2str(path, _path);
    rc = stat(_path, &st);
    if (rc == EOF)
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "get file/dir info failed. \"%V\" may not exist.", path);
        return NGX_ERROR;
    }
    if (S_ISDIR(st.st_mode))
    {
        return NGX_OK;
    }
    else
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "\"%V\" is not a dir.", path);
        return NGX_NONE;
    }
    return NGX_OK;
}

ngx_int_t ngx_file_is_rwx(ngx_log_t *log, ngx_str_t *path)
{
    int rc;
    char *_path;
    ngx_str2str(path, _path);
    rc = access(_path, R_OK | W_OK | X_OK);
    if (rc != 0)
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "not have 'rwx' permisson of file/dir \"%V\"", path);
        return NGX_ERROR;
    }
    else
    {
        return NGX_OK;
    }
    return NGX_OK;
}

ngx_int_t ngx_file_is_exist(ngx_log_t *log, ngx_str_t *path)
{
    ngx_int_t rc;
    char *_path;
    ngx_str2str(path, _path);
    struct stat st;
    rc = stat(_path, &st);
    if (rc == EOF)
        return NGX_NONE;
    if (S_ISDIR(st.st_mode))
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "\"%V\" is a dir.", path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t ngx_file_create_or_add(ngx_log_t *log, ngx_str_t *path, FILE **fd)
{
    ngx_int_t rc;
    char *_path;
    ngx_str2str(path, _path);
    rc = ngx_file_is_exist(log, path);
    if (rc == NGX_ERROR)
        return NGX_ERROR;
    *fd = fopen(_path, "a+");
    if (*fd == NULL)
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "open file \"%V\" failed.", path);
        return NGX_ERROR;
    }
    return NGX_OK;
}