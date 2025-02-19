#ifndef _NGX_KAZE_BK_H_INCLUDED_
#define _NGX_KAZE_BK_H_INCLUDED_

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

#ifndef _mysql_h
#include <mysql/mysql.h>
#endif

extern ngx_http_module_t ngx_http_kaze_backend_ctx;

/*主机地址结构体*/
typedef struct ngx_http_kaze_backend_host_s ngx_http_kaze_backend_host_t;
/*文件名结构体*/
typedef struct ngx_http_kaze_backend_filename_s ngx_http_kaze_backend_filename_t;
/*配置信息主结构体*/
typedef struct ngx_http_kaze_backend_conf_s ngx_http_kaze_backend_conf_t;
/*服务块配置结构体*/
typedef struct ngx_http_kaze_backend_srv_conf_s ngx_http_kaze_backend_srv_conf_t;
/*位置块配置结构体*/
typedef struct ngx_http_kaze_backend_loc_conf_s ngx_http_kaze_backend_loc_conf_t;
/*主机地址树结点*/
typedef struct ngx_http_kaze_backend_host_name_tree_node_s ngx_http_kaze_backend_host_name_tree_node_t;
/*指令结构体*/
typedef struct ngx_http_kaze_backend_directives_s ngx_http_kaze_backend_directives_t;
/*指令范围*/
typedef enum ngx_http_kaze_backend_directive_type_e ngx_http_kaze_backend_directive_type_t;
/*指令类型*/
typedef enum ngx_http_kaze_backend_directive_host_type_e ngx_http_kaze_backend_directive_host_type_t;

enum ngx_http_kaze_backend_directive_host_type_e
{
    NGX_HTTP_K_DIRECTIVE_R_NONE = -1,
    NGX_HTTP_K_DIRECTIVE_R_ALL = 0,
    NGX_HTTP_K_DIRECTIVE_R_SPE
};

enum ngx_http_kaze_backend_directive_type_e
{
    NGX_HTTP_K_DIRECTIVE_NONE = -1,
    NGX_HTTP_K_DIRECTIVE_SRC = 0,
    NGX_HTTP_K_DIRECTIVE_FUN
};

struct ngx_http_kaze_backend_host_s
{
    /*主机名*/
    ngx_str_t hostname;
    /*IP地址*/
    struct in_addr addr;
    /*端口*/
    ngx_int_t port;
};

struct ngx_http_kaze_backend_directives_s
{
    /*指令*/
    ngx_str_t directive;
    /*根目录*/
    ngx_str_t root;
    /*主机范围*/
    ngx_http_kaze_backend_directive_host_type_t range;
    /*主机名*/
    ngx_str_t host;
    /*类型*/
    ngx_http_kaze_backend_directive_type_t type;
    /*执行函数*/
    ngx_int_t (*func)(ngx_http_kaze_backend_conf_t *kbcf, ngx_http_request_t *r);
};

struct ngx_http_kaze_backend_filename_s
{
    /*文件名*/
    ngx_str_t filename;
    /*文件FD*/
    FILE *fd;
};

struct ngx_http_kaze_backend_host_name_tree_node_s
{
    /*下一字母查找表*/
    struct ngx_http_kaze_backend_host_name_tree_node_s **next;
    /*当前host指令列表*/
    ngx_array_t *directives;
};

struct ngx_http_kaze_backend_conf_s
{
    /*启用标志*/
    ngx_flag_t enabled;

    /*启用Server块计数器*/
    ngx_int_t srv_counter;

    /*主机名称树*/
    ngx_http_kaze_backend_host_name_tree_node_t hosts;

    /*数据库用户名*/
    ngx_str_t db_usr;
    /*数据库密码*/
    ngx_str_t db_passwd;
    /*数据库主机地址*/
    ngx_http_kaze_backend_host_t db_host;
    /*数据库名*/
    ngx_str_t db_name;
    /*用户数据表*/
    ngx_str_t db_usr_name;
    /*资源数据表*/
    ngx_str_t db_src_name;

    /*有效指令*/
    ngx_array_t *directives;

    /*是否记录IP*/
    ngx_flag_t record_ip;
    /*IP记录文件*/
    ngx_http_kaze_backend_filename_t record_ip_file;
    /*IP数据表*/
    ngx_str_t db_ip_name;

    /*mysql套接字*/
    MYSQL *sql;
};

struct ngx_http_kaze_backend_srv_conf_s
{
    /*启用标志*/
    ngx_flag_t backend_enabled;
    /*服务器主机名*/
    ngx_array_t *server_names;
};

struct ngx_http_kaze_backend_loc_conf_s
{
    /*启用标志*/
    ngx_flag_t src_enabled;
    /*根目录*/
    ngx_str_t root;
    /*位置*/
    ngx_str_t loc;
};

#endif