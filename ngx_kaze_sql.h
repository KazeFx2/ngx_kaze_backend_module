#include "./../sql/kaze_sql.h"
#include "ngx_kaze_string.h"

#define CREATE_SRC_TABLE "create table %s"                            \
                         "("                                          \
                         "`filename` varchar(100) not null unique, "  \
                         "`md5` varchar(32) default 'null', "         \
                         "`last_modify` varchar(32) default 'null', " \
                         "`r` tinyint(1) not null default 1, "        \
                         "`w` tinyint(1) not null default 1, "        \
                         "`x` tinyint(1) not null default 1, "        \
                         "`reserve` tinyint(1) not null default 1, "  \
                         "primary key(filename)"                      \
                         ")ENGINE=InnoDB CHARSET=utf8mb3;"

#define CREATE_USR_TABLE "CREATE TABLE %s ("                                                         \
                         "`uid` int unsigned NOT NULL AUTO_INCREMENT COMMENT 'UID', "                \
                         "`username` varchar(30) NOT NULL DEFAULT 'null' COMMENT 'UserName', "       \
                         "`passwd` varchar(20) NOT NULL DEFAULT '123456' COMMENT 'Password', "       \
                         "`permission` tinyint unsigned NOT NULL DEFAULT '2' COMMENT 'Permission', " \
                         "PRIMARY KEY (`uid`) "                                                      \
                         ") ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb3;"

#define CREATE_USR_AU_TABLE "CREATE TABLE %s ("                                           \
                            "`uid` int unsigned NOT NULL COMMENT 'UID', "                 \
                            "`authority` char(128) NOT NULL UNIQUE COMMENT 'Authority', " \
                            "`time` bigint unsigned NOT NULL COMMENT 'TimeGenerated', "   \
                            "`ip` int unsigned NOT NULL COMMENT 'LoginIP', "              \
                            "PRIMARY KEY (`uid`) "                                        \
                            ") ENGINE=InnoDB CHARSET=utf8mb3;"

#define ngx_kaze_sql_dir_table_create(sql, pool, dir, end) ngx_kaze_sql_table_create(sql, pool, CREATE_SRC_TABLE, dir, end)

#define ngx_kaze_sql_usr_table_create(sql, pool, dir, end) ngx_kaze_sql_table_create(sql, pool, CREATE_USR_TABLE, dir, end)

#define ngx_kaze_sql_usr_au_table_create(sql, pool, dir, end) ngx_kaze_sql_table_create(sql, pool, CREATE_USR_AU_TABLE, dir, end)

#define ngx_kaze_sql_usr_add(sql, table, usr, passwd, perm) \
    sql_kaze_add_row_str(sql, table, "'%ts', '%ts', %d", "username", "passwd", "permission", usr, passwd, perm)

#define ngx_kaze_sql_usr_au_add(sql, table, uid, au, _time, ip) \
    sql_kaze_add_row_str(sql, table, "%d, '%ts', %ld, %d", uid, au, _time, ip)

ngx_int_t ngx_kaze_sql_passwd(MYSQL *sql, ngx_pool_t *pool, const char *table, ngx_str_t *username, ngx_str_t *out_passwd, ngx_uint_t end);

ngx_int_t ngx_kaze_sql_passwd_permit_uid_chr(MYSQL *sql, const char *table, ngx_str_t *username, char *out_passwd, uint *permit, uint *uid, ngx_uint_t end);

ngx_int_t ngx_kaze_sql_qurey_key_val_exist(MYSQL *sql, const char *table, const char *key, const char *val);

ngx_int_t ngx_kaze_sql_usr_registered(MYSQL *sql, ngx_pool_t *pool, const char *table, ngx_str_t *username, ngx_uint_t end);

ngx_int_t ngx_kaze_sql_table_exist(MYSQL *sql, ngx_pool_t *pool, ngx_str_t *dir, ngx_uint_t end);

ngx_int_t ngx_kaze_sql_table_create(MYSQL *sql, ngx_pool_t *pool, const char *cmd, ngx_str_t *dir, ngx_uint_t end);