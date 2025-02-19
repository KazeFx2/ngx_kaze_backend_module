#include <ngx_http.h>
#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_conf_file.h>
#include <time.h>

enum sql_dtype
{
    /*value*/
    SQL_TINYINT = 0,
    SQL_SMALLINT,
    SQL_MEDIUMINT,
    SQL_INTEGER,
    SQL_BIGINT,
    SQL_FLOAT,
    SQL_DOUBLE,
    SQL_DECIMAL,
    /*date*/
    SQL_DATE = 8,
    SQL_TIME,
    SQL_YEAR,
    SQL_DATETIME,
    SQL_TIMESTAMP,
    /*string/blob*/
    SQL_CHAR = 13,
    SQL_VARCHAR,
    SQL_TINYBLOB,
    SQL_TINYTEXT,
    SQL_BLOB,
    SQL_TEXT,
    SQL_MEDIUMTEXT,
    SQL_LONGBLOB,
    SQL_LONGTEXT,
    /*end*/
    SQL_NULL = 22
};

enum sql_bool
{
    SQL_FALSE = 0,
    SQL_TRUE
};

enum sql_charsets
{
    SQL_CHARSET_ARMSCII8,
    SQL_CHARSET_ASCII,
    SQL_CHARSET_BIG5,
    SQL_CHARSET_BINARY,
    SQL_CHARSET_CP1250,
    SQL_CHARSET_CP1251,
    SQL_CHARSET_CP1256,
    SQL_CHARSET_CP1257,
    SQL_CHARSET_850,
    SQL_CHARSET_852,
    SQL_CHARSET_866,
    SQL_CHARSET_932,
    SQL_CHARSET_DEC8,
    SQL_CHARSET_EUCJPMS,
    SQL_CHARSET_EUCKR,
    SQL_CHARSET_GB18030,
    SQL_CHARSET_GB2312,
    SQL_CHARSET_GBK,
    SQL_CHARSET_GEOSTD8,
    SQL_CHARSET_GREEK,
    SQL_CHARSET_HEBREW,
    SQL_CHARSET_HP8,
    SQL_CHARSET_KEYBCS2,
    SQL_CHARSET_KOI8R,
    SQL_CHARSET_KOI8U,
    SQL_CHARSET_LATIN1,
    SQL_CHARSET_LATIN2,
    SQL_CHARSET_LATIN5,
    SQL_CHARSET_LATIN7,
    SQL_CHARSET_MACCE,
    SQL_CHARSET_MARCOMAN,
    SQL_CHARSET_SJIS,
    SQL_CHARSET_SWE7,
    SQL_CHARSET_TIS620,
    SQL_CHARSET_UCS2,
    SQL_CHARSET_UJIS,
    SQL_CHARSET_UTF16,
    SQL_CHARSET_UTF16LE,
    SQL_CHARSET_UTF32,
    SQL_CHARSET_UTF8MB3,
    SQL_CHARSET_UTF8MB4
};

typedef struct sql_dtype_s sql_dtype_t;
typedef struct sql_dtype_intx_s sql_dtype_intx_t;
typedef struct sql_dtype_floatx_s sql_dtype_floatx_t;
typedef struct sql_dtype_date_s sql_dtype_date_t;
typedef struct sql_dtype_blob_s sql_dtype_blob_t;
typedef struct str_s str_t;

struct str_s
{
    size_t len;
    unsigned char *date;
};

struct sql_dtype_s
{
    str_t name, comment;
    sql_dtype dtype;
    size_t size;
    sql_bool have_data, not_null, auto_increment, primary_key, ;
    struct sql_dtype_s *next;
};

struct sql_dtype_intx_s
{
    struct sql_dtype_s attr;
    union int_val
    {
        unsigned char tinyint;
        uint16_t smallint;
        uint32_t mediumint, integer;
        uint64_t bigint;
    } value;
};

struct sql_dtype_floatx_s
{
    struct sql_dtype_s attr;
    union float_val
    {
        float _float;
        double _double, decimal;
    } value;
    struct
    {
        short m;
        short d;
    } dec_attr;
};

struct sql_dtype_date_s
{
    struct sql_dtype_s attr;
    struct tm gmt;
    time_t timestamp;
};

struct sql_dtype_blob_s
{
    struct sql_dtype_s attr;
    sql_bool is_file;
    union
    {
        str_t file_path;
        struct
        {
            void *start;
            void *pos;
            void *end;
        } buf;
    } date;
};

struct sql_table_s
{
    str_t name;
    sql_dtype_t *elm;
    sql_charsets charset;
};