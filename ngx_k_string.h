#ifndef _NGX_KAZE_STRING_H_INCLUDED_
#define _NGX_KAZE_STRING_H_INCLUDED_

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

#define ngx_str2str(old, new)               \
                                            \
    new = (char *)(old)->data;              \
    char new##_tmp[(old)->len + 1];         \
    if ((new)[(old)->len] == '\0')          \
        goto new##_FLAG;                    \
    ngx_memcpy(new##_tmp, new, (old)->len); \
    new##_tmp[(old)->len] = '\0';           \
    new = new##_tmp;                        \
    new##_FLAG:

#endif