#include "ngx_kaze_string.h"
#include <stdarg.h>

#define toHex(str) (str[0] > 'A' ? (str[0] - 'A') + 10 : str[0] - '0') * 16 + (str[1] > 'A' ? (str[1] - 'A') + 10 : str[1] - '0')

#define setType(val, name)                                  \
    case val:                                               \
        ngx_str_set(&r->headers_out.content_type, name);    \
        r->headers_out.content_type_len = sizeof(name) - 1; \
        break

size_t ngx_kaze_str_find(ngx_str_t *str, u_char a)
{
    if (str->len == 0)
        return 0;
    size_t pos = 0;
    while (str->data[pos] != a && pos != str->len)
        pos++;
    return pos;
}

size_t ngx_kaze_str_rfind(ngx_str_t *str, u_char a)
{
    if (str->len == 0)
        return 0;
    size_t pos = str->len - 1;
    while (1)
    {
        if (str->data[pos] == a)
            return pos;
        if (pos == 0)
            return str->len;
        pos--;
    }
}

size_t ngx_kaze_str_rfind_start(ngx_str_t *str, u_char a, size_t start)
{
    if (str->len == 0)
        return 0;
    if (start >= str->len)
        return str->len;
    if (start == 0)
        return str->len;
    size_t pos = start - 1;
    while (1)
    {
        if (str->data[pos] == a)
            return pos;
        if (pos == 0)
            return str->len;
        pos--;
    }
}

ngx_str_t ngx_kaze_str_cat(ngx_pool_t *pool, ngx_str_t *a, ngx_str_t *b)
{
    size_t total = a->len + b->len;
    ngx_str_t ret = {0, NULL};
    u_char *data = ngx_palloc(pool, sizeof(u_char) * total);
    if (data == NULL)
        return ret;
    ret.len = total;
    ret.data = data;
    ngx_memcpy(data, a->data, a->len);
    ngx_memcpy(data + a->len, b->data, b->len);
    return ret;
}

ngx_str_t ngx_kaze_str_ncat(ngx_pool_t *pool, ngx_uint_t n, ...)
{
    size_t total = 0;
    ngx_str_t ret = {0, NULL};
    u_char *data;
    ngx_str_t *in[n];
    ngx_uint_t pos = 0;
    va_list list;
    va_start(list, n);
    while (n)
    {
        in[pos] = va_arg(list, ngx_str_t *);
        total += in[pos]->len;
        pos++;
        n--;
    }
    va_end(list);
    data = ngx_palloc(pool, total);
    if (data == NULL)
        return ret;
    ret.data = data;
    ret.len = total;
    while (pos)
    {
        ngx_memcpy(data, in[n]->data, in[n]->len);
        data += in[n]->len;
        pos--;
        n++;
    }
    return ret;
}

ngx_str_t ngx_kaze_str_n_arycat(ngx_pool_t *pool, ngx_uint_t n, ngx_str_t *str_ary)
{
    size_t total = 0;
    ngx_str_t ret = {0, NULL};
    u_char *data;
    ngx_uint_t pos = 0;
    for (pos = 0; pos < n; pos++)
        total += str_ary[pos].len;
    data = ngx_palloc(pool, total);
    if (data == NULL)
        return ret;
    ret.data = data;
    ret.len = total;
    n = 0;
    while (pos)
    {
        ngx_memcpy(data, str_ary[n].data, str_ary[n].len);
        data += str_ary[n].len;
        pos--;
        n++;
    }
    return ret;
}

ngx_int_t ngx_kaze_str_cmp(ngx_str_t *a, ngx_str_t *b)
{
    if (a->len != b->len)
        if (a->len > b->len)
            return 1;
        else
            return -1;
    else
    {
        if (a->len == 0)
            return 0;
        size_t pos = 0;
        while (pos != a->len && a->data[pos] == b->data[pos])
            pos++;
        if (pos == a->len)
            return 0;
        if (a->data[pos] > b->data[pos])
            return 1;
        else
            return -1;
    }
}

ngx_int_t ngx_kaze_str_cmp_chr(ngx_str_t *a, char *b)
{
    size_t len = 0;
    if (*b == 0)
    {
        if (a->len > 0)
            return 1;
        else
            return 0;
    }
    while (b[++len] != 0)
        ;
    if (a->len != len)
        if (a->len > len)
            return 1;
        else
            return -1;
    else
    {
        if (a->len == 0)
            return 0;
        size_t pos = 0;
        while (pos != a->len && a->data[pos] == b[pos])
            pos++;
        if (pos == a->len)
            return 0;
        if (a->data[pos] > b[pos])
            return 1;
        else
            return -1;
    }
}

ngx_int_t ngx_kaze_set_content_type(ngx_http_request_t *r, ngx_kaze_content_type ty)
{
    switch (ty)
    {
        setType(NGX_K_CONTENT_JSON, "application/json");
        setType(NGX_K_CONTENT_TXT, "text/plain");
    default:
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t ngx_kaze_heads_add(ngx_http_request_t *r, const u_char *key, const u_char *val)
{
    ngx_table_elt_t *new = ngx_list_push(&r->headers_out.headers);
    if (new == NULL)
        return NGX_ERROR;
    new->hash = 1;
    ngx_str_set(&new->key, key);
    ngx_str_set(&new->value, val);
    return NGX_OK;
}

ngx_int_t ngx_kaze_heads_str_add(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *val)
{
    ngx_table_elt_t *new = ngx_list_push(&r->headers_out.headers);
    if (new == NULL)
        return NGX_ERROR;
    new->hash = 1;
    new->key = *key;
    new->value = *val;
    return NGX_OK;
}

ngx_str_t ngx_kaze_itoa(ngx_pool_t *pool, ngx_int_t val)
{
    ngx_str_t ret = {0, NULL};
    ngx_uint_t neg = val < 0 ? 1 : 0;
    val *= neg ? -1 : 1;
    ngx_int_t n[10], len = 0;
    while (val)
    {
        n[len] = val % 10;
        val /= 10;
        len++;
    }
    ret.data = ngx_palloc(pool, len + neg);
    if (ret.data == NULL)
        return ret;
    ret.len = len + neg;
    val = -1;
    if (neg)
        ret.data[++val] = '-';
    while (1)
    {
        len--;
        ret.data[++val] = '0' + n[len];
        if (len == 0)
            break;
    }
    return ret;
}

ngx_int_t ngx_kaze_heads_add_cookie(ngx_http_request_t *r, ngx_kaze_cookie_t *cookie)
{
    if (!cookie)
        return NGX_ERROR;
    ngx_str_t va[11];
    size_t pos = 0;
    ngx_str_t tp = ngx_string("="), br = ngx_string("; "), key = ngx_string("Set-Cookie");
    va[0] = ngx_kaze_str_ncat(r->pool, 3, &cookie->key, &tp, &cookie->val);
    if (cookie->max_age != 0)
    {
        va[++pos] = br;
        ngx_str_t k = ngx_string("Max-Age=");
        u_char *c_time = ngx_palloc(r->connection->pool, 32);
        ngx_http_cookie_time(c_time, cookie->max_age);
        ngx_str_t tmp = {strlen((char *)c_time) - 1, c_time};
        va[++pos] = ngx_kaze_str_cat(r->pool, &k, &tmp);
    }
    if (cookie->secure)
    {
        va[++pos] = br;
        ngx_str_t k = ngx_string("Secure");
        va[++pos] = k;
    }
    if (cookie->http_only)
    {
        va[++pos] = br;
        ngx_str_t k = ngx_string("HttpOnly");
        va[++pos] = k;
    }
    if (cookie->domain.len)
    {
        va[++pos] = br;
        ngx_str_t k = ngx_string("Domain=");
        va[++pos] = ngx_kaze_str_cat(r->pool, &k, &cookie->domain);
    }
    if (cookie->path.len)
    {
        va[++pos] = br;
        ngx_str_t k = ngx_string("Path=");
        va[++pos] = ngx_kaze_str_cat(r->pool, &k, &cookie->path);
    }
    ngx_str_t fin_val = ngx_kaze_str_n_arycat(r->pool, pos + 1, va);
    if (fin_val.len == 0)
        return NGX_ERROR;
    if (ngx_kaze_heads_str_add(r, &key, &fin_val) != NGX_OK)
        return NGX_ERROR;
    return NGX_OK;
}

ngx_int_t ngx_kaze_heads_add_ncookie(ngx_http_request_t *r, size_t n, ngx_kaze_cookie_t *cookie)
{
    size_t i = 0;
    for (i = 0; i < n; i++)
        if (ngx_kaze_heads_add_cookie(r, &cookie[i]) != NGX_OK)
            return NGX_ERROR;
    return NGX_OK;
}

ngx_list_t *ngx_kaze_heads_in_parser_cookie(ngx_http_request_t *r)
{
    ngx_uint_t i = 0;
    ngx_table_elt_t **start = r->headers_in.cookies.elts;
    ngx_list_t *ret_list = ngx_list_create(r->pool, 2, sizeof(ngx_table_elt_t));
    if (ret_list == NULL)
        return NULL;
    ngx_str_t cookie_str = ngx_string("Cookie");
    for (i = 0; i < r->headers_in.cookies.nelts; i++)
    {
        if (ngx_kaze_str_cmp(&start[i]->key, &cookie_str) == 0)
        {
            ngx_str_t line = start[i]->value, key, val;
            size_t begin = 0,
                   end = 0, h_end = line.len;
            end = ngx_kaze_str_rfind(&line, '=');
            while (end != line.len)
            {
                ngx_table_elt_t *item = ngx_list_push(ret_list);
                if (item == NULL)
                    return NULL;
                if ((begin = ngx_kaze_str_rfind_start(&line, ';', end)) == line.len)
                    begin = 0;
                else
                    begin += 2;
                key.data = &line.data[begin];
                key.len = end - begin;
                val.data = &line.data[end + 1];
                val.len = h_end - end - 1;
                end = ngx_kaze_str_rfind_start(&line, '=', begin - 2);
                h_end = begin - 2;
                item->key = key;
                item->hash = 1;
                item->value = val;
                item->lowcase_key = NULL;
            }
            break;
        }
    }
    return ret_list;
}

ngx_str_t ngx_kaze_str_lowcase(ngx_pool_t *pool, ngx_str_t *str)
{
    ngx_str_t str_ret = {0, NULL};
    if (str->len == 0)
        return str_ret;
    size_t i = 0;
    u_char *data = ngx_palloc(pool, str->len);
    if (data == NULL)
        return str_ret;
    for (i = 0; i < str->len; i++)
    {
        if (str->data[i] < 'a')
        {
            data[i] = str->data[i] - 'A' + 'a';
        }
        else
            data[i] = str->data[i];
    }
    str_ret.data = data;
    str_ret.len = str->len;
    return str_ret;
}

ngx_list_t *ngx_kaze_heads_in_parser_args(ngx_http_request_t *r)
{
    ngx_list_t *ret_list = ngx_list_create(r->pool, 5, sizeof(ngx_table_elt_t));
    if (ret_list == NULL)
        return NULL;
    ngx_str_t line = r->args;
    if (line.len == 0)
        return ret_list;
    ngx_str_t key, val;
    size_t begin = 0, end = 0, h_end = line.len;
    end = ngx_kaze_str_rfind(&line, '=');
    while (end != line.len)
    {
        ngx_table_elt_t *item = ngx_list_push(ret_list);
        if (item == NULL)
            return NULL;
        if ((begin = ngx_kaze_str_rfind_start(&line, '&', end)) == line.len)
            begin = 0;
        else
            begin += 1;
        key.data = &line.data[begin];
        key.len = end - begin;
        val.data = &line.data[end + 1];
        val.len = h_end - end - 1;
        end = ngx_kaze_str_rfind_start(&line, '=', begin - 1);
        h_end = begin - 1;
        item->hash = 1;
        item->key = ngx_kaze_str_url_decode(r->pool, &key);
        item->value = ngx_kaze_str_url_decode(r->pool, &val);
        item->lowcase_key = NULL;
    }
    return ret_list;
}

/*
RFC3986文档规定，Url中只允许包含以下四种：

                   1、英文字母（a-zA-Z）

                   2、数字（0-9）

                   3、-_.~ 4个特殊字符

                   4、所有保留字符，RFC3986中指定了以下字符为保留字符（英文字符）：     ! * ' ( ) ; : @ & = + $ , / ? # [ ]

字符    -    URL编码值

空格    -    %20 （URL中的空格可以用+号或者编码值表示）
"          -    %22
#         -    %23
%        -    %25
&         -    %26
(          -    %28
)          -    %29
+         -    %2B
,          -    %2C
/          -    %2F
:          -    %3A
;          -    %3B
<         -    %3C
=         -    %3D
>         -    %3E
?         -    %3F
@       -    %40
\          -    %5C
|          -    %7C

{          -    %7B

}          -    %7D
*/
ngx_str_t ngx_kaze_str_url_decode(ngx_pool_t *pool, ngx_str_t *in)
{
    ngx_str_t ret = {0, NULL};
    u_char *data = ngx_palloc(pool, in->len);
    u_char val[2];
    if (data == NULL)
        return ret;
    size_t pos_a = 0, pos_b = 0, pos_val = 0;
    ngx_uint_t isTrans = 0;
    while (pos_a != in->len)
    {
        if (isTrans)
        {
            if (in->data[pos_a] < '0' || (in->data[pos_a] > '9' && in->data[pos_a] < 'A') || (in->data[pos_a] > 'F' && in->data[pos_a] < 'a') || in->data[pos_a] > 'f')
            {
                data[pos_b++] = '%';
                if (pos_val == 1)
                    data[pos_b++] = val[0];
                data[pos_b++] = in->data[pos_a++];
                isTrans = 0;
                pos_val = 0;
                continue;
            }
            val[pos_val] = in->data[pos_a];
            if (val[pos_val] >= 'a')
            {
                val[pos_val] = val[pos_val] - 'a' + 'A';
            }
            pos_val++;
            if (pos_val == 2)
            {
                switch (val[0])
                {
                case '2':
                    switch (val[1])
                    {
                    case '0':
                        data[pos_b] = ' ';
                        break;
                    case '2':
                        data[pos_b] = '"';
                        break;
                    case '3':
                        data[pos_b] = '#';
                        break;
                    case '5':
                        data[pos_b] = '%';
                        break;
                    case '6':
                        data[pos_b] = '&';
                        break;
                    case '8':
                        data[pos_b] = '(';
                        break;
                    case '9':
                        data[pos_b] = ')';
                        break;
                    case 'B':
                        data[pos_b] = '+';
                        break;
                    case 'C':
                        data[pos_b] = ',';
                        break;
                    case 'F':
                        data[pos_b] = '/';
                        break;
                    default:
                        data[pos_b] = toHex(val);
                        break;
                    }
                    break;
                case '3':
                    switch (val[1])
                    {
                    case 'A':
                        data[pos_b] = ':';
                        break;
                    case 'B':
                        data[pos_b] = ';';
                        break;
                    case 'C':
                        data[pos_b] = '<';
                        break;
                    case 'D':
                        data[pos_b] = '=';
                        break;
                    case 'E':
                        data[pos_b] = '>';
                        break;
                    case 'F':
                        data[pos_b] = '?';
                        break;
                    default:
                        data[pos_b] = toHex(val);
                        break;
                    }
                    break;
                case '4':
                    switch (val[1])
                    {
                    case '0':
                        data[pos_b] = '@';
                        break;
                    default:
                        data[pos_b] = toHex(val);
                        break;
                    }
                    break;
                case '5':
                    switch (val[1])
                    {
                    case 'C':
                        data[pos_b] = '\\';
                        break;
                    default:
                        data[pos_b] = toHex(val);
                        break;
                    }
                    break;
                case '7':
                    switch (val[1])
                    {
                    case 'C':
                        data[pos_b] = '|';
                        break;
                    case 'B':
                        data[pos_b] = '{';
                        break;
                    case 'D':
                        data[pos_b] = '}';
                        break;
                    default:
                        data[pos_b] = toHex(val);
                        break;
                    }
                    break;
                default:
                    data[pos_b] = toHex(val);
                    break;
                }
                pos_val = 0;
                isTrans = 0;
                pos_b++;
            }
        }
        else
        {
            if (in->data[pos_a] == '%')
                isTrans = 1;
            else if (in->data[pos_a] == '+')
                data[pos_b] = ' ', pos_b++;
            else
                data[pos_b] = in->data[pos_a], pos_b++;
        }
        pos_a++;
    }
    ret.data = data;
    ret.len = pos_b;
    return ret;
}

ngx_str_t ngx_kaze_list_find_key(ngx_list_t *list, ngx_str_t *key)
{
    ngx_str_t ret = ngx_null_string;
    ngx_uint_t i = 0;
    ngx_list_part_t *start = &list->part;
    while (1)
    {
        ngx_table_elt_t *tmp = start->elts;
        for (i = 0; i < start->nelts; i++)
        {
            if (ngx_kaze_str_cmp(&tmp[i].key, key) == 0)
                return tmp[i].value;
        }
        if (!(start->next))
            break;
        else
            start = start->next;
    }
    return ret;
}

ngx_str_t ngx_kaze_list_find_key_chr(ngx_list_t *list, char *key)
{
    ngx_str_t ret = ngx_null_string;
    ngx_uint_t i = 0;
    ngx_list_part_t *start = &list->part;
    while (1)
    {
        ngx_table_elt_t *tmp = start->elts;
        for (i = 0; i < start->nelts; i++)
        {
            if (ngx_kaze_str_cmp_chr(&tmp[i].key, key) == 0)
                return tmp[i].value;
        }
        if (!(start->next))
            break;
        else
            start = start->next;
    }
    return ret;
}

ngx_str_t ngx_kaze_heads_host(ngx_http_request_t *r)
{
    ngx_str_t host = r->headers_in.host->value;
    size_t pt = ngx_kaze_str_rfind(&host, ':');
    if (pt != host.len)
        host.len = pt;
    return host;
}

ngx_str_t ngx_kaze_heads_url(ngx_http_request_t *r)
{
    ngx_str_t uri = ngx_kaze_heads_uri(r),
              host = ngx_kaze_heads_host(r);
    return ngx_kaze_str_cat(r->connection->pool, &host, &uri);
}

ngx_int_t ngx_kaze_out_str(ngx_http_request_t *r, ngx_chain_t *out, ngx_str_t *str)
{
    r->headers_out.content_length_n = str->len;
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, str->len);
    if (b == NULL)
        return NGX_ERROR;
    ngx_memcpy(b->pos, str->data, str->len);
    b->last = b->pos + str->len;
    b->last_buf = 1;
    out->buf = b;
    out->next = NULL;
    return NGX_OK;
}

u_char *ngx_kaze_stoc(ngx_pool_t *pool, ngx_str_t *str)
{
    u_char *ret = ngx_palloc(pool, str->len + 1);
    if (ret == NULL)
        return NULL;
    ngx_memcpy(ret, str->data, str->len);
    ret[str->len] = 0;
    return ret;
}

ngx_str_t ngx_kaze_ctos(ngx_pool_t *pool, const u_char *str)
{
    ngx_str_t ret = {0, NULL};
    if (str == NULL)
        return ret;
    u_char *data = ngx_palloc(pool, strlen((const char *)str));
    if (data == NULL)
        return ret;
    ngx_memcpy(data, str, strlen((const char *)str));
    ret.data = data;
    ret.len = strlen((const char *)str);
    return ret;
}

ngx_str_t ngx_kaze_find_replace(ngx_pool_t *pool, ngx_str_t *str, char a, char b, ngx_uint_t end)
{
    ngx_str_t ret = {0, NULL};
    size_t n = 0, i = 0, len = 0;
    for (i = 0; i < str->len; i++)
    {
        if (str->data[i] == b)
            n++;
    }
    len = str->len + n + (end ? 1 : 0);
    u_char *data = ngx_palloc(pool, len);
    if (data == NULL)
        return ret;
    for (i = 0, len = 0; i < str->len; i++)
    {
        if (str->data[i] == b)
        {
            data[len++] = b;
            data[len++] = b;
        }
        else if (str->data[i] == a)
            data[len++] = b;
        else
            data[len++] = str->data[i];
    }
    if (end)
        data[len] = 0;
    len--;
    ret.data = data;
    ret.len = len;
    return ret;
}

ngx_int_t ngx_kaze_rand_str(size_t length, char *buf, ngx_uint_t end)
{
    size_t i = 0;
    char t;
    while (i != length)
    {
        t = rand() % 62;
        if (t < 26)
        {
            buf[i] = t + 'A';
        }
        else if (t < 52)
        {
            buf[i] = t - 26 + 'a';
        }
        else
            buf[i] = t - 52 + '0';
        i++;
    }
    if (end)
        buf[i] = 0;
    return NGX_OK;
}

ngx_str_t ngx_str_set_fmt(ngx_pool_t *pool, size_t max_buf, const char *fmt, ...)
{
    ngx_str_t ret;
    char vals[max_buf];
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
                if (fmt[pos] == 'c')
                {
                    sprintf(&vals[j], tmp_f, va_arg(list, int));
                }
                else
                {
                    sprintf(&vals[j], tmp_f, va_arg(list, char *));
                }
                j = strlen(vals);
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
    va_end(list);
    u_char *data = ngx_palloc(pool, j);
    if (data == NULL)
        return ret;
    ngx_memcpy(data, vals, j);
    ret.data = data;
    ret.len = j;
    return ret;
}

size_t ngx_kaze_str_find_str_start(ngx_str_t *src, ngx_str_t *tar, size_t start)
{
    if (start >= src->len || src->len - start < tar->len)
        return src->len;
    int next[tar->len];
    size_t pos = 0, i = 0, j = 0, k = 0;
    for (; pos < tar->len; pos++)
    {
        for (k = 1; k <= pos; k++)
        {
            for (i = k, j = 0; i < pos; i++, j++)
            {
                if (tar->data[i] != tar->data[j])
                {
                    next[pos] = next[j];
                    break;
                }
            }
            if (i == pos)
            {
                if (tar->data[i] != tar->data[j])
                {
                    next[pos] = j;
                    break;
                }
            }
        }
        if (k > pos)
        {
            next[pos] = -1;
        }
    }
    i = start, j = 0;
    for (; i < src->len && j < tar->len;)
    {
        if (src->data[i] != tar->data[j])
        {
            if (next[j] == -1)
            {
                i++, j = 0;
            }
            else
            {
                j = next[j];
            }
        }
        else
            i++, j++;
    }
    if (j == tar->len)
        return i - tar->len;
    return i;
}

size_t ngx_kaze_str_rfind_str_start(ngx_str_t *src, ngx_str_t *tar, size_t start)
{
    if (start + 1 < tar->len)
        return src->len;
    int next[tar->len];
    size_t pos = tar->len - 1, i, j, k;
    for (; pos > 0; pos--)
    {
        if (pos == tar->len - 1)
        {
            next[pos] = -1;
            continue;
        }
        for (k = tar->len - 2; k > pos; k--)
        {
            for (i = k, j = tar->len - 1; i > pos; i--, j--)
            {
                if (tar->data[i] != tar->data[j])
                {
                    next[pos] = next[j];
                    break;
                }
            }
            if (i == pos)
            {
                if (tar->data[i] != tar->data[j])
                {
                    next[pos] = j;
                    break;
                }
            }
        }
        if (k == pos)
        {
            if (tar->data[pos] != tar->data[tar->len - 1])
            {
                next[pos] = tar->len - 1;
            }
            else
                next[pos] = -1;
        }
    }
    for (k = tar->len - 2; k > pos; k--)
    {
        for (i = k, j = tar->len - 1; i > pos; i--, j--)
        {
            if (tar->data[i] != tar->data[j])
            {
                next[pos] = next[j];
                break;
            }
        }
        if (i == pos)
        {
            if (tar->data[i] != tar->data[j])
            {
                next[pos] = j;
                break;
            }
        }
    }
    if (k == pos)
    {
        if (tar->data[pos] != tar->data[tar->len - 1])
        {
            next[pos] = tar->len - 1;
        }
        else
            next[pos] = -1;
    }
    i = start, j = tar->len - 1;
    for (;;)
    {
        if (src->data[i] != tar->data[j])
        {
            if (i == 0)
                return src->len;
            if (next[j] == -1)
            {
                i--, j = tar->len - 1;
            }
            else
            {
                j = next[j];
            }
        }
        else if (j == 0)
            return i;
        else if (i == 0)
            return src->len;
        else
            i--, j--;
    }
}

ngx_str_t ngx_kaze_heads_all(ngx_http_request_t *r)
{
    ngx_str_t head = {r->header_in->end - r->header_in->start, r->header_in->start},
              tar = ngx_string("Connection"),
              end = ngx_string("\n\r\n"), re = ngx_null_string;
    size_t pos = ngx_kaze_str_find_str_start(&head, &tar, 0);
    size_t end_pos = ngx_kaze_str_find_str_start(&head, &end, pos);
    if (pos == head.len || end_pos == head.len)
        return re;
    re.data = head.data + pos;
    re.len = end_pos - pos;
    return re;
}