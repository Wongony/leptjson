#include "leptjson.h"
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <string.h>
#include <stdio.h>

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#ifndef LEPT_PARSE_STRINGIFY_INIT_SIZE
#define LEPT_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define EXPECT(c, ch) do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch) ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch) ((ch) >= '1' && (ch) <= '9')
#define PUTC(c, ch) do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)
#define PUTS(c, s, len) do { memcpy(lept_context_push(c, len), s, len); } while(0)
#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

typedef struct {
    const char* json;
    char* stack;
    size_t size, top;
}lept_context;

void lept_free(lept_value* v)
{
    size_t i;
    assert(v != NULL);
    switch (v->type)
    {
        case LEPT_STRING:
            free(v->s.s);
            break;
        case LEPT_ARRAY:
            for (i = 0; i < v->a.size; ++i)
                lept_free(&v->a.e[i]);
            free(v->a.e);
            break;
        case LEPT_OBJECT:
            for (i = 0; i < v->o.size; ++i) {
                lept_free(&v->o.m[i].v);
                free(v->o.m[i].k);
            }
            free(v->o.m);
            break;
        default:break;

    }
    v->type = LEPT_NULL;
}

static void* lept_context_push(lept_context* c, size_t size)
{
    void* ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0)
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        while (c->top + size >= c->size)
            c->size += c->size >> 1;
        c->stack = (char*)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void* lept_context_pop(lept_context* c, size_t size)
{
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

static void lept_parse_whitespace(lept_context* c) {
    const char* p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        ++p;
    c->json = p;
}

static int lept_parse_literal(lept_context* c,
                              lept_value* v,
                              const char* literal,
                              lept_type type)
{
    size_t i;
    EXPECT(c, literal[0]);
    for (i = 0; literal[i+1]; i++)
        if (c->json[i] != literal[i+1])
            return LEPT_PARSE_INVALID_VALUE;
    c->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context* c, lept_value* v)
{
    const char* p = c->json;
    if (*p == '-') ++p;
    if (*p =='0') ++p;
    else {
        if (!ISDIGIT1TO9(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    if (*p == '.') {
        ++p;
        if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }

    errno = 0;
    v->n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL))
        return LEPT_PARSE_NUMBER_TOO_BIG;

    c->json = p;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

static const char* lept_parse_hex4(const char* p, unsigned* u)
{
    int i;
    *u = 0;
    for (i = 0; i < 4; i++) {
        char ch = *p++;
        *u <<= 4;
        if (ch >= '0' && ch <= '9') *u |= ch - '0';
        else if (ch >= 'A' && ch <= 'F') *u |= ch - 'A' + 10;
        else if (ch >= 'a' && ch <= 'f') *u |= ch - 'a' + 10;
        else return NULL;
    }
    return p;
}

static void lept_encode_utf8(lept_context* c, unsigned u)
{
    if (u <= 0x7F)
        PUTC(c, u & 0xFF);
    else if (u <= 0x7FF) {
        PUTC(c, 0xC0 | ((u>>6) & 0xFF));
        PUTC(c, 0x80 | (u & 0x3F));
    }
    else if (u <= 0xFFFF) {
        PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
        PUTC(c, 0x80 | ((u >> 6) & 0x3F));
        PUTC(c, 0x80 | (u & 0x3F));
    }
    else {
        assert(u <= 0X10FFFF);
        PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >> 6) & 0x3F));
        PUTC(c, 0x80 | (u & 0x3F));
    }
}

static int lept_parse_string_raw(lept_context* c, char** str, size_t* len)
{
    size_t head = c->top;
    unsigned u, u2;
    const char* p;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch)
        {
            case '\\':
                switch (*p++)
                {
                    case '\"': PUTC(c, '\"'); break;
                    case '\\': PUTC(c, '\\'); break;
                    case '/': PUTC(c, '/'); break;
                    case 'b': PUTC(c, '\b'); break;
                    case 'f': PUTC(c, '\f'); break;
                    case 'n': PUTC(c, '\n'); break;
                    case 'r': PUTC(c, '\r'); break;
                    case 't': PUTC(c, '\t'); break;
                    case 'u':
                        if (!(p = lept_parse_hex4(p, &u)))
                            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                        if (u >= 0xD800 && u <= 0xDBFF) {
                            if (*p++ != '\\')
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            if (*p++ != 'u')
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            if (!(p = lept_parse_hex4(p, &u2)))
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                            if (u2 < 0xDC00 || u2 > 0xDFFF)
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            u = (((u-0xD800)<<10) | (u2-0xDC00)) + 0x10000;
                        }
                        lept_encode_utf8(c, u);
                        break;
                    default:
                        STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            case '\"':
                *len = c->top - head;
                *str = lept_context_pop(c, *len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\0':
                STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
            default:
                if ((unsigned char)ch < 0x20)
                    STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
                PUTC(c, ch);
        }
    }
}

static int lept_parse_string(lept_context* c, lept_value* v)
{
    int ret;
    char* s;
    size_t len;
    if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK)
        lept_set_string(v, s, len);
    return ret;
}

static int lept_parse_value(lept_context* c, lept_value* v);

static int lept_parse_array(lept_context* c, lept_value* v)
{
    size_t size = 0, i;
    int ret;
    EXPECT(c, '[');
    lept_parse_whitespace(c);
    if (*c->json == ']') {
        c->json++;
        lept_set_array(v, 0);
        return LEPT_PARSE_OK;
    }
    for (;;) {
        lept_value e;
        lept_init(&e);
        if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK)
            break;
        memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
        size++;
        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        }
        else if (*c->json == ']') {
            c->json++;
            lept_set_array(v, size);
            v->a.size = size;
            size *= sizeof(v->a.e[0]);
            memcpy(v->a.e, lept_context_pop(c, size), size);
            return LEPT_PARSE_OK;
        }
        else {
            ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }
    for (i = 0; i < size; ++i)
        lept_free((lept_value*)lept_context_pop(c, sizeof(lept_value)));
    return ret;
}

static int lept_parse_object(lept_context* c, lept_value* v)
{
    size_t size = 0, i;
    lept_member m;
    int ret;
    EXPECT(c, '{');
    lept_parse_whitespace(c);
    if (*c->json == '}') {
        c->json++;
        lept_set_object(v, 0);
        return LEPT_PARSE_OK;
    }
    m.k = NULL;
    for (;;) {
        char* str;
        lept_init(&m.v);
        if (*c->json != '"') {
            ret = LEPT_PARSE_MISS_KEY;
            break;
        }
        if ((ret = lept_parse_string_raw(c, &str, &m.klen)) != LEPT_PARSE_OK)
            break;
        memcpy(m.k=(char*)malloc(m.klen+1), str, m.klen);
        m.k[m.klen] = '\0';
        lept_parse_whitespace(c);
        if (*c->json != ':') {
            ret = LEPT_PARSE_MISS_COLON;
            break;
        }
        c->json++;
        lept_parse_whitespace(c);
        if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK) {
            break;
        }
        memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
        size++;
        m.k = NULL;

        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        }
        else if (*c->json == '}') {
            c->json++;
            lept_set_object(v, size);
            v->o.size = size;
            size *= sizeof(v->o.m[0]);
            memcpy(v->o.m, lept_context_pop(c, size), size);
            return LEPT_PARSE_OK;
        }
        else {
            ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }
    free(m.k);
    for (i = 0; i < size; ++i) {
        lept_member* gc = (lept_member*)lept_context_pop(c, sizeof(lept_member));
        free(gc->k);
        gc->klen = 0;
        lept_free(&gc->v);
    }
    return ret;
}

static int lept_parse_value(lept_context* c, lept_value* v)
{
    switch (*c->json)
    {
        case 't': return lept_parse_literal(c, v, "true", LEPT_TRUE);
        case 'f': return lept_parse_literal(c, v, "false", LEPT_FALSE);
        case 'n': return lept_parse_literal(c, v, "null", LEPT_NULL);
        case '"': return lept_parse_string(c, v);
        case '[': return lept_parse_array(c, v);
        case '{': return lept_parse_object(c, v);
        default: return lept_parse_number(c, v);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
    }
}

int lept_parse(lept_value* v, const char* json)
{
    lept_context c;
    int ret = 0;
    assert(v != NULL);
    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
    lept_init(v);
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

#if 0
static void lept_stringify_string(lept_context* c, const char* s, size_t len)
{
    size_t i;
    assert(s != NULL);
    PUTC(c, '"');
    for (i = 0; i < len; ++i) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch)
        {
            case '\"': PUTS(c, "\\\"", 2); break;
            case '\\': PUTS(c, "\\\\", 2); break;
            case '\b': PUTS(c, "\\b", 2); break;
            case '\f': PUTS(c, "\\f", 2); break;
            case '\n': PUTS(c, "\\n", 2); break;
            case '\r': PUTS(c, "\\r", 2); break;
            case '\t': PUTS(c, "\\t", 2); break;
            default:
                if (ch < 0x20) {
                    char buffer[7] = {0};
                    snprintf(buffer, sizeof(buffer), "\\u%04X", ch);
                    PUTS(c, buffer, 6);
                }
                else {
                    PUTC(c, s[i]);
                }
        }
    }
    PUTC(c, '"');
}
#else
static void lept_stringify_string(lept_context* c, const char* s, size_t len)
{
    static const char hex_digits[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    size_t i, size;
    char *head, *p;
    assert(s != NULL);
    p = head = lept_context_push(c, size = len*6+2);
    *p++ = '"';
    for (i = 0; i < len; ++i) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch)
        {
            case '\"': *p++ = '\\'; *p++ = '\"'; break;
            case '\\': *p++ = '\\'; *p++ = '\\'; break;
            case '\b': *p++ = '\\'; *p++ = 'b'; break;
            case '\f': *p++ = '\\'; *p++ = 'f'; break;
            case '\n': *p++ = '\\'; *p++ = 'n'; break;
            case '\r': *p++ = '\\'; *p++ = 'r'; break;
            case '\t': *p++ = '\\'; *p++ = 't'; break;
            default:
                if (ch < 0x20) {
                    *p++ = '\\'; *p++ = 'u'; *p++ = '0'; *p++ = '0';
                    *p++ = hex_digits[(ch>>4)&0xF];
                    *p++ = hex_digits[ch&0xF];
                }
                else *p++ = s[i];
        }
    }
    *p++ = '"';
    c->top -= size - (p - head);
}
#endif

static void lept_stringify_value(lept_context* c, const lept_value* v)
{
    size_t i;
    switch (v->type)
    {
        case LEPT_NULL: PUTS(c, "null", 4); break;
        case LEPT_FALSE: PUTS(c, "false", 5); break;
        case LEPT_TRUE: PUTS(c, "true", 4); break;
        case LEPT_NUMBER:
        {
            char* buffer = lept_context_push(c, 32);
            int length = snprintf(buffer, 32, "%.17g", v->n);
            c->top -= 32 - length;
        }
        break;
        case LEPT_STRING: lept_stringify_string(c, v->s.s, v->s.len); break;
        case LEPT_ARRAY:
        {
            PUTC(c, '[');
            for (i = 0; i < v->a.size; ++i) {
                if (i > 0) PUTC(c, ',');
                lept_stringify_value(c, &v->a.e[i]);
            }
            PUTC(c, ']');
        }
        break;
        case LEPT_OBJECT:
        {
            PUTC(c, '{');
            for (i = 0; i < v->o.size; ++i) {
                if (i > 0) PUTC(c, ',');
                lept_stringify_string(c, v->o.m[i].k, v->o.m[i].klen);
                PUTC(c, ':');
                lept_stringify_value(c, &v->o.m[i].v);
            }
            PUTC(c, '}');
        }
        break;
        default: assert(0 && "invalid type");
    }
}

char* lept_stringify(const lept_value* v, size_t* length)
{
    lept_context c;
    assert(v != NULL);
    c.stack = (char*)malloc(c.size = LEPT_PARSE_STRINGIFY_INIT_SIZE);
    c.top = 0;
    lept_stringify_value(&c, v);
    if (length)
        *length = c.top;
    PUTC(&c, '\0');
    return c.stack;
}

int lept_is_equal(const lept_value* lhs, const lept_value* rhs)
{
    size_t i;
    assert(lhs != NULL && rhs != NULL);
    if (lhs->type != rhs->type)
        return 0;
    switch (lhs->type)
    {
        case LEPT_NUMBER:
            return lhs->n == rhs->n;
        case LEPT_STRING:
            return lhs->s.len == rhs->s.len && memcmp(lhs->s.s, rhs->s.s, lhs->s.len) == 0;
        case LEPT_ARRAY:
            if (lhs->a.size != rhs->a.size)
                return 0;
            for (i = 0; i < lhs->a.size; ++i)
                if (!lept_is_equal(&lhs->a.e[i], &rhs->a.e[i]))
                    return 0;
            return 1;
        case LEPT_OBJECT:
            if (lhs->o.size != rhs->o.size)
                return 0;
            for (i = 0; i < lhs->o.size; ++i) {
                lept_value* r_v = lept_find_object_value(rhs, lhs->o.m[i].k, lhs->o.m[i].klen);
                if (!lept_is_equal(&lhs->o.m[i].v, r_v))
                    return 0;
            }
            return 1;
        default:
            return 1;
    }
}

void lept_copy(lept_value* dst, const lept_value* src)
{
    size_t i;
    assert(src != NULL && dst != NULL && src != dst);
    switch (src->type)
    {
        case LEPT_STRING:
            lept_set_string(dst, src->s.s, src->s.len);
            break;
        case LEPT_ARRAY:
            lept_free(dst);
            lept_set_array(dst, src->a.size);
            dst->a.size = src->a.size;
            for (i = 0; i < src->a.size; ++i)
                lept_copy(&dst->a.e[i], &src->a.e[i]);
            break;
        case LEPT_OBJECT:
            lept_free(dst);
            lept_set_object(dst, src->o.size);
            dst->o.size = src->o.size;
            for (i = 0; i < src->o.size; ++i) {
                dst->o.m[i].klen = src->o.m[i].klen;
                dst->o.m[i].k = (char*)malloc(src->o.m[i].klen+1);
                memcpy(dst->o.m[i].k, src->o.m[i].k, src->o.m[i].klen);
                lept_copy(&dst->o.m[i].v, &src->o.m[i].v);
            }
            break;
        default:
            lept_free(dst);
            memcpy(dst, src, sizeof(lept_value));
            break;
    }
}

void lept_move(lept_value* dst, lept_value* src)
{
    assert(dst != NULL && src != NULL && dst != src);
    lept_free(dst);
    memcpy(dst, src, sizeof(lept_value));
    lept_init(src);
}

void lept_swap(lept_value* lhs, lept_value* rhs)
{
    assert(lhs != NULL && rhs != NULL);
    if (lhs != rhs) {
        lept_value temp;
        memcpy(&temp, lhs, sizeof(lept_value));
        memcpy(lhs, rhs, sizeof(lept_value));
        memcpy(rhs, &temp, sizeof(lept_value));
    }
}

lept_type lept_get_type(const lept_value* v)
{
    assert(v != NULL);
    return v->type;
}

int lept_get_boolean(const lept_value* v)
{
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value* v, int b)
{
    lept_free(v);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

double lept_get_number(const lept_value* v)
{
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->n;
}

void lept_set_number(lept_value* v, double n)
{
    lept_free(v);
    v->n = n;
    v->type = LEPT_NUMBER;
}

const char* lept_get_string(const lept_value* v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->s.s;
}

size_t lept_get_string_length(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->s.len;
}

void lept_set_string(lept_value* v, const char* s, size_t len)
{
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->s.s = (char*)malloc(len+1);
    memcpy(v->s.s, s, len);
    v->s.s[len] = '\0';
    v->s.len = len;
    v->type = LEPT_STRING;
}

void lept_set_array(lept_value* v, size_t capacity)
{
    assert(v != NULL);
    lept_free(v);
    v->type = LEPT_ARRAY;
    v->a.size = 0;
    v->a.capacity = capacity;
    v->a.e = (capacity>0) ? (lept_value*)malloc(capacity*sizeof(lept_value)) : NULL;
}

size_t lept_get_array_capacity(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->a.capacity;
}

void lept_reserve_array(lept_value* v, size_t capacity)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->a.capacity < capacity) {
        v->a.capacity = capacity;
        v->a.e = (lept_value*)realloc(v->a.e, capacity*sizeof(lept_value));
    }
}

void lept_shrink_array(lept_value* v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->a.capacity > v->a.size) {
        v->a.capacity = v->a.size;
        v->a.e = (lept_value*)realloc(v->a.e, v->a.capacity*sizeof(lept_value));
    }
}

lept_value* lept_pushback_array_element(lept_value* v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->a.size == v->a.capacity)
        lept_reserve_array(v, v->a.capacity==0?1:v->a.capacity*2);
    lept_init(&v->a.e[v->a.size]);
    return &v->a.e[v->a.size++];
}

void lept_popback_array_element(lept_value* v)
{
    assert(v != NULL && v->type == LEPT_ARRAY && v->a.size > 0);
    lept_free(&v->a.e[--v->a.size]);
}

lept_value* lept_insert_array_element(lept_value* v, size_t index)
{
    size_t i;
    assert(v != NULL && v->type == LEPT_ARRAY && index <= v->a.size);
    if (v->a.size == v->a.capacity)
        lept_reserve_array(v, v->a.capacity==0?1:v->a.capacity*2);
    lept_init(&v->a.e[v->a.size++]);
    for (i = v->a.size-1; i > index; --i) {
        lept_move(&v->a.e[i], &v->a.e[i-1]);
    }
    lept_init(&v->a.e[index]);
    return &v->a.e[index];
}

void lept_erase_array_element(lept_value* v, size_t index, size_t count)
{
    size_t i;
    assert(v != NULL && v->type == LEPT_ARRAY && index < v->a.size && index+count <= v->a.size);
    if (count == 0) return;
    for (i = index+count; i < v->a.size; ++i) {
        lept_move(&v->a.e[i-count], &v->a.e[i]);
    }
    v->a.size -= count;
}

void lept_clear_array(lept_value* v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    while (v->o.size > 0) {
        lept_free(&v->a.e[--v->a.size]);
    }
}

size_t lept_get_array_size(const lept_value* v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->a.size;
}

lept_value* lept_get_array_element(const lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->a.size);
    return &v->a.e[index];
}

void lept_set_object(lept_value* v, size_t capacity)
{
    assert(v != NULL);
    lept_free(v);
    v->type = LEPT_OBJECT;
    v->o.size = 0;
    v->o.capacity = capacity;
    v->o.m = (capacity>0) ? (lept_member*)malloc(capacity*sizeof(lept_member)) : NULL;
}

size_t lept_get_object_capacity(const lept_value* v)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->o.capacity;
}

void lept_reserve_object(lept_value* v, size_t capacity)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    if (v->o.capacity < capacity) {
        v->o.capacity = capacity;
        v->o.m = (lept_member*)realloc(v->o.m, capacity*sizeof(lept_member));
    }
}

void lept_shrink_object(lept_value* v)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    if (v->o.capacity > v->o.size) {
        v->o.capacity = v->o.size;
        v->o.m = (lept_member*)realloc(v->o.m, v->o.capacity*sizeof(lept_member));
    }
}

void lept_clear_object(lept_value* v)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    while (v->o.size > 0) {
        free(v->o.m[v->o.size-1].k);
        lept_free(&v->o.m[v->o.size-1].v);
        --v->o.size;
    }
}

lept_value* lept_set_object_value(lept_value* v, const char* key, size_t klen)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    lept_value* ret = lept_find_object_value(v, key, klen);
    if (ret != NULL) return ret;
    if (v->o.size >= v->o.capacity)
        lept_reserve_object(v, (v->o.capacity==0)?1:v->o.capacity*2);
    v->o.m[v->o.size].klen = klen;
    v->o.m[v->o.size].k = (char*)malloc(klen+1);
    memcpy(v->o.m[v->o.size].k, key, klen);
    lept_init(&v->o.m[v->o.size].v);
    return &v->o.m[v->o.size++].v;
}

void lept_remove_object_value(lept_value* v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT && index < v->o.size);
    free(v->o.m[index].k);
    v->o.m[index].k = v->o.m[v->o.size-1].k;
    v->o.m[index].klen = v->o.m[v->o.size-1].klen;
    v->o.m[v->o.size-1].k = NULL;
    v->o.m[v->o.size-1].klen = 0;
    lept_swap(&v->o.m[index].v, &v->o.m[v->o.size-1].v);
    lept_free(&v->o.m[v->o.size-1].v);
    v->o.size--;
}

size_t lept_get_object_size(const lept_value* v)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->o.size;
}

const char* lept_get_object_key(const lept_value* v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->o.size);
    assert(v->o.m[index].k != NULL && v->o.m[index].klen != 0);
    return v->o.m[index].k;
}

size_t lept_get_object_key_length(const lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->o.size);
    assert(v->o.m[index].k != NULL && v->o.m[index].klen != 0);
    return v->o.m[index].klen;
}

lept_value* lept_get_object_value(const lept_value* v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->o.size);
    return &v->o.m[index].v;
}

#define LEPT_KEY_NOT_EXIST ((size_t)-1)

size_t lept_find_object_index(const lept_value *v, const char *key, size_t klen)
{
    size_t i;
    assert(v != NULL && v->type == LEPT_OBJECT && key != NULL);
    for (i = 0; i < v->o.size; ++i)
        if (v->o.m[i].klen == klen && memcmp(v->o.m[i].k, key, klen) == 0)
            return i;
    return LEPT_KEY_NOT_EXIST;
}

lept_value* lept_find_object_value(const lept_value* v, const char *key, size_t klen)
{
    size_t index = lept_find_object_index(v, key, klen);
    return index != LEPT_KEY_NOT_EXIST ? &v->o.m[index].v : NULL;
}