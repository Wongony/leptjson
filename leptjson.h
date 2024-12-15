#ifndef LEPTJSON_H
#define LEPTJSON_H

#include <stddef.h>

typedef enum {
    LEPT_NULL = 0,
    LEPT_FALSE = 1,
    LEPT_TRUE = 2,
    LEPT_NUMBER = 3,
    LEPT_STRING = 4,
    LEPT_ARRAY = 5,
    LEPT_OBJECT = 6,
} lept_type;

typedef struct {
    union {
        struct { char* s; size_t len; }s;
        double n;
    };
    lept_type type;
} lept_value;

enum {
    LEPT_PARSE_OK = 0,
    LEPT_PARSE_EXPECT_VALUE = 1,
    LEPT_PARSE_INVALID_VALUE = 2,
    LEPT_PARSE_ROOT_NOT_SINGULAR = 3,
    LEPT_PARSE_NUMBER_TOO_BIG = 4,
    LEPT_PARSE_MISS_QUOTATION_MARK = 5,
    LEPT_PARSE_INVALID_STRING_ESCAPE = 6,
    LEPT_PARSE_INVALID_STRING_CHAR = 7,
};

#define lept_init(v) do { (v)->type = LEPT_NULL; } while(0)
#define lept_set_null(v) lept_free(v);

void lept_free(lept_value* v);

int lept_parse(lept_value* v, const char* json);

lept_type lept_get_type(const lept_value* v);

int lept_get_boolean(const lept_value* v);
void lept_set_boolean(lept_value* v, int b);

double lept_get_number(const lept_value* v);
void lept_set_number(lept_value* v, double n);

const char* lept_get_string(const lept_value* v);
size_t lept_get_string_length(const lept_value* v);
void lept_set_string(lept_value* v, const char* s, size_t len);

#endif