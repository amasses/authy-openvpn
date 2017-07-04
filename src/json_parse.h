#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include "vendor/json-parser/json.h"

#define BOOL short // Boolean type.
#define TRUE 1
#define FALSE 0

char* getUUID(json_char *json);
void process_value(json_value* value, int depth);
BOOL get_json_boolean(json_value* value, char* name);
json_value* get_json_object(json_value* value, char* name);
char* get_json_string(json_value* value, char* name);
