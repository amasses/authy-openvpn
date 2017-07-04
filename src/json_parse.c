#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include "vendor/json-parser/json.h"
#include "json_parse.h"

// int main() {
//  char *reqResponse = "{\"approval_request\":{\"uuid\":\"c0b21060-425d-0135-1824-1226b57fac04\"},\"success\":true}";

//  char* guid = NULL;
//  guid = getUUID((json_char*)reqResponse);

//  printf("GUid: %s", guid);

// }

char* getUUID(json_char *json)
{
    json_value *parsed;
    char *guid;
    char *result;

    parsed = json_parse(json, strlen(json));

    if (parsed == NULL) {
      fprintf(stdout, "Unable to parse JSON\n");
      return NULL;
    }

    if (get_json_boolean(parsed, "success")) {
      printf("Successful request\n");
      json_value *approval_request;
      approval_request = get_json_object(parsed, "approval_request");
      guid = get_json_string(approval_request, "uuid");
      result = calloc(strlen(guid), sizeof(char));
      strcpy(result, guid);
    }

    json_value_free(parsed);
    return result;
}

char* get_json_string(json_value* value, char* name) {
  int length, x;
  char *str;

  if (value == NULL) {
    printf("Value is null!\n");
    return NULL;
  }

  length = value->u.object.length;
  for (x = 0; x < length; x++) {
    json_object_entry v;
    v = value->u.object.values[x];
    if (strcmp(value->u.object.values[x].name, name) == 0) {
      json_value *val;
      val = value->u.object.values[x].value;
      str = val->u.string.ptr;
    } 
  }

  return str;
}

json_value* get_json_object(json_value* value, char* name) {
  int length, x;
  json_value *val;

  length = value->u.object.length;
  for (x = 0; x < length; x++) {
    if (strcmp(value->u.object.values[x].name, name) == 0) {
      val = value->u.object.values[x].value;
    } 
  }

  return val;
}

BOOL get_json_boolean(json_value* value, char* name) {
  int length, x;
  length = value->u.object.length;
  for (x = 0; x < length; x++) {
    if (strcmp(value->u.object.values[x].name, name)) {
      return value->u.object.values[x].value->u.boolean;
    } 
  }

  return 0;
}
