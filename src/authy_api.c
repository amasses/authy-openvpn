//------------------------------------------------------------------------------
//
// Copyright (c) Authy Inc.
//
// Name
//
//   authy_api.c
//
// Abstract
//
// Implements the public Authy API using json. Uses CURL to do multi-platform HTTPS request.
//
// registerUser
// verifyToken
// requestSMS
//
//
//
// History
//
//  8/1/2013    dpalacio    Created
//
//------------------------------------------------------------------------------


#include <stdarg.h>
#include <curl/curl.h>
#include <assert.h>
#include "utils.h"
#include "logger.h"
#include "authy_api.h"
#include "constants.h"
#include "json_parse.h"

#ifdef WIN32
#define snprintf _snprintf
#endif


//
// Description
//
// Given the url, endpoint, params and keys, calculates the size
// of the URL
//
// Parameters
//
// pszApiUrl   - Server URL
// pszEndPoint - The API endpoint including format
// pszParams   - The endpoint params.
// pszApiKey   - The Authy API key.
//
// Returns
//
// The size of the URL to be allocated.
//
//

static size_t
calcUrlSize(const char *pszApiUrl,
            const char *pszEndPoint,
            const char *pszParams,
            const char *pszApiKey)
{
  return strlen(pszApiUrl) + strlen(pszEndPoint) + strlen(pszParams) + strlen(pszApiKey) + 1;
}

//
// Description
//
// Allocates the memory and build the URL of the enpoind including
// params.
//
// Parameters
//
// pResultUrl -  A pointer to the pointer were the URL will be stored.
// pszApiUrl   - Server URL
// pszEndPoint - The API endpoint including format
// pszParams   - The endpoint params.
// pszApiKey   - The Authy API key.
//
// Returns
//
// Standard RESULT
//
RESULT
buildUrl(__out char **ppszResultUrl,
         const char *pszApiUrl,
         const char *pszEndPoint,
         const char *pszParams,
         const char *pszApiKey)
{
  assert(ppszResultUrl != NULL);

  RESULT r = FAIL;

  size_t urlSize = calcUrlSize(pszApiUrl,
                               pszEndPoint,
                               pszParams,
                               pszApiKey);


  *ppszResultUrl = calloc(urlSize, sizeof(char));
  if(NULL == *ppszResultUrl){
    trace(ERROR, __LINE__, "[Authy] Out of Memory: Malloc failed.");
    r = OUT_OF_MEMORY;
    goto EXIT;
  }

  snprintf(*ppszResultUrl,
           urlSize,
           "%s%s%s%s",
           pszApiUrl, pszEndPoint, pszParams, pszApiKey);

  trace(DEBUG, __LINE__, "[Authy] buildUrl pszResultUrl=%s\n.", *ppszResultUrl);
  r = OK;

EXIT:
  return r;
}



//
// Description
//
// curl custom writer. Implements the prototype:
// prototype: size_t function( char *ptr, size_t size, size_t nmemb, void *userdata);
//
// Parameters
//
// ptr         - Rough data with size size * nmemb. Not zero terminated
// size        - size of each member of ptr
// nmemb       - number of members
// userdata    - pointer to were the date is written too. Max write is CURL_MAX_WRITE_SIZE
//               We allocate userdate 0 termited from the start.
//
// Returns
//
// Ammount of data that was written to userdata. Else curl will raise an
// error.
//
//
static size_t
curlWriter(char *ptr,
             size_t size,
             size_t nmemb,
             void *userdata)
{
  memcpy(userdata, ptr, (size_t) size * nmemb);
  return nmemb*size;
}

// Description
//
//  Goes through the response body looking for token validity.
//
// Parameters
//
//   pszRespone           - Response body in json format
//
// Returns
//
//   TRUE if the response body includes "token": "is valid", FALSE otherwise.
//
BOOL
tokenResponseIsValid(char *pszResponse)
{
  json_value *parsed;
  parsed = json_parse((json_char*)pszResponse, strlen(pszResponse));

  if (get_json_boolean(parsed, "success")) {
    json_value_free(parsed);
    return TRUE;
  }

  json_value_free(parsed);
	return FALSE;
}

char* getGuid(char *pszResponse) {
  json_value *parsed;
  char *guid;
  char *result;

  parsed = json_parse(pszResponse, strlen(pszResponse));
  if (get_json_boolean(parsed, "success")) {
    json_value *approval_request;
    approval_request = get_json_object(parsed, "approval_request");
    guid = get_json_string(approval_request, "uuid");
    result = calloc(strlen(guid), sizeof(char));
    strcpy(result, guid);
  }

  json_value_free(parsed);
  return result;
}

uint
tokenVerifyResponseIsValid(char *pszResponse, char *pszApprovalStatus)
{
  char *result;
  json_value *parsed;

  parsed = json_parse(pszResponse, strlen(pszResponse));
  if (get_json_boolean(parsed, "success")) {
    json_value *approval_request;
    approval_request = get_json_object(parsed, "approval_request");
    result = get_json_string(approval_request, "status");
    strcpy(pszApprovalStatus, result);
    
    if (strcmp(result, "approved") == 0) {
      json_value_free(parsed);
      return 0;
    } else if(strcmp(result, "denied") == 0 || strcmp(result, "expired") == 0) {
      json_value_free(parsed);
      return 1;
    }
  }

  json_value_free(parsed);
  return -1;
}

//
// Description
//
// Handles the http request to the api
// it knows when to do a GET or a POST based
// on the present of pszPostFields
//
// Parameters
//
// pszResultUrl         - The full URL
// pszPostFields  - POST fields if it's a POST request or NULL for GET request
// pszEndPoint - The API endpoint including format
// pszParams   - The endpoint params.
// pszApiKey   - The Authy API key.
//
// Returns
//
// Standard RESULT
//
RESULT
doHttpRequest(char *pszResultUrl, char *pszPostFields, char *pszResponse)
{
  RESULT r = FAIL;
  CURL *pCurl = NULL;
  int curlResult = -1;
  char *pszUserAgent = NULL;
  struct curl_slist *headers = NULL;

  pszUserAgent = getUserAgent();
  if(NULL == pszUserAgent)
  {
    trace(ERROR, __LINE__, "[Authy] Cannot get user agent. Setting user agent to unkown.");

    pszUserAgent = calloc(strlen(UNKNOWN_VERSION_AGENT) + 1, sizeof(char));
    if(pszUserAgent == NULL)
    {
      trace(ERROR, __LINE__, "[Authy] Failed to set user agent. Could not allocate memory for user agent.");
      goto EXIT;
    }
    pszUserAgent = strncpy(pszUserAgent, UNKNOWN_VERSION_AGENT, strlen(UNKNOWN_VERSION_AGENT));
  }

  curl_global_init(CURL_GLOBAL_ALL);

  pCurl = curl_easy_init();
  if(!pCurl){
    r = FAIL;
    trace(ERROR, __LINE__, "[Authy] CURL failed to initialize");
    goto EXIT;
  }

  curl_easy_setopt(pCurl, CURLOPT_URL, pszResultUrl);

  if(pszPostFields) // POST REQUEST
  {
    curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, pszPostFields);
  }

#ifdef WIN32
  curl_easy_setopt(p_curl, CURLOPT_CAINFO, "curl-bundle-ca.crt");
#endif

  headers = curl_slist_append(headers, "Connection: close");
  curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, headers);

  curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 1L); //verify PEER certificate
  curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 2L); //verify HOST certificate
  curl_easy_setopt(pCurl, CURLOPT_VERBOSE, 0L);
  curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, curlWriter);
  curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, pszResponse);
  curl_easy_setopt(pCurl, CURLOPT_USERAGENT, pszUserAgent);

  curlResult = (int) curl_easy_perform(pCurl);
  if(0 != curlResult) {
    trace(ERROR, __LINE__, "Curl failed with code %d", curlResult);
    r = FAIL;
    goto EXIT;
  }

  trace(DEBUG, __LINE__, "[Authy] Curl response: Body=%s\n", pszResponse);

  r = OK;

EXIT:
  if(pszUserAgent)
  {
    free(pszUserAgent);
  }

#ifdef WIN32
  trace(DEBUG, __LINE__, "[Authy] Can't clean curl, curl easy cleanup doesn't work on Windows");
#else
  if(pCurl){
    curl_easy_cleanup(pCurl);
    curl_slist_free_all(headers);
  }
#endif

  return r;
}

//
// Description
//
// Calls the new user Authy API API
//
// Parameters
//
// pszApiUrl    - The server URL
// pszPostFields  - POST fields if it's a POST request
// pszEndPoint - The API endpoint including format
// pszParams   - The endpoint params.
// pszApiKey   - The Authy API key.
//
// Returns
//
// Standard RESULT
//
extern RESULT
registerUser(const char *pszApiUrl,
              char *pszPostFields,
              const char *pszApiKey,
              char *pszResponse)
{
  int r = FAIL;
  char *pszResultUrl = NULL;
  char *pszEndPoint = "/users/new";
  char *pszParams = "?api_key=";

  r = buildUrl(&pszResultUrl,
               pszApiUrl,
               pszEndPoint,
               pszParams,
               pszApiKey);

  if(FAILED(r)){
    goto EXIT;
  }

  r = doHttpRequest(pszResultUrl, pszPostFields, pszResponse);

  // Clean memory used in the request
  cleanAndFree(pszResultUrl);
  pszResultUrl = NULL;

  if(FAILED(r)){
    trace(ERROR, __LINE__, "[Authy] User Registration Failed\n");
    goto EXIT;
  }

  r = OK;

EXIT:
  return r;
}

extern RESULT
requestOnetouch(const char *pszApiUrl,
            char *pszAuthyId,
            const char *pszApiKey,
            char *pszResponse) {
              
  RESULT r = FAIL;
  size_t endPointSize = 0;
  char *pszRequestUrl = NULL;
  char *pszEndPoint = NULL;
  char *pszNullPost = "";
  char *pszParams = "?seconds_to_expire=60&message=Please+Authorize+VPN+Access&api_key=";

  endPointSize = strlen("/onetouch/json/users/") + strlen("/approval_requests") + strlen(pszAuthyId) + 1;
  pszEndPoint = calloc(endPointSize, sizeof(char));
  if(!pszEndPoint){
    r = FAIL;
    goto EXIT;
  }

  snprintf(pszEndPoint, endPointSize, "/onetouch/json/users/%s/approval_requests", pszAuthyId);

  r = buildUrl(&pszRequestUrl,
               pszApiUrl,
               pszEndPoint,
               pszParams,
               pszApiKey);

  if(FAILED(r)) {
    trace(INFO, __LINE__, "[Authy] URL for Token verification failed\n");
    goto EXIT;
  }

  r = doHttpRequest(pszRequestUrl, pszNullPost, pszResponse); //GET request, postFields are NULL

  if(FAILED(r)) {
    trace(INFO, __LINE__, "[Authy] Token request verification failed.\n");
    goto EXIT;
  }

  if(FALSE == tokenResponseIsValid(pszResponse))
  {
    trace(ERROR, __LINE__, "[Authy] Response does not include 'success': true. Invalid token assumed.");
    r = FAIL;
    goto EXIT;
  }

  char *guid = getGuid(pszResponse); // Replace the raw response with the GUID for checking later...
  strcpy(pszResponse, guid);
EXIT:
  cleanAndFree(pszRequestUrl);
  pszRequestUrl = NULL;
  cleanAndFree(pszEndPoint);
  pszEndPoint = NULL;

  return r;
}

extern int
verifyOnetouch(const char *pszApiUrl,
            char *pszGuid,
            const char *pszApiKey,
            char *pszResponse,
            char *pszApprovalStatus) {

  int r = -1;
  size_t endPointSize = 0;
  char *pszRequestUrl = NULL;
  char *pszEndPoint = NULL;
  char *pszNullPost = NULL;
  char *pszParams = "?api_key=";

  endPointSize = strlen("/onetouch/json/") + strlen("/approval_requests/") + strlen(pszGuid) + 1;
  pszEndPoint = calloc(endPointSize, sizeof(char));
  if(!pszEndPoint){
    r = FAIL;
    goto EXIT;
  }

  snprintf(pszEndPoint, endPointSize, "/onetouch/json/approval_requests/%s", pszGuid);

  r = buildUrl(&pszRequestUrl,
               pszApiUrl,
               pszEndPoint,
               pszParams,
               pszApiKey);

  if(FAILED(r)) {
    trace(INFO, __LINE__, "[Authy] URL for Token verification failed\n");
    goto EXIT;
  }

  r = doHttpRequest(pszRequestUrl, pszNullPost, pszResponse); //GET request, postFields are NULL

  if(FAILED(r)) {
    trace(INFO, __LINE__, "[Authy] Token request verification failed.\n");
    goto EXIT;
  }

  r = tokenVerifyResponseIsValid(pszResponse, pszApprovalStatus);

  if(1 == r) // Expired or Denied
  {
    trace(ERROR, __LINE__, "[Authy] OneTouch Response Denied or Expired.");
    goto EXIT;
  }

EXIT:
  cleanAndFree(pszRequestUrl);
  pszRequestUrl = NULL;
  cleanAndFree(pszEndPoint);
  pszEndPoint = NULL;
  return r;
}
