#include "platform.h"
#include "gnunet_jsonapi_lib.h"
/**
 * jsonapi error object
 */
struct GNUNET_JSONAPI_Error
{
  /**
   * DLL
   */
  struct GNUNET_JSONAPI_Error *next;

  /**
   * DLL
   */
  struct GNUNET_JSONAPI_Error *prev;

  /**
   * Unique error id
   */
  char *id;

  /**
   * Links object
   */
  json_t *links;

  /**
   * HTTP status code for this error
   */
  char *status;

  /**
   * Application error code
   */
  char *code;

  /**
   * Error title
   */
  char *title;

  /**
   * Error details
   */
  char *detail;

  /**
   * Error source
   */
  json_t *source;

  /**
   * Meta info for the error
   */
  json_t *meta;
};

struct GNUNET_JSONAPI_Relationship
{
  /**
   * Links object
   */
  struct GNUNET_JSONAPI_Link *links;

  /**
   * Resource linkage data
   */
  struct GNUNET_JSONAPI_Resource *res_list_head;

  /**
   * DLL
   */
  struct GNUNET_JSONAPI_Resource *res_list_tail;
  
  /**
   * Number of resources in data section
   */
  int res_count;

  /**
   * Meta information
   */
  json_t *meta;
};

/**
 * A jsonapi resource object
 */
struct GNUNET_JSONAPI_Resource
{
  /**
   * DLL
   */
  struct GNUNET_JSONAPI_Resource *next;

  /**
   * DLL
   */
  struct GNUNET_JSONAPI_Resource *prev;

  /**
   * Resource type
   */
  char *type;

  /**
   * Resource ID
   */
  char *id;

  /**
   * Attributes object
   */
  json_t *attr_obj;

  /**
   * Relationship
   */
  struct GNUNET_JSONAPI_Relationship *relationship;
};


struct GNUNET_JSONAPI_Document
{
  /**
   * DLL Resource
   */
  struct GNUNET_JSONAPI_Resource *res_list_head;

  /**
   * DLL Resource
   */
  struct GNUNET_JSONAPI_Resource *res_list_tail;

  /**
   * num resources
   */
  int res_count;

  /**
   * DLL Error
   */
  struct GNUNET_JSONAPI_Error *err_list_head;

  /**
   * DLL Error
   */
  struct GNUNET_JSONAPI_Error *err_list_tail;

  /**
   * num errors
   */
  int err_count;

  /**
   * Meta info
   */
  json_t *meta;
};


