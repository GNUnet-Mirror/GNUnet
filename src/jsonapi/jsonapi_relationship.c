#include "platform.h"
#include "gnunet_jsonapi_lib.h"


/**
 * Delete a JSON API relationship TODO
 *
 * @param res the JSON relationship
 */
void
GNUNET_JSONAPI_relationship_delete (struct GNUNET_JSONAPI_Relationship *relationship)
{
  GNUNET_assert (NULL != relationship);
  GNUNET_free (relationship);
}


