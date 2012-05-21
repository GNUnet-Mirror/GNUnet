/*
 * Glue function to return the authoritative part
 * of a name. i.e. the site of origin
 *
 * @param name the name to process
 * @param auth pointer where the result is stored
 * @return 0 on success < 0 on failure
 */
int
gns_glue_get_auth ( char* name, char* auth );

/*
 * Glue function to return the short version of
 * a given name
 *
 * @param name the name to shorten
 * @param shortened pointer where the result will be stored
 * @return 0 on success < 0 on failure
 */
int
gns_glue_shorten ( char* name, char* shortened);

/*
 * Glue function to expand .+ urls and shorted the
 * resulting name
 *
 * @param to_expand the .+ name to expand
 * @param host the site of origin
 * @param shortened the expanded and shortened result pointer
 */
int
gns_glue_expand_and_shorten (char* to_expand,
                             char* host,
                             char* shortened);
