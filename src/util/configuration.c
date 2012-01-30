/*
     This file is part of GNUnet.
     (C) 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file src/util/configuration.c
 * @brief configuration management
 *
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_strings_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

/**
 * @brief configuration entry
 */
struct ConfigEntry
{

  /**
   * This is a linked list.
   */
  struct ConfigEntry *next;

  /**
   * key for this entry
   */
  char *key;

  /**
   * current, commited value
   */
  char *val;
};


/**
 * @brief configuration section
 */
struct ConfigSection
{
  /**
   * This is a linked list.
   */
  struct ConfigSection *next;

  /**
   * entries in the section
   */
  struct ConfigEntry *entries;

  /**
   * name of the section
   */
  char *name;
};


/**
 * @brief configuration data
 */
struct GNUNET_CONFIGURATION_Handle
{
  /**
   * Configuration sections.
   */
  struct ConfigSection *sections;

  /**
   * Modification indication since last save
   * GNUNET_NO if clean, GNUNET_YES if dirty,
   * GNUNET_SYSERR on error (i.e. last save failed)
   */
  int dirty;

};


/**
 * Used for diffing a configuration object against
 * the default one
 */
struct DiffHandle
{
  const struct GNUNET_CONFIGURATION_Handle *cfgDefault;
  struct GNUNET_CONFIGURATION_Handle *cfgDiff;
};



/**
 * Create a GNUNET_CONFIGURATION_Handle.
 *
 * @return fresh configuration object
 */
struct GNUNET_CONFIGURATION_Handle *
GNUNET_CONFIGURATION_create ()
{
  return GNUNET_malloc (sizeof (struct GNUNET_CONFIGURATION_Handle));
}


/**
 * Destroy configuration object.
 *
 * @param cfg configuration to destroy
 */
void
GNUNET_CONFIGURATION_destroy (struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct ConfigSection *sec;

  while (NULL != (sec = cfg->sections))
    GNUNET_CONFIGURATION_remove_section (cfg, sec->name);
  GNUNET_free (cfg);
}


/**
 * Parse a configuration file, add all of the options in the
 * file to the configuration environment.
 *
 * @param cfg configuration to update
 * @param filename name of the configuration file
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_parse (struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *filename)
{
  int dirty;
  char line[256];
  char tag[64];
  char value[192];
  FILE *fp;
  unsigned int nr;
  int i;
  int emptyline;
  int ret;
  char *section;
  char *fn;

  fn = GNUNET_STRINGS_filename_expand (filename);
  if (fn == NULL)
    return GNUNET_SYSERR;
  dirty = cfg->dirty;           /* back up value! */
  if (NULL == (fp = FOPEN (fn, "r")))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fopen", fn);
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  GNUNET_free (fn);
  ret = GNUNET_OK;
  section = GNUNET_strdup ("");
  memset (line, 0, 256);
  nr = 0;
  while (NULL != fgets (line, 255, fp))
  {
    nr++;
    for (i = 0; i < 255; i++)
      if (line[i] == '\t')
        line[i] = ' ';
    if (line[0] == '\n' || line[0] == '#' || line[0] == '%' || line[0] == '\r')
      continue;
    emptyline = 1;
    for (i = 0; (i < 255 && line[i] != 0); i++)
      if (line[i] != ' ' && line[i] != '\n' && line[i] != '\r')
        emptyline = 0;
    if (emptyline == 1)
      continue;
    /* remove tailing whitespace */
    for (i = strlen (line) - 1; (i >= 0) && (isspace ((unsigned char) line[i]));
         i--)
      line[i] = '\0';
    if (1 == sscanf (line, "@INLINE@ %191[^\n]", value))
    {
      /* @INLINE@ value */
      if (GNUNET_OK != GNUNET_CONFIGURATION_parse (cfg, value))
        ret = GNUNET_SYSERR;    /* failed to parse included config */
    }
    else if (1 == sscanf (line, "[%99[^]]]", value))
    {
      /* [value] */
      GNUNET_free (section);
      section = GNUNET_strdup (value);
    }
    else if (2 == sscanf (line, " %63[^= ] = %191[^\n]", tag, value))
    {
      /* tag = value */
      /* Strip LF */
      i = strlen (value) - 1;
      while ((i >= 0) && (isspace ((unsigned char) value[i])))
        value[i--] = '\0';
      /* remove quotes */
      i = 0;
      if (value[0] == '"')
      {
        i = 1;
        while ((value[i] != '\0') && (value[i] != '"'))
          i++;
        if (value[i] == '"')
        {
          value[i] = '\0';
          i = 1;
        }
        else
          i = 0;
      }
      GNUNET_CONFIGURATION_set_value_string (cfg, section, tag, &value[i]);
    }
    else if (1 == sscanf (line, " %63[^= ] =[^\n]", tag))
    {
      /* tag = */
      GNUNET_CONFIGURATION_set_value_string (cfg, section, tag, "");
    }
    else
    {
      /* parse error */
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _("Syntax error in configuration file `%s' at line %u.\n"), filename,
           nr);
      ret = GNUNET_SYSERR;
      break;
    }
  }
  GNUNET_assert (0 == FCLOSE (fp));
  /* restore dirty flag - anything we set in the meantime
   * came from disk */
  cfg->dirty = dirty;
  GNUNET_free (section);
  return ret;
}


/**
 * Test if there are configuration options that were
 * changed since the last save.
 *
 * @param cfg configuration to inspect
 * @return GNUNET_NO if clean, GNUNET_YES if dirty, GNUNET_SYSERR on error (i.e. last save failed)
 */
int
GNUNET_CONFIGURATION_is_dirty (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  return cfg->dirty;
}


/**
 * Write configuration file.
 *
 * @param cfg configuration to write
 * @param filename where to write the configuration
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_write (struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *filename)
{
  struct ConfigSection *sec;
  struct ConfigEntry *ent;
  FILE *fp;
  int error;
  char *fn;
  char *val;
  char *pos;

  fn = GNUNET_STRINGS_filename_expand (filename);
  if (fn == NULL)
    return GNUNET_SYSERR;
  if (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn))
  {
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  if (NULL == (fp = FOPEN (fn, "w")))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fopen", fn);
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  GNUNET_free (fn);
  error = 0;
  sec = cfg->sections;
  while (sec != NULL)
  {
    if (0 > FPRINTF (fp, "[%s]\n", sec->name))
    {
      error = 1;
      break;
    }
    ent = sec->entries;
    while (ent != NULL)
    {
      if (ent->val != NULL)
      {
        val = GNUNET_malloc (strlen (ent->val) * 2 + 1);
        strcpy (val, ent->val);
        while (NULL != (pos = strstr (val, "\n")))
        {
          memmove (&pos[2], &pos[1], strlen (&pos[1]));
          pos[0] = '\\';
          pos[1] = 'n';
        }
        if (0 > FPRINTF (fp, "%s = %s\n", ent->key, val))
        {
          error = 1;
          GNUNET_free (val);
          break;
        }
        GNUNET_free (val);
      }
      ent = ent->next;
    }
    if (error != 0)
      break;
    if (0 > FPRINTF (fp, "%s\n", ""))
    {
      error = 1;
      break;
    }
    sec = sec->next;
  }
  if (error != 0)
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fprintf", filename);
  GNUNET_assert (0 == FCLOSE (fp));
  if (error != 0)
  {
    cfg->dirty = GNUNET_SYSERR; /* last write failed */
    return GNUNET_SYSERR;
  }
  cfg->dirty = GNUNET_NO;       /* last write succeeded */
  return GNUNET_OK;
}


/**
 * Iterate over all options in the configuration.
 *
 * @param cfg configuration to inspect
 * @param iter function to call on each option
 * @param iter_cls closure for iter
 */
void
GNUNET_CONFIGURATION_iterate (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              GNUNET_CONFIGURATION_Iterator iter,
                              void *iter_cls)
{
  struct ConfigSection *spos;
  struct ConfigEntry *epos;

  spos = cfg->sections;
  while (spos != NULL)
  {
    epos = spos->entries;
    while (epos != NULL)
    {
      iter (iter_cls, spos->name, epos->key, epos->val);
      epos = epos->next;
    }
    spos = spos->next;
  }
}


/**
 * Iterate over values of a section in the configuration.
 *
 * @param cfg configuration to inspect
 * @param section the section
 * @param iter function to call on each option
 * @param iter_cls closure for iter
 */
void
GNUNET_CONFIGURATION_iterate_section_values (const struct
                                             GNUNET_CONFIGURATION_Handle *cfg,
                                             const char *section,
                                             GNUNET_CONFIGURATION_Iterator iter,
                                             void *iter_cls)
{
  struct ConfigSection *spos;
  struct ConfigEntry *epos;

  spos = cfg->sections;
  while ((spos != NULL) && (0 != strcasecmp (spos->name, section)))
    spos = spos->next;

  if (spos == NULL)
    return;

  epos = spos->entries;
  while (epos != NULL)
  {
    iter (iter_cls, spos->name, epos->key, epos->val);
    epos = epos->next;
  }
}


/**
 * Iterate over all sections in the configuration.
 *
 * @param cfg configuration to inspect
 * @param iter function to call on each section
 * @param iter_cls closure for iter
 */
void
GNUNET_CONFIGURATION_iterate_sections (const struct GNUNET_CONFIGURATION_Handle
                                       *cfg,
                                       GNUNET_CONFIGURATION_Section_Iterator
                                       iter, void *iter_cls)
{
  struct ConfigSection *spos;
  struct ConfigSection *next;

  next = cfg->sections;
  while (next != NULL)
  {
    spos = next;
    next = spos->next;
    iter (iter_cls, spos->name);
  }
}

/**
 * Remove the given section and all options in it.
 *
 * @param cfg configuration to inspect
 * @param section name of the section to remove
 */
void
GNUNET_CONFIGURATION_remove_section (struct GNUNET_CONFIGURATION_Handle *cfg,
                                     const char *section)
{
  struct ConfigSection *spos;
  struct ConfigSection *prev;
  struct ConfigEntry *ent;

  prev = NULL;
  spos = cfg->sections;
  while (spos != NULL)
  {
    if (0 == strcasecmp (section, spos->name))
    {
      if (prev == NULL)
        cfg->sections = spos->next;
      else
        prev->next = spos->next;
      while (NULL != (ent = spos->entries))
      {
        spos->entries = ent->next;
        GNUNET_free (ent->key);
        GNUNET_free_non_null (ent->val);
        GNUNET_free (ent);
        cfg->dirty = GNUNET_YES;
      }
      GNUNET_free (spos->name);
      GNUNET_free (spos);
      return;
    }
    prev = spos;
    spos = spos->next;
  }
}


/**
 * Copy a configuration value to the given target configuration.
 * Overwrites existing entries.
 *
 * @param cls the destination configuration (struct GNUNET_CONFIGURATION_Handle*)
 * @param section section for the value
 * @param option option name of the value
 * @param value value to copy
 */
static void
copy_entry (void *cls, const char *section, const char *option,
            const char *value)
{
  struct GNUNET_CONFIGURATION_Handle *dst = cls;

  GNUNET_CONFIGURATION_set_value_string (dst, section, option, value);
}


/**
 * Duplicate an existing configuration object.
 *
 * @param cfg configuration to duplicate
 * @return duplicate configuration
 */
struct GNUNET_CONFIGURATION_Handle *
GNUNET_CONFIGURATION_dup (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CONFIGURATION_Handle *ret;

  ret = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_iterate (cfg, &copy_entry, ret);
  return ret;
}


/**
 * FIXME.
 *
 * @param cfg FIXME
 * @param section FIXME
 * @return matching entry, NULL if not found
 */
static struct ConfigSection *
findSection (const struct GNUNET_CONFIGURATION_Handle *cfg, const char *section)
{
  struct ConfigSection *pos;

  pos = cfg->sections;
  while ((pos != NULL) && (0 != strcasecmp (section, pos->name)))
    pos = pos->next;
  return pos;
}


/**
 * Find an entry from a configuration.
 *
 * @param cfg handle to the configuration
 * @param section section the option is in
 * @param key the option
 * @return matching entry, NULL if not found
 */
static struct ConfigEntry *
findEntry (const struct GNUNET_CONFIGURATION_Handle *cfg, const char *section,
           const char *key)
{
  struct ConfigSection *sec;
  struct ConfigEntry *pos;

  sec = findSection (cfg, section);
  if (sec == NULL)
    return NULL;
  pos = sec->entries;
  while ((pos != NULL) && (0 != strcasecmp (key, pos->key)))
    pos = pos->next;
  return pos;
}


/**
 * A callback function, compares entries from two configurations
 * (default against a new configuration) and write the diffs in a
 * diff-configuration object (the callback object).
 *
 * @param cls the diff configuration (struct DiffHandle*)
 * @param section section for the value (of the default conf.)
 * @param option option name of the value (of the default conf.)
 * @param value value to copy (of the default conf.)
 */
static void
compareEntries (void *cls, const char *section, const char *option,
                const char *value)
{
  struct DiffHandle *dh = cls;
  struct ConfigEntry *entNew;

  entNew = findEntry (dh->cfgDefault, section, option);
  if ((entNew != NULL) && (strcmp (entNew->val, value) == 0))
    return;
  GNUNET_CONFIGURATION_set_value_string (dh->cfgDiff, section, option, value);
}


/**
 * Write only configuration entries that have been changed to configuration file
 * @param cfgDefault default configuration
 * @param cfgNew new configuration
 * @param filename where to write the configuration diff between default and new
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_write_diffs (const struct GNUNET_CONFIGURATION_Handle
                                  *cfgDefault,
                                  const struct GNUNET_CONFIGURATION_Handle
                                  *cfgNew, const char *filename)
{
  int ret;
  struct DiffHandle diffHandle;

  diffHandle.cfgDiff = GNUNET_CONFIGURATION_create ();
  diffHandle.cfgDefault = cfgDefault;
  GNUNET_CONFIGURATION_iterate (cfgNew, compareEntries, &diffHandle);
  ret = GNUNET_CONFIGURATION_write (diffHandle.cfgDiff, filename);
  GNUNET_CONFIGURATION_destroy (diffHandle.cfgDiff);
  return ret;
}


/**
 * Set a configuration value that should be a string.
 *
 * @param cfg configuration to update
 * @param section section of interest
 * @param option option of interest
 * @param value value to set
 */
void
GNUNET_CONFIGURATION_set_value_string (struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *section, const char *option,
                                       const char *value)
{
  struct ConfigSection *sec;
  struct ConfigEntry *e;

  e = findEntry (cfg, section, option);
  if (e != NULL)
  {
    GNUNET_free_non_null (e->val);
    e->val = GNUNET_strdup (value);
    return;
  }
  sec = findSection (cfg, section);
  if (sec == NULL)
  {
    sec = GNUNET_malloc (sizeof (struct ConfigSection));
    sec->name = GNUNET_strdup (section);
    sec->next = cfg->sections;
    cfg->sections = sec;
  }
  e = GNUNET_malloc (sizeof (struct ConfigEntry));
  e->key = GNUNET_strdup (option);
  e->val = GNUNET_strdup (value);
  e->next = sec->entries;
  sec->entries = e;
}


/**
 * Set a configuration value that should be a number.
 *
 * @param cfg configuration to update
 * @param section section of interest
 * @param option option of interest
 * @param number value to set
 */
void
GNUNET_CONFIGURATION_set_value_number (struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *section, const char *option,
                                       unsigned long long number)
{
  char s[64];

  GNUNET_snprintf (s, 64, "%llu", number);
  GNUNET_CONFIGURATION_set_value_string (cfg, section, option, s);
}


/**
 * Get a configuration value that should be a number.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param number where to store the numeric value of the option
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_number (const struct GNUNET_CONFIGURATION_Handle
                                       *cfg, const char *section,
                                       const char *option,
                                       unsigned long long *number)
{
  struct ConfigEntry *e;

  e = findEntry (cfg, section, option);
  if (e == NULL)
    return GNUNET_SYSERR;
  if (1 != SSCANF (e->val, "%llu", number))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Get a configuration value that should be a relative time.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param time set to the time value stored in the configuration
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_time (const struct GNUNET_CONFIGURATION_Handle
                                     *cfg, const char *section,
                                     const char *option,
                                     struct GNUNET_TIME_Relative *time)
{
  struct ConfigEntry *e;

  e = findEntry (cfg, section, option);
  if (e == NULL)
    return GNUNET_SYSERR;

  return GNUNET_STRINGS_fancy_time_to_relative (e->val, time);
}


/**
 * Get a configuration value that should be a size in bytes.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param size set to the size in bytes as stored in the configuration
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_size (const struct GNUNET_CONFIGURATION_Handle
                                     *cfg, const char *section,
                                     const char *option,
                                     unsigned long long *size)
{
  struct ConfigEntry *e;

  e = findEntry (cfg, section, option);
  if (e == NULL)
    return GNUNET_SYSERR;
  return GNUNET_STRINGS_fancy_size_to_bytes (e->val, size);
}


/**
 * Get a configuration value that should be a string.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param value will be set to a freshly allocated configuration
 *        value, or NULL if option is not specified
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_string (const struct GNUNET_CONFIGURATION_Handle
                                       *cfg, const char *section,
                                       const char *option, char **value)
{
  struct ConfigEntry *e;

  e = findEntry (cfg, section, option);
  if ((e == NULL) || (e->val == NULL))
  {
    *value = NULL;
    return GNUNET_SYSERR;
  }
  *value = GNUNET_strdup (e->val);
  return GNUNET_OK;
}


/**
 * Get a configuration value that should be in a set of
 * predefined strings
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param choices NULL-terminated list of legal values
 * @param value will be set to an entry in the legal list,
 *        or NULL if option is not specified and no default given
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_choice (const struct GNUNET_CONFIGURATION_Handle
                                       *cfg, const char *section,
                                       const char *option, const char **choices,
                                       const char **value)
{
  struct ConfigEntry *e;
  int i;

  e = findEntry (cfg, section, option);
  if (e == NULL)
    return GNUNET_SYSERR;
  i = 0;
  while (choices[i] != NULL)
  {
    if (0 == strcasecmp (choices[i], e->val))
      break;
    i++;
  }
  if (choices[i] == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Configuration value '%s' for '%s'"
           " in section '%s' is not in set of legal choices\n"), e->val, option,
         section);
    return GNUNET_SYSERR;
  }
  *value = choices[i];
  return GNUNET_OK;
}


/**
 * Test if we have a value for a particular option
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @return GNUNET_YES if so, GNUNET_NO if not.
 */
int
GNUNET_CONFIGURATION_have_value (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 const char *section, const char *option)
{
  struct ConfigEntry *e;

  if ((NULL == (e = findEntry (cfg, section, option))) || (e->val == NULL))
    return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Expand an expression of the form "$FOO/BAR" to "DIRECTORY/BAR"
 * where either in the "PATHS" section or the environtment
 * "FOO" is set to "DIRECTORY".
 *
 * @param cfg configuration to use for path expansion
 * @param orig string to $-expand (will be freed!)
 * @return $-expanded string
 */
char *
GNUNET_CONFIGURATION_expand_dollar (const struct GNUNET_CONFIGURATION_Handle
                                    *cfg, char *orig)
{
  int i;
  char *prefix;
  char *result;
  const char *post;
  const char *env;

  if (orig[0] != '$')
    return orig;
  i = 0;
  while ((orig[i] != '/') && (orig[i] != '\\') && (orig[i] != '\0'))
    i++;
  if (orig[i] == '\0')
  {
    post = "";
  }
  else
  {
    orig[i] = '\0';
    post = &orig[i + 1];
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "PATHS", &orig[1], &prefix))
  {
    if (NULL == (env = getenv (&orig[1])))
    {
      orig[i] = DIR_SEPARATOR;
      return orig;
    }
    prefix = GNUNET_strdup (env);
  }
  result = GNUNET_malloc (strlen (prefix) + strlen (post) + 2);
  strcpy (result, prefix);
  if ((strlen (prefix) == 0) ||
      ((prefix[strlen (prefix) - 1] != DIR_SEPARATOR) && (strlen (post) > 0)))
    strcat (result, DIR_SEPARATOR_STR);
  strcat (result, post);
  GNUNET_free (prefix);
  GNUNET_free (orig);
  return result;
}


/**
 * Get a configuration value that should be a string.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param value will be set to a freshly allocated configuration
 *        value, or NULL if option is not specified
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_filename (const struct
                                         GNUNET_CONFIGURATION_Handle *cfg,
                                         const char *section,
                                         const char *option, char **value)
{
  char *tmp;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, section, option, &tmp))
  {
    *value = NULL;
    return GNUNET_SYSERR;
  }
  tmp = GNUNET_CONFIGURATION_expand_dollar (cfg, tmp);
  *value = GNUNET_STRINGS_filename_expand (tmp);
  GNUNET_free (tmp);
  if (*value == NULL)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Get a configuration value that should be in a set of
 * "GNUNET_YES" or "GNUNET_NO".
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @return GNUNET_YES, GNUNET_NO or GNUNET_SYSERR
 */
int
GNUNET_CONFIGURATION_get_value_yesno (const struct GNUNET_CONFIGURATION_Handle
                                      *cfg, const char *section,
                                      const char *option)
{
  static const char *yesno[] = { "YES", "NO", NULL };
  const char *val;
  int ret;

  ret =
      GNUNET_CONFIGURATION_get_value_choice (cfg, section, option, yesno, &val);
  if (ret == GNUNET_SYSERR)
    return ret;
  if (val == yesno[0])
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Iterate over the set of filenames stored in a configuration value.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param cb function to call on each filename
 * @param cb_cls closure for cb
 * @return number of filenames iterated over, -1 on error
 */
int
GNUNET_CONFIGURATION_iterate_value_filenames (const struct
                                              GNUNET_CONFIGURATION_Handle *cfg,
                                              const char *section,
                                              const char *option,
                                              GNUNET_FileNameCallback cb,
                                              void *cb_cls)
{
  char *list;
  char *pos;
  char *end;
  char old;
  int ret;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, section, option, &list))
    return 0;
  GNUNET_assert (list != NULL);
  ret = 0;
  pos = list;
  while (1)
  {
    while (pos[0] == ' ')
      pos++;
    if (strlen (pos) == 0)
      break;
    end = pos + 1;
    while ((end[0] != ' ') && (end[0] != '\0'))
    {
      if (end[0] == '\\')
      {
        switch (end[1])
        {
        case '\\':
        case ' ':
          memmove (end, &end[1], strlen (&end[1]) + 1);
        case '\0':
          /* illegal, but just keep it */
          break;
        default:
          /* illegal, but just ignore that there was a '/' */
          break;
        }
      }
      end++;
    }
    old = end[0];
    end[0] = '\0';
    if (strlen (pos) > 0)
    {
      ret++;
      if ((cb != NULL) && (GNUNET_OK != cb (cb_cls, pos)))
      {
        ret = GNUNET_SYSERR;
        break;
      }
    }
    if (old == '\0')
      break;
    pos = end + 1;
  }
  GNUNET_free (list);
  return ret;
}


/**
 * FIXME.
 *
 * @param value FIXME
 * @return FIXME
 */
static char *
escape_name (const char *value)
{
  char *escaped;
  const char *rpos;
  char *wpos;

  escaped = GNUNET_malloc (strlen (value) * 2 + 1);
  memset (escaped, 0, strlen (value) * 2 + 1);
  rpos = value;
  wpos = escaped;
  while (rpos[0] != '\0')
  {
    switch (rpos[0])
    {
    case '\\':
    case ' ':
      wpos[0] = '\\';
      wpos[1] = rpos[0];
      wpos += 2;
      break;
    default:
      wpos[0] = rpos[0];
      wpos++;
    }
    rpos++;
  }
  return escaped;
}


/**
 * FIXME.
 *
 * @param cls string we compare with (const char*)
 * @param fn filename we are currently looking at
 * @return GNUNET_OK if the names do not match, GNUNET_SYSERR if they do
 */
static int
test_match (void *cls, const char *fn)
{
  const char *of = cls;

  return (0 == strcmp (of, fn)) ? GNUNET_SYSERR : GNUNET_OK;
}


/**
 * Append a filename to a configuration value that
 * represents a list of filenames
 *
 * @param cfg configuration to update
 * @param section section of interest
 * @param option option of interest
 * @param value filename to append
 * @return GNUNET_OK on success,
 *         GNUNET_NO if the filename already in the list
 *         GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_append_value_filename (struct GNUNET_CONFIGURATION_Handle
                                            *cfg, const char *section,
                                            const char *option,
                                            const char *value)
{
  char *escaped;
  char *old;
  char *nw;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_iterate_value_filenames (cfg, section, option,
                                                    &test_match,
                                                    (void *) value))
    return GNUNET_NO;           /* already exists */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, section, option, &old))
    old = GNUNET_strdup ("");
  escaped = escape_name (value);
  nw = GNUNET_malloc (strlen (old) + strlen (escaped) + 2);
  strcpy (nw, old);
  if (strlen (old) > 0)
    strcat (nw, " ");
  strcat (nw, escaped);
  GNUNET_CONFIGURATION_set_value_string (cfg, section, option, nw);
  GNUNET_free (old);
  GNUNET_free (nw);
  GNUNET_free (escaped);
  return GNUNET_OK;
}


/**
 * Remove a filename from a configuration value that
 * represents a list of filenames
 *
 * @param cfg configuration to update
 * @param section section of interest
 * @param option option of interest
 * @param value filename to remove
 * @return GNUNET_OK on success,
 *         GNUNET_NO if the filename is not in the list,
 *         GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_remove_value_filename (struct GNUNET_CONFIGURATION_Handle
                                            *cfg, const char *section,
                                            const char *option,
                                            const char *value)
{
  char *list;
  char *pos;
  char *end;
  char *match;
  char old;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, section, option, &list))
    return GNUNET_NO;
  match = escape_name (value);
  pos = list;
  while (1)
  {
    while (pos[0] == ' ')
      pos++;
    if (strlen (pos) == 0)
      break;
    end = pos + 1;
    while ((end[0] != ' ') && (end[0] != '\0'))
    {
      if (end[0] == '\\')
      {
        switch (end[1])
        {
        case '\\':
        case ' ':
          end++;
          break;
        case '\0':
          /* illegal, but just keep it */
          break;
        default:
          /* illegal, but just ignore that there was a '/' */
          break;
        }
      }
      end++;
    }
    old = end[0];
    end[0] = '\0';
    if (0 == strcmp (pos, match))
    {
      if (old != '\0')
        memmove (pos, &end[1], strlen (&end[1]) + 1);
      else
      {
        if (pos != list)
          pos[-1] = '\0';
        else
          pos[0] = '\0';
      }
      GNUNET_CONFIGURATION_set_value_string (cfg, section, option, list);
      GNUNET_free (list);
      GNUNET_free (match);
      return GNUNET_OK;
    }
    if (old == '\0')
      break;
    end[0] = old;
    pos = end + 1;
  }
  GNUNET_free (list);
  GNUNET_free (match);
  return GNUNET_NO;
}


/**
 * Wrapper around GNUNET_CONFIGURATION_parse.
 *
 * @param cls the cfg
 * @param filename file to parse
 * @return GNUNET_OK on success
 */
static int
parse_configuration_file (void *cls, const char *filename)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  int ret;

  ret = GNUNET_CONFIGURATION_parse (cfg, filename);
  return ret;
}


/**
 * Load configuration (starts with defaults, then loads
 * system-specific configuration).
 *
 * @param cfg configuration to update
 * @param filename name of the configuration file, NULL to load defaults
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_load (struct GNUNET_CONFIGURATION_Handle *cfg,
                           const char *filename)
{
  char *baseconfig;
  char *ipath;

  ipath = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
  if (ipath == NULL)
    return GNUNET_SYSERR;
  baseconfig = NULL;
  GNUNET_asprintf (&baseconfig, "%s%s", ipath, "config.d");
  GNUNET_free (ipath);
  if (GNUNET_SYSERR ==
      GNUNET_DISK_directory_scan (baseconfig, &parse_configuration_file, cfg))
  {
    GNUNET_free (baseconfig);
    return GNUNET_SYSERR;       /* no configuration at all found */
  }
  GNUNET_free (baseconfig);
  if ((filename != NULL) &&
      (GNUNET_OK != GNUNET_CONFIGURATION_parse (cfg, filename)))
  {
    /* specified configuration not found */
    return GNUNET_SYSERR;
  }
  if (((GNUNET_YES !=
        GNUNET_CONFIGURATION_have_value (cfg, "PATHS", "DEFAULTCONFIG"))) &&
      (filename != NULL))
    GNUNET_CONFIGURATION_set_value_string (cfg, "PATHS", "DEFAULTCONFIG",
                                           filename);
  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_have_value (cfg, "TESTING", "WEAKRANDOM")) &&
      (GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_yesno (cfg, "TESTING", "WEAKRANDOM")))
    GNUNET_CRYPTO_random_disable_entropy_gathering ();
  return GNUNET_OK;
}



/* end of configuration.c */
