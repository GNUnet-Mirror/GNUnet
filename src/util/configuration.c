/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2007, 2008, 2009, 2013 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file src/util/configuration.c
 * @brief configuration management
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_strings_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_disk_lib.h"

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
   * #GNUNET_NO if clean, #GNUNET_YES if dirty,
   * #GNUNET_SYSERR on error (i.e. last save failed)
   */
  int dirty;

};


/**
 * Used for diffing a configuration object against
 * the default one
 */
struct DiffHandle
{
  const struct GNUNET_CONFIGURATION_Handle *cfg_default;

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
  return GNUNET_new (struct GNUNET_CONFIGURATION_Handle);
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
 * De-serializes configuration
 *
 * @param cfg configuration to update
 * @param mem the memory block of serialized configuration
 * @param size the size of the memory block
 * @param allow_inline set to #GNUNET_YES if we recursively load configuration
 *          from inlined configurations; #GNUNET_NO if not and raise warnings
 *          when we come across them
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_deserialize (struct GNUNET_CONFIGURATION_Handle *cfg,
				  const char *mem,
				  const size_t size,
				  int allow_inline)
{
  char *line;
  char *line_orig;
  size_t line_size;
  char *pos;
  unsigned int nr;
  size_t r_bytes;
  size_t to_read;
  size_t i;
  int emptyline;
  int ret;
  char *section;
  char *eq;
  char *tag;
  char *value;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Deserializing config file\n");
  ret = GNUNET_OK;
  section = GNUNET_strdup ("");
  nr = 0;
  r_bytes = 0;
  line_orig = NULL;
  while (r_bytes < size)
  {
    GNUNET_free_non_null (line_orig);
    /* fgets-like behaviour on buffer */
    to_read = size - r_bytes;
    pos = memchr (&mem[r_bytes], '\n', to_read);
    if (NULL == pos)
    {
      line_orig = GNUNET_strndup (&mem[r_bytes], line_size = to_read);
      r_bytes += line_size;
    }
    else
    {
      line_orig = GNUNET_strndup (&mem[r_bytes], line_size = (pos - &mem[r_bytes]));
      r_bytes += line_size + 1;
    }
    line = line_orig;
    /* increment line number */
    nr++;
    /* tabs and '\r' are whitespace */
    emptyline = GNUNET_YES;
    for (i = 0; i < line_size; i++)
    {
      if (line[i] == '\t')
        line[i] = ' ';
      if (line[i] == '\r')
        line[i] = ' ';
      if (' ' != line[i])
        emptyline = GNUNET_NO;
    }
    /* ignore empty lines */
    if (GNUNET_YES == emptyline)
      continue;

    /* remove tailing whitespace */
    for (i = line_size - 1; (i >= 1) && (isspace ((unsigned char) line[i]));i--)
      line[i] = '\0';

    /* remove leading whitespace */
    for (; line[0] != '\0' && (isspace ((unsigned char) line[0])); line++);

    /* ignore comments */
    if ( ('#' == line[0]) || ('%' == line[0]) )
      continue;

    /* handle special "@INLINE@" directive */
    if (0 == strncasecmp (line,
			  "@INLINE@ ",
			  strlen ("@INLINE@ ")))
    {
      /* @INLINE@ value */
      value = &line[strlen ("@INLINE@ ")];
      if (GNUNET_YES == allow_inline)
      {
	if (GNUNET_OK != GNUNET_CONFIGURATION_parse (cfg, value))
	{
	  ret = GNUNET_SYSERR;    /* failed to parse included config */
	  break;
	}
      }
      else
      {
	LOG (GNUNET_ERROR_TYPE_DEBUG,
	     "Ignoring parsing @INLINE@ configurations, not allowed!\n");
	ret = GNUNET_SYSERR;
	break;
      }
      continue;
    }
    if ( ('[' == line[0]) && (']' == line[line_size - 1]) )
    {
      /* [value] */
      line[line_size - 1] = '\0';
      value = &line[1];
      GNUNET_free (section);
      section = GNUNET_strdup (value);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Config section `%s'\n",
	   section);
      continue;
    }
    if (NULL != (eq = strchr (line, '=')))
    {
      /* tag = value */
      tag = GNUNET_strndup (line, eq - line);
      /* remove tailing whitespace */
      for (i = strlen (tag) - 1; (i >= 1) && (isspace ((unsigned char) tag[i]));i--)
	tag[i] = '\0';

      /* Strip whitespace */
      value = eq + 1;
      while (isspace ((unsigned char) value[0]))
	value++;
      for (i = strlen (value) - 1; (i >= 1) && (isspace ((unsigned char) value[i]));i--)
	value[i] = '\0';

      /* remove quotes */
      i = 0;
      if ( ('"' == value[0]) &&
	   ('"' == value[strlen (value) - 1]) )
      {
	value[strlen (value) - 1] = '\0';
	value++;
      }
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Config value %s=\"%s\"\n", tag, value);
      GNUNET_CONFIGURATION_set_value_string (cfg, section, tag, &value[i]);
      GNUNET_free (tag);
      continue;
    }
    /* parse error */
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 _("Syntax error while deserializing in line %u\n"),
	 nr);
    ret = GNUNET_SYSERR;
    break;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Finished deserializing config\n");
  GNUNET_free_non_null (line_orig);
  GNUNET_free (section);
  GNUNET_assert ( (GNUNET_OK != ret) || (r_bytes == size) );
  return ret;
}


/**
 * Parse a configuration file, add all of the options in the
 * file to the configuration environment.
 *
 * @param cfg configuration to update
 * @param filename name of the configuration file
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_parse (struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *filename)
{
  uint64_t fs64;
  size_t fs;
  char *fn;
  char *mem;
  int dirty;
  int ret;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to parse config file `%s'\n",
       filename);
  fn = GNUNET_STRINGS_filename_expand (filename);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Config file name expanded to `%s'\n",
       fn);
  if (NULL == fn)
    return GNUNET_SYSERR;
  dirty = cfg->dirty;           /* back up value! */
  if (GNUNET_SYSERR ==
      GNUNET_DISK_file_size (fn, &fs64, GNUNET_YES, GNUNET_YES))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 "Error while determining the file size of %s\n", fn);
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  if (fs64 > SIZE_MAX)
  {
    GNUNET_break (0); 		/* File size is more than the heap size */
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  fs = fs64;
  mem = GNUNET_malloc (fs);
  if (fs != GNUNET_DISK_fn_read (fn, mem, fs))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 "Error while reading file %s\n",
         fn);
    GNUNET_free (fn);
    GNUNET_free (mem);
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Deserializing contents of file `%s'\n",
       fn);
  GNUNET_free (fn);
  ret = GNUNET_CONFIGURATION_deserialize (cfg, mem, fs, GNUNET_YES);
  GNUNET_free (mem);
  /* restore dirty flag - anything we set in the meantime
   * came from disk */
  cfg->dirty = dirty;
  return ret;
}


/**
 * Test if there are configuration options that were
 * changed since the last save.
 *
 * @param cfg configuration to inspect
 * @return #GNUNET_NO if clean, #GNUNET_YES if dirty, #GNUNET_SYSERR on error (i.e. last save failed)
 */
int
GNUNET_CONFIGURATION_is_dirty (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  return cfg->dirty;
}


/**
 * Serializes the given configuration.
 *
 * @param cfg configuration to serialize
 * @param size will be set to the size of the serialized memory block
 * @return the memory block where the serialized configuration is
 *           present. This memory should be freed by the caller
 */
char *
GNUNET_CONFIGURATION_serialize (const struct GNUNET_CONFIGURATION_Handle *cfg,
				size_t *size)
{
  struct ConfigSection *sec;
  struct ConfigEntry *ent;
  char *mem;
  char *cbuf;
  char *val;
  char *pos;
  int len;
  size_t m_size;
  size_t c_size;


  /* Pass1 : calculate the buffer size required */
  m_size = 0;
  for (sec = cfg->sections; NULL != sec; sec = sec->next)
  {
    /* For each section we need to add 3 charaters: {'[',']','\n'} */
    m_size += strlen (sec->name) + 3;
    for (ent = sec->entries; NULL != ent; ent = ent->next)
    {
      if (NULL != ent->val)
      {
	/* if val has any '\n' then they occupy +1 character as '\n'->'\\','n' */
	pos = ent->val;
	while (NULL != (pos = strstr (pos, "\n")))
	{
	  m_size++;
	  pos++;
	}
	/* For each key = value pair we need to add 4 characters (2
	   spaces and 1 equal-to character and 1 new line) */
	m_size += strlen (ent->key) + strlen (ent->val) + 4;
      }
    }
    /* A new line after section end */
    m_size++;
  }

  /* Pass2: Allocate memory and write the configuration to it */
  mem = GNUNET_malloc (m_size);
  sec = cfg->sections;
  c_size = 0;
  *size = c_size;
  while (NULL != sec)
  {
    len = GNUNET_asprintf (&cbuf, "[%s]\n", sec->name);
    GNUNET_assert (0 < len);
    memcpy (mem + c_size, cbuf, len);
    c_size += len;
    GNUNET_free (cbuf);
    for (ent = sec->entries; NULL != ent; ent = ent->next)
    {
      if (NULL != ent->val)
      {
	val = GNUNET_malloc (strlen (ent->val) * 2 + 1);
	strcpy (val, ent->val);
        while (NULL != (pos = strstr (val, "\n")))
        {
          memmove (&pos[2], &pos[1], strlen (&pos[1]));
          pos[0] = '\\';
          pos[1] = 'n';
        }
	len = GNUNET_asprintf (&cbuf, "%s = %s\n", ent->key, val);
	GNUNET_free (val);
	memcpy (mem + c_size, cbuf, len);
	c_size += len;
	GNUNET_free (cbuf);
      }
    }
    memcpy (mem + c_size, "\n", 1);
    c_size ++;
    sec = sec->next;
  }
  GNUNET_assert (c_size == m_size);
  *size = c_size;
  return mem;
}


/**
 * Write configuration file.
 *
 * @param cfg configuration to write
 * @param filename where to write the configuration
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_write (struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *filename)
{
  char *fn;
  char *cfg_buf;
  size_t size;

  fn = GNUNET_STRINGS_filename_expand (filename);
  if (fn == NULL)
    return GNUNET_SYSERR;
  if (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn))
  {
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  cfg_buf = GNUNET_CONFIGURATION_serialize (cfg, &size);
  if (size != GNUNET_DISK_fn_write (fn, cfg_buf, size,
				    GNUNET_DISK_PERM_USER_READ
				    | GNUNET_DISK_PERM_USER_WRITE
				    | GNUNET_DISK_PERM_GROUP_READ
				    | GNUNET_DISK_PERM_GROUP_WRITE))
  {
    GNUNET_free (fn);
    GNUNET_free (cfg_buf);
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 "Writing configration to file: %s failed\n", filename);
    cfg->dirty = GNUNET_SYSERR; /* last write failed */
    return GNUNET_SYSERR;
  }
  GNUNET_free (fn);
  GNUNET_free (cfg_buf);
  cfg->dirty = GNUNET_NO;       /* last write succeeded */
  return GNUNET_OK;
}


/**
 * Iterate over all options in the configuration.
 *
 * @param cfg configuration to inspect
 * @param iter function to call on each option
 * @param iter_cls closure for @a iter
 */
void
GNUNET_CONFIGURATION_iterate (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              GNUNET_CONFIGURATION_Iterator iter,
                              void *iter_cls)
{
  struct ConfigSection *spos;
  struct ConfigEntry *epos;

  for (spos = cfg->sections; NULL != spos; spos = spos->next)
    for (epos = spos->entries; NULL != epos; epos = epos->next)
      if (NULL != epos->val)
	iter (iter_cls, spos->name, epos->key, epos->val);
}


/**
 * Iterate over values of a section in the configuration.
 *
 * @param cfg configuration to inspect
 * @param section the section
 * @param iter function to call on each option
 * @param iter_cls closure for @a iter
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
  if (NULL == spos)
    return;
  for (epos = spos->entries; NULL != epos; epos = epos->next)
    if (NULL != epos->val)
      iter (iter_cls, spos->name, epos->key, epos->val);
}


/**
 * Iterate over all sections in the configuration.
 *
 * @param cfg configuration to inspect
 * @param iter function to call on each section
 * @param iter_cls closure for @a iter
 */
void
GNUNET_CONFIGURATION_iterate_sections (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                       GNUNET_CONFIGURATION_Section_Iterator iter,
                                       void *iter_cls)
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
  while (NULL != spos)
  {
    if (0 == strcasecmp (section, spos->name))
    {
      if (NULL == prev)
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
 * @param cls the destination configuration (`struct GNUNET_CONFIGURATION_Handle *`)
 * @param section section for the value
 * @param option option name of the value
 * @param value value to copy
 */
static void
copy_entry (void *cls,
            const char *section,
            const char *option,
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
 * Find a section entry from a configuration.
 *
 * @param cfg configuration to search in
 * @param section name of the section to look for
 * @return matching entry, NULL if not found
 */
static struct ConfigSection *
find_section (const struct GNUNET_CONFIGURATION_Handle *cfg,
             const char *section)
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
find_entry (const struct GNUNET_CONFIGURATION_Handle *cfg,
           const char *section,
           const char *key)
{
  struct ConfigSection *sec;
  struct ConfigEntry *pos;

  if (NULL == (sec = find_section (cfg, section)))
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
 * @param cls the diff configuration (`struct DiffHandle *`)
 * @param section section for the value (of the default conf.)
 * @param option option name of the value (of the default conf.)
 * @param value value to copy (of the default conf.)
 */
static void
compare_entries (void *cls,
                 const char *section,
                 const char *option,
		 const char *value)
{
  struct DiffHandle *dh = cls;
  struct ConfigEntry *entNew;

  entNew = find_entry (dh->cfg_default, section, option);
  if ( (NULL != entNew) &&
       (NULL != entNew->val) &&
       (0 == strcmp (entNew->val, value)) )
    return;
  GNUNET_CONFIGURATION_set_value_string (dh->cfgDiff, section, option, value);
}


/**
 * Compute configuration with only entries that have been changed
 *
 * @param cfg_default original configuration
 * @param cfg_new new configuration
 * @return configuration with only the differences, never NULL
 */
struct GNUNET_CONFIGURATION_Handle *
GNUNET_CONFIGURATION_get_diff (const struct GNUNET_CONFIGURATION_Handle *cfg_default,
			       const struct GNUNET_CONFIGURATION_Handle *cfg_new)
{
  struct DiffHandle diffHandle;

  diffHandle.cfgDiff = GNUNET_CONFIGURATION_create ();
  diffHandle.cfg_default = cfg_default;
  GNUNET_CONFIGURATION_iterate (cfg_new, &compare_entries, &diffHandle);
  return diffHandle.cfgDiff;
}


/**
 * Write only configuration entries that have been changed to configuration file
 *
 * @param cfg_default default configuration
 * @param cfg_new new configuration
 * @param filename where to write the configuration diff between default and new
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_write_diffs (const struct GNUNET_CONFIGURATION_Handle
                                  *cfg_default,
                                  const struct GNUNET_CONFIGURATION_Handle
                                  *cfg_new, const char *filename)
{
  int ret;
  struct GNUNET_CONFIGURATION_Handle *diff;

  diff = GNUNET_CONFIGURATION_get_diff (cfg_default, cfg_new);
  ret = GNUNET_CONFIGURATION_write (diff, filename);
  GNUNET_CONFIGURATION_destroy (diff);
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
  char *nv;

  e = find_entry (cfg, section, option);
  if (NULL != e)
  {
    if (NULL == value)
    {
      GNUNET_free_non_null (e->val);
      e->val = NULL;
    }
    else
    {
      nv = GNUNET_strdup (value);
      GNUNET_free_non_null (e->val);
      e->val = nv;
    }
    return;
  }
  sec = find_section (cfg, section);
  if (sec == NULL)
  {
    sec = GNUNET_new (struct ConfigSection);
    sec->name = GNUNET_strdup (section);
    sec->next = cfg->sections;
    cfg->sections = sec;
  }
  e = GNUNET_new (struct ConfigEntry);
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
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_number (const struct GNUNET_CONFIGURATION_Handle
                                       *cfg, const char *section,
                                       const char *option,
                                       unsigned long long *number)
{
  struct ConfigEntry *e;

  if (NULL == (e = find_entry (cfg, section, option)))
    return GNUNET_SYSERR;
  if (NULL == e->val)
    return GNUNET_SYSERR;
  if (1 != SSCANF (e->val, "%llu", number))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

/**
 * Get a configuration value that should be a floating point number.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param number where to store the floating value of the option
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_float  (const struct GNUNET_CONFIGURATION_Handle
                                       *cfg, const char *section,
                                       const char *option,
                                       float *number)
{
  struct ConfigEntry *e;

  if (NULL == (e = find_entry (cfg, section, option)))
    return GNUNET_SYSERR;
  if (NULL == e->val)
    return GNUNET_SYSERR;
  if (1 != SSCANF (e->val, "%f", number))
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
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_time (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                     const char *section,
                                     const char *option,
                                     struct GNUNET_TIME_Relative *time)
{
  struct ConfigEntry *e;

  if (NULL == (e = find_entry (cfg, section, option)))
    return GNUNET_SYSERR;
  if (NULL == e->val)
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
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_size (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                     const char *section,
                                     const char *option,
                                     unsigned long long *size)
{
  struct ConfigEntry *e;

  if (NULL == (e = find_entry (cfg, section, option)))
    return GNUNET_SYSERR;
  if (NULL == e->val)
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
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_string (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *section,
                                       const char *option,
                                       char **value)
{
  struct ConfigEntry *e;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to retrieve string `%s' in section `%s'\n",
       option,
       section);
  if ( (NULL == (e = find_entry (cfg, section, option))) ||
       (NULL == e->val) )
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
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_choice (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *section,
                                       const char *option,
                                       const char *const *choices,
                                       const char **value)
{
  struct ConfigEntry *e;
  unsigned int i;

  if (NULL == (e = find_entry (cfg, section, option)))
    return GNUNET_SYSERR;
  for (i = 0; NULL != choices[i]; i++)
    if (0 == strcasecmp (choices[i], e->val))
      break;
  if (NULL == choices[i])
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Configuration value '%s' for '%s'"
           " in section '%s' is not in set of legal choices\n"),
         e->val,
         option,
         section);
    return GNUNET_SYSERR;
  }
  *value = choices[i];
  return GNUNET_OK;
}


/**
 * Get crockford32-encoded fixed-size binary data from a configuration.
 *
 * @param cfg configuration to access
 * @param section section to access
 * @param option option to access
 * @param buf where to store the decoded binary result
 * @param buf_size exact number of bytes to store in @a buf
 * @return #GNUNET_OK on success
 *         #GNUNET_NO is the value does not exist
 *         #GNUNET_SYSERR on decoding error
 */
int
GNUNET_CONFIGURATION_get_data (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const char *section,
                               const char *option,
                               void *buf,
                               size_t buf_size)
{
  char *enc;
  int res;
  size_t data_size;

  if (GNUNET_OK !=
      (res = GNUNET_CONFIGURATION_get_value_string (cfg,
                                                    section,
                                                    option,
                                                    &enc)))
    return res;
  data_size = (strlen (enc) * 5) / 8;
  if (data_size != buf_size)
  {
    GNUNET_free (enc);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (enc,
                                     strlen (enc),
                                     buf, buf_size))
  {
    GNUNET_free (enc);
    return GNUNET_SYSERR;
  }
  GNUNET_free (enc);
  return GNUNET_OK;
}


/**
 * Test if we have a value for a particular option
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @return #GNUNET_YES if so, #GNUNET_NO if not.
 */
int
GNUNET_CONFIGURATION_have_value (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 const char *section,
                                 const char *option)
{
  struct ConfigEntry *e;

  if ((NULL == (e = find_entry (cfg, section, option))) || (NULL == e->val))
    return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Expand an expression of the form "$FOO/BAR" to "DIRECTORY/BAR"
 * where either in the "PATHS" section or the environtment "FOO" is
 * set to "DIRECTORY".  We also support default expansion,
 * i.e. ${VARIABLE:-default} will expand to $VARIABLE if VARIABLE is
 * set in PATHS or the environment, and otherwise to "default".  Note
 * that "default" itself can also be a $-expression, thus
 * "${VAR1:-{$VAR2}}" will expand to VAR1 and if that is not defined
 * to VAR2.
 *
 * @param cfg configuration to use for path expansion
 * @param orig string to $-expand (will be freed!)
 * @param depth recursion depth, used to detect recursive expansions
 * @return $-expanded string
 */
static char *
expand_dollar (const struct GNUNET_CONFIGURATION_Handle *cfg,
               char *orig,
               unsigned int depth)
{
  int i;
  char *prefix;
  char *result;
  char *start;
  const char *post;
  const char *env;
  char *def;
  char *end;
  unsigned int lopen;
  char erased_char;
  char *erased_pos;
  size_t len;

  if (NULL == orig)
    return NULL;
  if (depth > 128)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Recursive expansion suspected, aborting $-expansion for term `%s'\n"),
         orig);
    return orig;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to $-expand %s\n", orig);
  if ('$' != orig[0])
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Doesn't start with $ - not expanding\n");
    return orig;
  }
  erased_char = 0;
  erased_pos = NULL;
  if ('{' == orig[1])
  {
    start = &orig[2];
    lopen = 1;
    end = &orig[1];
    while (lopen > 0)
    {
      end++;
      switch (*end)
      {
      case '}':
        lopen--;
        break;
      case '{':
        lopen++;
        break;
      case '\0':
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _("Missing closing `%s' in option `%s'\n"),
             "}",
             orig);
        return orig;
      default:
        break;
      }
    }
    erased_char = *end;
    erased_pos = end;
    *end = '\0';
    post = end + 1;
    def = strchr (orig, ':');
    if (NULL != def)
    {
      *def = '\0';
      def++;
      if ( ('-' == *def) ||
           ('=' == *def) )
        def++;
      def = GNUNET_strdup (def);
    }
  }
  else
  {
    start = &orig[1];
    def = NULL;
    i = 0;
    while ( (orig[i] != '/') &&
            (orig[i] != '\\') &&
            (orig[i] != '\0')  &&
            (orig[i] != ' ') )
      i++;
    if (orig[i] == '\0')
    {
      post = "";
    }
    else
    {
      erased_char = orig[i];
      erased_pos = &orig[i];
      orig[i] = '\0';
      post = &orig[i + 1];
    }
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Split into `%s' and `%s' with default %s\n",
       start,
       post,
       def);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "PATHS",
                                             start,
                                             &prefix))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Filename for `%s' is not in PATHS config section\n",
         start);
    if (NULL == (env = getenv (start)))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "`%s' is not an environment variable\n",
           start);
      /* try default */
      def = expand_dollar (cfg, def, depth + 1);
      env = def;
    }
    if (NULL == env)
    {
      start = GNUNET_strdup (start);
      if (erased_pos)
        *erased_pos = erased_char;
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _("Failed to expand `%s' in `%s' as it is neither found in [PATHS] nor defined as an environmental variable\n"),
           start, orig);
      GNUNET_free (start);
      return orig;
    }
    prefix = GNUNET_strdup (env);
  }
  prefix = GNUNET_CONFIGURATION_expand_dollar (cfg, prefix);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Prefix is `%s'\n",
       prefix);
  if ( (erased_pos) && ('}' != erased_char) )
  {
    len = strlen (prefix) + 1;
    prefix = GNUNET_realloc (prefix, len + 1);
    prefix[len - 1] = erased_char;
    prefix[len] = '\0';
  }
  result = GNUNET_malloc (strlen (prefix) + strlen (post) + 1);
  strcpy (result, prefix);
  strcat (result, post);
  GNUNET_free_non_null (def);
  GNUNET_free (prefix);
  GNUNET_free (orig);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Expanded to `%s'\n",
       result);
  return result;
}


/**
 * Expand an expression of the form "$FOO/BAR" to "DIRECTORY/BAR"
 * where either in the "PATHS" section or the environtment "FOO" is
 * set to "DIRECTORY".  We also support default expansion,
 * i.e. ${VARIABLE:-default} will expand to $VARIABLE if VARIABLE is
 * set in PATHS or the environment, and otherwise to "default".  Note
 * that "default" itself can also be a $-expression, thus
 * "${VAR1:-{$VAR2}}" will expand to VAR1 and if that is not defined
 * to VAR2.
 *
 * @param cfg configuration to use for path expansion
 * @param orig string to $-expand (will be freed!).  Note that multiple
 *          $-expressions can be present in this string.  They will all be
 *          $-expanded.
 * @return $-expanded string
 */
char *
GNUNET_CONFIGURATION_expand_dollar (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                    char *orig)
{
  char *dup;
  size_t i;
  size_t len;

  for (i = 0; '\0' != orig[i]; i++)
  {
    if ('$' != orig[i])
      continue;
    dup = GNUNET_strdup (orig + i);
    dup = expand_dollar (cfg, dup, 0);
    len = strlen (dup) + 1;
    orig = GNUNET_realloc (orig, i + len);
    memcpy (orig + i, dup, len);
    GNUNET_free (dup);
  }
  return orig;
}


/**
 * Get a configuration value that should be a string.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param value will be set to a freshly allocated configuration
 *        value, or NULL if option is not specified
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_get_value_filename (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                         const char *section,
                                         const char *option,
                                         char **value)
{
  char *tmp;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to retrieve filename `%s' in section `%s'\n",
       option,
       section);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, section, option, &tmp))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failed to retrieve filename\n");
    *value = NULL;
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Retrieved filename `%s', $-expanding\n", tmp);
  tmp = GNUNET_CONFIGURATION_expand_dollar (cfg, tmp);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Expanded to filename `%s', *nix-expanding\n", tmp);
  *value = GNUNET_STRINGS_filename_expand (tmp);
  GNUNET_free (tmp);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Filename result is `%s'\n", *value);
  if (*value == NULL)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Get a configuration value that should be in a set of
 * "YES" or "NO".
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @return #GNUNET_YES, #GNUNET_NO or #GNUNET_SYSERR
 */
int
GNUNET_CONFIGURATION_get_value_yesno (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                      const char *section,
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
 * @param cb_cls closure for @a cb
 * @return number of filenames iterated over, -1 on error
 */
int
GNUNET_CONFIGURATION_iterate_value_filenames (const struct GNUNET_CONFIGURATION_Handle *cfg,
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
 * @return #GNUNET_OK if the names do not match, #GNUNET_SYSERR if they do
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
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if the filename already in the list
 *         #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_append_value_filename (struct GNUNET_CONFIGURATION_Handle *cfg,
                                            const char *section,
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
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if the filename is not in the list,
 *         #GNUNET_SYSERR on error
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
 * Wrapper around #GNUNET_CONFIGURATION_parse.  Called on each
 * file in a directory, we trigger parsing on those files that
 * end with ".conf".
 *
 * @param cls the cfg
 * @param filename file to parse
 * @return #GNUNET_OK on success
 */
static int
parse_configuration_file (void *cls, const char *filename)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  char * ext;
  int ret;

  /* Examine file extension */
  ext = strrchr (filename, '.');
  if ((NULL == ext) || (0 != strcmp (ext, ".conf")))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Skipping file `%s'\n",
                filename);
    return GNUNET_OK;
  }

  ret = GNUNET_CONFIGURATION_parse (cfg, filename);
  return ret;
}


/**
 * Load default configuration.  This function will parse the
 * defaults from the given defaults_d directory.
 *
 * @param cfg configuration to update
 * @param defaults_d directory with the defaults
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_CONFIGURATION_load_from (struct GNUNET_CONFIGURATION_Handle *cfg,
				const char *defaults_d)
{
  if (GNUNET_SYSERR ==
      GNUNET_DISK_directory_scan (defaults_d, &parse_configuration_file, cfg))
    return GNUNET_SYSERR;       /* no configuration at all found */
  return GNUNET_OK;
}


/* end of configuration.c */
