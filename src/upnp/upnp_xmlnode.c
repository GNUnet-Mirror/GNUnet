/**
 * @file xmlnode.c XML DOM functions
 *
 * gaim
 *
 * Gaim is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* A lot of this code at least resembles the code in libxode, but since
 * libxode uses memory pools that we simply have no need for, I decided to
 * write my own stuff.  Also, re-writing this lets me be as lightweight
 * as I want to be.  Thank you libxode for giving me a good starting point */

#include "platform.h"

#include "util.h"
#include "gnunet_util.h"
#include "xmlnode.h"

#include <libxml/parser.h>
#include <string.h>


#ifdef _WIN32
# define NEWLINE_S "\r\n"
#else
# define NEWLINE_S "\n"
#endif

#define TRUE GNUNET_YES
#define FALSE GNUNET_NO

#define g_return_if_fail(a) if(!(a)) return;
#define g_return_val_if_fail(a, val) if(!(a)) return (val);

/**
 * The valid types for an xmlnode
 */
typedef enum _XMLNodeType
{
  XMLNODE_TYPE_TAG,     /**< Just a tag */
  XMLNODE_TYPE_ATTRIB,          /**< Has attributes */
  XMLNODE_TYPE_DATA     /**< Has data */
} XMLNodeType;

typedef struct
{
  xmlnode *current;
  xmlnode **nodes;
  unsigned int pos;
  unsigned int size;
} XMLNodePool;

struct _xmlnode
{
  char *name;           /**< The name of the node. */
  char *xmlns;          /**< The namespace of the node */
  XMLNodeType type;     /**< The type of the node. */
  char *data;           /**< The data for the node. */
  size_t data_sz;               /**< The size of the data. */
  struct _xmlnode *parent;  /**< The parent node or @c NULL.*/
  struct _xmlnode *child;       /**< The child node or @c NULL.*/
  struct _xmlnode *lastchild;  /**< The last child node or @c NULL.*/
  struct _xmlnode *next;        /**< The next node or @c NULL. */
  XMLNodePool *pool;
  int free_pool;                /* set to GNUNET_YES for the root node, which must free the pool */
};


static void *
g_memdup (const void *data, size_t s)
{
  void *ret;

  ret = GNUNET_malloc (s);
  memcpy (ret, data, s);
  return ret;
}

static char *
g_string_append_len (char *prefix, const void *data, size_t s)
{
  char *ret;

  ret = g_strdup_printf ("%s%.*s", prefix, s, data);
  GNUNET_free (prefix);
  return ret;
}

static xmlnode *
new_node (const char *name, XMLNodeType type, void *user_data)
{
  xmlnode *node = GNUNET_malloc (sizeof (xmlnode));

  node->name = name == NULL ? NULL : GNUNET_strdup (name);
  node->type = type;
  node->pool = user_data;
  if (node->pool->size == node->pool->pos)
    GNUNET_array_grow (node->pool->nodes, node->pool->size,
                       node->pool->size * 2 + 64);
  node->pool->nodes[node->pool->pos++] = node;
  node->free_pool = 0;
  return node;
}

static xmlnode *
xmlnode_new (const char *name, void *user_data)
{
  g_return_val_if_fail (name != NULL, NULL);
  return new_node (name, XMLNODE_TYPE_TAG, user_data);
}

static void
xmlnode_insert_child (xmlnode * parent, xmlnode * child)
{
  g_return_if_fail (parent != NULL);
  g_return_if_fail (child != NULL);

  child->parent = parent;
  if (parent->lastchild)
    parent->lastchild->next = child;
  else
    parent->child = child;
  parent->lastchild = child;
}

static xmlnode *
xmlnode_new_child (xmlnode * parent, const char *name, void *user_data)
{
  xmlnode *node;

  g_return_val_if_fail (parent != NULL, NULL);
  g_return_val_if_fail (name != NULL, NULL);
  node = new_node (name, XMLNODE_TYPE_TAG, user_data);
  xmlnode_insert_child (parent, node);
  return node;
}

static void
xmlnode_insert_data (xmlnode * node,
                     const char *data, int size, void *user_data)
{
  xmlnode *child;
  size_t real_size;

  g_return_if_fail (node != NULL);
  g_return_if_fail (data != NULL);
  g_return_if_fail (size != 0);
  real_size = size == -1 ? strlen (data) : size;
  child = new_node (NULL, XMLNODE_TYPE_DATA, user_data);
  child->data = g_memdup (data, real_size);
  child->data_sz = real_size;
  xmlnode_insert_child (node, child);
}

static void
xmlnode_remove_attrib (xmlnode * node, const char *attr)
{
  xmlnode *attr_node, *sibling = NULL;

  g_return_if_fail (node != NULL);
  g_return_if_fail (attr != NULL);

  for (attr_node = node->child; attr_node; attr_node = attr_node->next)
    {
      if (attr_node->type == XMLNODE_TYPE_ATTRIB &&
          !strcmp (attr_node->name, attr))
        {
          if (node->child == attr_node)
            {
              node->child = attr_node->next;
            }
          else
            {
              sibling->next = attr_node->next;
            }
          if (node->lastchild == attr_node)
            {
              node->lastchild = sibling;
            }
          xmlnode_free (attr_node);
          return;
        }
      sibling = attr_node;
    }
}

static void
xmlnode_set_attrib (xmlnode * node,
                    const char *attr, const char *value, void *user_data)
{
  xmlnode *attrib_node;

  g_return_if_fail (node != NULL);
  g_return_if_fail (attr != NULL);
  g_return_if_fail (value != NULL);
  xmlnode_remove_attrib (node, attr);
  attrib_node = new_node (attr, XMLNODE_TYPE_ATTRIB, user_data);
  attrib_node->data = GNUNET_strdup (value);
  xmlnode_insert_child (node, attrib_node);
}

static void
xmlnode_set_namespace (xmlnode * node, const char *xmlns)
{
  g_return_if_fail (node != NULL);
  GNUNET_free_non_null (node->xmlns);
  node->xmlns = GNUNET_strdup (xmlns);
}

static const char *
xmlnode_get_namespace (xmlnode * node)
{
  g_return_val_if_fail (node != NULL, NULL);
  return node->xmlns;
}

static void
freePool (XMLNodePool * pool)
{
  unsigned int i;
  xmlnode *x;

  for (i = 0; i < pool->pos; i++)
    {
      x = pool->nodes[i];
      GNUNET_free_non_null (x->name);
      GNUNET_free_non_null (x->data);
      GNUNET_free_non_null (x->xmlns);
      GNUNET_free (x);
    }
  GNUNET_array_grow (pool->nodes, pool->size, 0);
  GNUNET_free (pool);
}

void
xmlnode_free (xmlnode * node)
{
  g_return_if_fail (node != NULL);
  if (node->free_pool != GNUNET_YES)
    return;
  freePool (node->pool);
}

static xmlnode *
xmlnode_get_child_with_namespace (const xmlnode * parent,
                                  const char *name, const char *ns)
{
  xmlnode *x;
  xmlnode *ret = NULL;
  char *parent_name;
  char *child_name;

  if (parent == NULL)
    return NULL;
  if (name == NULL)
    return NULL;

  parent_name = GNUNET_strdup (name);
  child_name = strstr (parent_name, "/");
  if (child_name != NULL)
    {
      child_name[0] = '\0';
      child_name++;
    }

  for (x = parent->child; x; x = x->next)
    {
      const char *xmlns = NULL;
      if (ns)
        xmlns = xmlnode_get_namespace (x);

      if (x->type == XMLNODE_TYPE_TAG && name
          && !strcmp (parent_name, x->name) && (!ns
                                                || (xmlns
                                                    && !strcmp (ns, xmlns))))
        {
          ret = x;
          break;
        }
    }

  if (child_name && ret)
    ret = xmlnode_get_child (ret, child_name);

  GNUNET_free (parent_name);
  return ret;
}

xmlnode *
xmlnode_get_child (const xmlnode * parent, const char *name)
{
  return xmlnode_get_child_with_namespace (parent, name, NULL);
}

char *
xmlnode_get_data (xmlnode * node)
{
  char *str = NULL;
  xmlnode *c;

  if (node == NULL)
    return NULL;
  for (c = node->child; c; c = c->next)
    {
      if (c->type == XMLNODE_TYPE_DATA)
        {
          if (!str)
            str = GNUNET_strdup ("");
          str = g_string_append_len (str, c->data, c->data_sz);
        }
    }
  if (str == NULL)
    return NULL;

  return str;
}

static void
xmlnode_parser_element_start_libxml (void *user_data,
                                     const xmlChar * element_name,
                                     const xmlChar * prefix,
                                     const xmlChar * xmlns,
                                     int nb_namespaces,
                                     const xmlChar ** namespaces,
                                     int nb_attributes,
                                     int nb_defaulted,
                                     const xmlChar ** attributes)
{
  XMLNodePool *xpd = user_data;
  xmlnode *node;
  int i;

  if (!element_name)
    return;
  if (xpd->current)
    node =
      xmlnode_new_child (xpd->current, (const char *) element_name,
                         user_data);
  else
    node = xmlnode_new ((const char *) element_name, user_data);

  xmlnode_set_namespace (node, (const char *) xmlns);

  for (i = 0; i < nb_attributes * 5; i += 5)
    {
      char *txt;
      int attrib_len = attributes[i + 4] - attributes[i + 3];
      char *attrib = GNUNET_malloc (attrib_len + 1);
      memcpy (attrib, attributes[i + 3], attrib_len);
      attrib[attrib_len] = '\0';
      txt = attrib;
      attrib = gaim_unescape_html (txt);
      GNUNET_free (txt);
      xmlnode_set_attrib (node, (const char *) attributes[i], attrib,
                          user_data);
      GNUNET_free (attrib);
    }
  xpd->current = node;
}

static void
xmlnode_parser_element_end_libxml (void *user_data,
                                   const xmlChar * element_name,
                                   const xmlChar * prefix,
                                   const xmlChar * xmlns)
{
  XMLNodePool *xpd = user_data;

  if (!element_name || !xpd->current)
    return;
  if (xpd->current->parent)
    {
      if (!xmlStrcmp ((xmlChar *) xpd->current->name, element_name))
        xpd->current = xpd->current->parent;
    }
}

static void
xmlnode_parser_element_text_libxml (void *user_data,
                                    const xmlChar * text, int text_len)
{
  XMLNodePool *xpd = user_data;

  if (!xpd->current || !text || !text_len)
    return;
  xmlnode_insert_data (xpd->current,
                       (const char *) text, text_len, user_data);
}

static xmlSAXHandler xmlnode_parser_libxml = {
  .internalSubset = NULL,
  .isStandalone = NULL,
  .hasInternalSubset = NULL,
  .hasExternalSubset = NULL,
  .resolveEntity = NULL,
  .getEntity = NULL,
  .entityDecl = NULL,
  .notationDecl = NULL,
  .attributeDecl = NULL,
  .elementDecl = NULL,
  .unparsedEntityDecl = NULL,
  .setDocumentLocator = NULL,
  .startDocument = NULL,
  .endDocument = NULL,
  .startElement = NULL,
  .endElement = NULL,
  .reference = NULL,
  .characters = xmlnode_parser_element_text_libxml,
  .ignorableWhitespace = NULL,
  .processingInstruction = NULL,
  .comment = NULL,
  .warning = NULL,
  .error = NULL,
  .fatalError = NULL,
  .getParameterEntity = NULL,
  .cdataBlock = NULL,
  .externalSubset = NULL,
  .initialized = XML_SAX2_MAGIC,
  ._private = NULL,
  .startElementNs = xmlnode_parser_element_start_libxml,
  .endElementNs = xmlnode_parser_element_end_libxml,
  .serror = NULL
};

xmlnode *
xmlnode_from_str (const char *str, int size)
{
  XMLNodePool *xpd;
  xmlnode *ret;
  size_t real_size;

  g_return_val_if_fail (str != NULL, NULL);

  real_size = size < 0 ? strlen (str) : size;
  xpd = GNUNET_malloc (sizeof (XMLNodePool));
  memset (xpd, 0, sizeof (XMLNodePool));
  if (xmlSAXUserParseMemory (&xmlnode_parser_libxml, xpd, str, real_size) < 0)
    {
      freePool (xpd);
      return NULL;
    }
  ret = xpd->current;
  ret->free_pool = GNUNET_YES;
  return ret;
}

xmlnode *
xmlnode_get_next_twin (xmlnode * node)
{
  xmlnode *sibling;
  const char *ns = xmlnode_get_namespace (node);

  g_return_val_if_fail (node != NULL, NULL);
  g_return_val_if_fail (node->type == XMLNODE_TYPE_TAG, NULL);

  for (sibling = node->next; sibling; sibling = sibling->next)
    {
      const char *xmlns = NULL;
      if (ns)
        xmlns = xmlnode_get_namespace (sibling);

      if (sibling->type == XMLNODE_TYPE_TAG
          && !strcmp (node->name, sibling->name) && (!ns
                                                     || (xmlns
                                                         && !strcmp (ns,
                                                                     xmlns))))
        return sibling;
    }
  return NULL;
}
