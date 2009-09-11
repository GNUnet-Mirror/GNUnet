/**
 * @file upnp/upnp_xmlnode.h XML DOM functions
 * @ingroup core
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
#ifndef _GGAIM_XMLNODE_H_
#define _GGAIM_XMLNODE_H_


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * An xmlnode.
 */
  typedef struct _xmlnode xmlnode;

/**
 * Gets a child node named name.
 *
 * @param parent The parent node.
 * @param name   The child's name.
 *
 * @return The child or NULL.
 */
  xmlnode *xmlnode_get_child (const xmlnode * parent, const char *name);

/**
 * Gets the next node with the same name as node.
 *
 * @param node The node of a twin to find.
 *
 * @return The twin of node or NULL.
 */
  xmlnode *xmlnode_get_next_twin (xmlnode * node);

/**
 * Gets data from a node.
 *
 * @param node The node to get data from.
 *
 * @return The data from the node.  You must g_free
 *         this string when finished using it.
 */
  char *xmlnode_get_data (xmlnode * node);

/**
 * Creates a node from a string of XML.  Calling this on the
 * root node of an XML document will parse the entire document
 * into a tree of nodes, and return the xmlnode of the root.
 *
 * @param str  The string of xml.
 * @param size The size of the string, or -1 if @a str is
 *             NUL-terminated.
 *
 * @return The new node.
 */
  xmlnode *xmlnode_from_str (const char *str, int size);

/**
 * Frees a node and all of it's children.
 *
 * @param node The node to free.
 */
  void xmlnode_free (xmlnode * node);

#ifdef __cplusplus
}
#endif

#endif                          /* _GAIM_XMLNODE_H_ */
