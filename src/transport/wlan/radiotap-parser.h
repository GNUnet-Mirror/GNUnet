/*
 *  Copyright (c) 2007, 2008, Andy Green <andy@warmcat.com>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#define	__user
#include "byteorder.h"
#include <stdint.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

#ifndef unlikely
#define	unlikely(x) (x)
#endif

#include "ieee80211_radiotap.h"


/*
 * Radiotap header iteration
 *   implemented in src/radiotap-parser.c
 *
 * call __ieee80211_radiotap_iterator_init() to init a semi-opaque iterator
 * struct ieee80211_radiotap_iterator (no need to init the struct beforehand)
 * then loop calling __ieee80211_radiotap_iterator_next()... it returns -1
 * if there are no more args in the header, or the next argument type index
 * that is present.  The iterator's this_arg member points to the start of the
 * argument associated with the current argument index that is present,
 * which can be found in the iterator's this_arg_index member.  This arg
 * index corresponds to the IEEE80211_RADIOTAP_... defines.
 */
/**
 * struct ieee80211_radiotap_iterator - tracks walk thru present radiotap args
 * @rtheader: pointer to the radiotap header we are walking through
 * @max_length: length of radiotap header in cpu byte ordering
 * @this_arg_index: IEEE80211_RADIOTAP_... index of current arg
 * @this_arg: pointer to current radiotap arg
 * @arg_index: internal next argument index
 * @arg: internal next argument pointer
 * @next_bitmap: internal pointer to next present u32
 * @bitmap_shifter: internal shifter for curr u32 bitmap, b0 set == arg present
 */

struct ieee80211_radiotap_iterator
{
  struct ieee80211_radiotap_header *rtheader;
  int max_length;
  int this_arg_index;
  u8 *this_arg;

  int arg_index;
  u8 *arg;
  u32 *next_bitmap;
  u32 bitmap_shifter;
};

int ieee80211_radiotap_iterator_init (struct ieee80211_radiotap_iterator
                                      *iterator,
                                      struct ieee80211_radiotap_header
                                      *radiotap_header, int max_length);

int ieee80211_radiotap_iterator_next (struct ieee80211_radiotap_iterator
                                      *iterator);
