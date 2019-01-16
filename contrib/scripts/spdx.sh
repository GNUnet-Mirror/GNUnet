#!/bin/sh
# NetBSD compatible sed to insert spdx into headers.
# This is a one-shot script, future runs would result in duplicate
# lines.
#
# Copyright (C) 2019 ng0 <ng0@n0.is>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL 
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED 
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL 
# THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR 
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, 
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN 
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# SPDX-License-Identifier: 0BSD

for x in $(egrep -nr -m1 "GNU Affero General Public License" . | cut -f1 -d':'); do
  sed -i -e '/along with this program.  If not, see <http:\/\/www.gnu.org\/licenses\/>./a\
\
     SPDX-License-Identifier: AGPL3.0-or-later' $x;
done
