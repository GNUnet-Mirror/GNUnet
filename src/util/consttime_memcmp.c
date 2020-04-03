/*
The MIT License (MIT)

Copyright (c) 2015 Christophe Meessen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/* Minimally modified for libgnunetutil: added license header
   (from https://github.com/chmike/cst_time_memcmp, LICENSE file), and
   renamed the exported symbol: */
#define consttime_memcmp GNUNET_memcmp_ct_
/* Rest of the file is 'original' */


#include <stddef.h>
#include <inttypes.h>

/*
 * "constant time" memcmp.  Time taken depends on the buffer length, of
 * course, but not on the content of the buffers.
 *
 * Just like the ordinary memcmp function, the return value is
 * tri-state: <0, 0, or >0.  However, applications that need a
 * constant-time memory comparison function usually need only a
 * two-state result, signalling only whether the inputs were identical
 * or different, but not signalling which of the inputs was larger.
 * This code could be made significantly faster and simpler if the
 * requirement for a tri-state result were removed.
 *
 * In order to protect against adversaries who can observe timing,
 * cache hits or misses, page faults, etc., and who can use such
 * observations to learn something about the relationship between the
 * contents of the two buffers, we have to perform exactly the same
 * instructions and memory accesses regardless of the contents of the
 * buffers.  We can't stop as soon as we find a difference, we can't
 * take different conditional branches depending on the data, and we
 * can't use different pointers or array indexes depending on the data.
 *
 * Further reading:
 *
 * .Rs
 * .%A Paul C. Kocher
 * .%T Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems
 * .%D 1996
 * .%J CRYPTO 1996
 * .%P 104-113
 * .%U http://www.cryptography.com/timingattack/paper.html
 * .%U http://www.webcitation.org/query?url=http%3A%2F%2Fwww.cryptography.com%2Ftimingattack%2Fpaper.html&date=2012-10-17
 * .Re
 *
 * .Rs
 * .%A D. Boneh
 * .%A D. Brumley
 * .%T Remote timing attacks are practical
 * .%D August 2003
 * .%J Proceedings of the 12th Usenix Security Symposium, 2003
 * .%U https://crypto.stanford.edu/~dabo/abstracts/ssl-timing.html
 * .%U http://www.webcitation.org/query?url=https%3A%2F%2Fcrypto.stanford.edu%2F%7Edabo%2Fabstracts%2Fssl-timing.html&date=2012-10-17
 * .%U http://www.webcitation.org/query?url=http%3A%2F%2Fcrypto.stanford.edu%2F%7Edabo%2Fpubs%2Fpapers%2Fssl-timing.pdf&date=2012-10-17
 * .Es
 *
 * .Rs
 * .%A Coda Hale
 * .%T A Lesson In Timing Attacks (or, Don't use MessageDigest.isEquals)
 * .%D 13 Aug 2009
 * .%U http://codahale.com/a-lesson-in-timing-attacks/
 * .%U http://www.webcitation.org/query?url=http%3A%2F%2Fcodahale.com%2Fa-lesson-in-timing-attacks%2F&date=2012-10-17
 * .Re
 *
 */

/*
 * A note on portability:
 *
 * We assume that char is exactly 8 bits, the same as uint8_t, and that
 * integer types with exactly 16 bits and exactly 32 bits exist.  (If
 * there is ever a need to change this, then the actual requirement is
 * that we need a type that is at least two bits wider than char, and
 * another type that is at least two bits wider than that, or we need to
 * fake it somehow.)
 *
 * We do not assume any particular size for the plain "int" type, except
 * that it is at least 16 bits, as is guaranteed by the C language
 * standard.
 *
 * We do not assume that signed integer overflow is harmless.  We
 * ensure that signed integer overflow does not occur, so that
 * implementation-defined overflow behaviour is not invoked.
 *
 * We rely on the C standard's guarantees regarding the wraparound
 * behaviour of unsigned integer arithmetic, and on the analagous
 * guarantees regarding conversions from signed types to narrower
 * unsigned types.
 *
 * We do not assume that the platform uses two's complement arithmetic.
 */

/*
 * How hard do we have to try to prevent unwanted compiler optimisations?
 *
 * Try compiling with "#define USE_VOLATILE_TEMPORARY 0", and examine
 * the compiler output.  If the only conditional tests in the entire
 * function are to test whether len is zero, then all is well, but try
 * again with different optimisation flags to be sure.  If the compiler
 * emitted code with conditional tests that do anything other than
 * testing whether len is zero, then that's a problem, so try again with
 * "#define USE_VOLATILE_TEMPORARY 1".  If it's still bad, then you are
 * out of luck.
 */
#define USE_VOLATILE_TEMPORARY 0

int
consttime_memcmp (const void *b1, const void *b2, size_t len)
{
  const uint8_t *c1, *c2;
  uint16_t d, r, m;

#if USE_VOLATILE_TEMPORARY
  volatile uint16_t v;
#else
  uint16_t v;
#endif

  c1 = b1;
  c2 = b2;

  r = 0;
  while (len)
  {
    /*
     * Take the low 8 bits of r (in the range 0x00 to 0xff,
     * or 0 to 255);
     * As explained elsewhere, the low 8 bits of r will be zero
     * if and only if all bytes compared so far were identical;
     * Zero-extend to a 16-bit type (in the range 0x0000 to
     * 0x00ff);
     * Add 255, yielding a result in the range 255 to 510;
     * Save that in a volatile variable to prevent
     * the compiler from trying any shortcuts (the
     * use of a volatile variable depends on "#ifdef
     * USE_VOLATILE_TEMPORARY", and most compilers won't
     * need it);
     * Divide by 256 yielding a result of 1 if the original
     * value of r was non-zero, or 0 if r was zero;
     * Subtract 1, yielding 0 if r was non-zero, or -1 if r
     * was zero;
     * Convert to uint16_t, yielding 0x0000 if r was
     * non-zero, or 0xffff if r was zero;
     * Save in m.
     */v = ((uint16_t) (uint8_t) r) + 255;
    m = v / 256 - 1;

    /*
     * Get the values from *c1 and *c2 as uint8_t (each will
     * be in the range 0 to 255, or 0x00 to 0xff);
     * Convert them to signed int values (still in the
     * range 0 to 255);
     * Subtract them using signed arithmetic, yielding a
     * result in the range -255 to +255;
     * Convert to uint16_t, yielding a result in the range
     * 0xff01 to 0xffff (for what was previously -255 to
     * -1), or 0, or in the range 0x0001 to 0x00ff (for what
     * was previously +1 to +255).
     */d = (uint16_t) ((int) *c1 - (int) *c2);

    /*
     * If the low 8 bits of r were previously 0, then m
     * is now 0xffff, so (d & m) is the same as d, so we
     * effectively copy d to r;
     * Otherwise, if r was previously non-zero, then m is
     * now 0, so (d & m) is zero, so leave r unchanged.
     * Note that the low 8 bits of d will be zero if and
     * only if d == 0, which happens when *c1 == *c2.
     * The low 8 bits of r are thus zero if and only if the
     * entirety of r is zero, which happens if and only if
     * all bytes compared so far were equal.  As soon as a
     * non-zero value is stored in r, it remains unchanged
     * for the remainder of the loop.
     */r |= (d & m);

    /*
     * Increment pointers, decrement length, and loop.
     */
    ++c1;
    ++c2;
    --len;
  }

  /*
   * At this point, r is an unsigned value, which will be 0 if the
   * final result should be zero, or in the range 0x0001 to 0x00ff
   * (1 to 255) if the final result should be positive, or in the
   * range 0xff01 to 0xffff (65281 to 65535) if the final result
   * should be negative.
   *
   * We want to convert the unsigned values in the range 0xff01
   * to 0xffff to signed values in the range -255 to -1, while
   * converting the other unsigned values to equivalent signed
   * values (0, or +1 to +255).
   *
   * On a machine with two's complement arithmetic, simply copying
   * the underlying bits (with sign extension if int is wider than
   * 16 bits) would do the job, so something like this might work:
   *
   *     return (int16_t)r;
   *
   * However, that invokes implementation-defined behaviour,
   * because values larger than 32767 can't fit in a signed 16-bit
   * integer without overflow.
   *
   * To avoid any implementation-defined behaviour, we go through
   * these contortions:
   *
   * a. Calculate ((uint32_t)r + 0x8000).  The cast to uint32_t
   *    it to prevent problems on platforms where int is narrower
   *    than 32 bits.  If int is a larger than 32-bits, then the
   *    usual arithmetic conversions cause this addition to be
   *    done in unsigned int arithmetic.  If int is 32 bits
   *    or narrower, then this addition is done in uint32_t
   *    arithmetic.  In either case, no overflow or wraparound
   *    occurs, and the result from this step has a value that
   *    will be one of 0x00008000 (32768), or in the range
   *    0x00008001 to 0x000080ff (32769 to 33023), or in the range
   *    0x00017f01 to 0x00017fff (98049 to 98303).
   *
   * b. Cast the result from (a) to uint16_t.  This effectively
   *    discards the high bits of the result, in a way that is
   *    well defined by the C language.  The result from this step
   *    will be of type uint16_t, and its value will be one of
   *    0x8000 (32768), or in the range 0x8001 to 0x80ff (32769 to
   *    33023), or in the range 0x7f01 to 0x7fff (32513 to
   *    32767).
   *
   * c. Cast the result from (b) to int32_t.  We use int32_t
   *    instead of int because we need a type that's strictly
   *    larger than 16 bits, and the C standard allows
   *    implementations where int is only 16 bits.  The result
   *    from this step will be of type int32_t, and its value wll
   *    be one of 0x00008000 (32768), or in the range 0x00008001
   *    to 0x000080ff (32769 to 33023), or in the range 0x00007f01
   *    to 0x00007fff (32513 to 32767).
   *
   * d. Take the result from (c) and subtract 0x8000 (32768) using
   *    signed int32_t arithmetic.  The result from this step will
   *    be of type int32_t and the value will be one of
   *    0x00000000 (0), or in the range 0x00000001 to 0x000000ff
   *    (+1 to +255), or in the range 0xffffff01 to 0xffffffff
   *    (-255 to -1).
   *
   * e. Cast the result from (d) to int.  This does nothing
   *    interesting, except to make explicit what would have been
   *    implicit in the return statement.  The final result is an
   *    int in the range -255 to +255.
   *
   * Unfortunately, compilers don't seem to be good at figuring
   * out that most of this can be optimised away by careful choice
   * of register width and sign extension.
   *
   */return (/*e*/ int) (/*d*/
    (/*c*/ int32_t) (/*b*/ uint16_t) (/*a*/ (uint32_t) r + 0x8000)
    - 0x8000);
}
