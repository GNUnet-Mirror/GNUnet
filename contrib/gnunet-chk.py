#!/usr/bin/python
# This file is part of GNUnet.
# (C) 2013 Christian Grothoff (and other contributing authors)
#
# GNUnet is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 3, or (at your
# option) any later version.
#
# GNUnet is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNUnet; see the file COPYING.  If not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA 02110-1301, USA.
# 
# File:    gnunet-chk.py
# Brief:   Computes GNUNET style Content Hash Key for a given file
# Author:  Sree Harsha Totakura

from hashlib import sha512
import logging
import os
import getopt
import sys
from Crypto.Cipher import AES

# Defaults
DBLOCK_SIZE = (32 * 1024)   # Data block size

# Pick a multiple of 2 here to achive 8-byte alignment!  We also
# probably want DBlocks to have (roughly) the same size as IBlocks.
# With SHA-512, the optimal value is 32768 byte / 128 byte = 256 (128
# byte = 2 * 512 bits).  DO NOT CHANGE!
CHK_PER_INODE = 256

CHK_HASH_SIZE = 64              # SHA-512 hash = 512 bits = 64 bytes

CHK_QUERY_SIZE = CHK_HASH_SIZE  # Again a SHA-512 hash

GNUNET_FS_URI_PREFIX = "gnunet://fs/" # FS CHK URI prefix

GNUNET_FS_URI_CHK_INFIX = "chk/" # FS CHK URI infix


def encode_data_to_string (data):
    """Returns an ASCII encoding of the given data block like
    GNUNET_STRINGS_data_to_string() function.
    
    data: A bytearray representing the block of data which has to be encoded
    """
    echart = "0123456789ABCDEFGHIJKLMNOPQRSTUV"    
    assert (None != data)
    assert (bytearray == type(data))
    size = len(data)
    assert (0 != size)
    vbit = 0
    wpos = 0
    rpos = 0
    bits = 0
    out = ""
    while (rpos < size) or (vbit > 0):
        if (rpos < size) and (vbit < 5):
            bits = (bits << 8) | data[rpos] # eat 8 more bits
            rpos += 1
            vbit += 8
        if (vbit < 5):
            bits <<= (5 - vbit) # zero-padding
            assert (vbit == ((size * 8) % 5))
            vbit = 5
        out += echart[(bits >> (vbit - 5)) & 31]
        wpos += 1
        vbit -= 5
    assert (0 == vbit)
    return out;


def sha512_hash (data):
    """ Returns the sha512 hash of the given data. 
    
    data: string to hash
    """
    hash_obj = sha512()
    hash_obj.update (data)
    return hash_obj.digest()


class AESKey:
    """Class for AES Keys. Contains the main key and the initialization
    vector. """

    key = None                  # The actual AES key
    iv = None                   # The initialization vector
    cipher = None               # The cipher object
    KEY_SIZE = 32               # AES 256-bit key = 32 bytes
    IV_SIZE = AES.block_size    # Initialization vector size (= AES block size)
    
    def __init__ (self, passphrase):
        """Creates a new AES key. 
        
        passphrase: string containing the passphrase to get the AES key and
                      initialization vector
        """
        passphrase = bytearray (passphrase);
        self.key = bytearray (self.KEY_SIZE)
        self.iv = bytearray (self.IV_SIZE)
        if (len (passphrase) > self.KEY_SIZE):
            self.key = passphrase[:self.KEY_SIZE]
            passphrase = passphrase[self.KEY_SIZE:]
            if (len (passphrase) > self.IV_SIZE):
                self.iv = passphrase[:self.IV_SIZE]
            else:
                self.iv[0:len (passphrase)] = passphrase
        else:
            self.key[0:len (passphrase)] = passphrase
        self.key = str (self.key)
        self.iv = str (self.iv)
        assert (len(self.key) == self.KEY_SIZE)
        assert (len(self.iv) == self.IV_SIZE)

def setup_aes_cipher_ (aes_key):
    """Initializes the AES object with settings similar to those in GNUnet.
    
    aes_key: the AESKey object
    Returns the newly initialized AES object
    """
    return AES.new (aes_key.key, AES.MODE_CFB, aes_key.iv, segment_size=128)

def aes_pad_ (data):
    """Adds padding to the data such that the size of the data is a multiple of
    16 bytes
    
    data: the data string
    Returns a tuple:(pad_len, data). pad_len denotes the number of bytes added
    as padding; data is the new data string with padded bytes at the end
    """
    pad_len = len(data) % 16
    if (0 != pad_len):
        pad_len = 16 - pad_len
        pad_bytes = bytearray (15)
        data += str(pad_bytes[:pad_len])
    return (pad_len, data)

def aes_encrypt (aes_key, data):
    """Encrypts the given data using AES.

    aes_key: the AESKey object to use for AES encryption
    data: the data string to encrypt
    """
    (pad_len, data) = aes_pad_ (data)
    cipher = setup_aes_cipher_ (aes_key)
    enc_data = cipher.encrypt (data)
    if (0 != pad_len):
        enc_data = enc_data[:-pad_len]
    return enc_data

def aes_decrypt (aes_key, data):
    """Decrypts the given data using AES
    
    aes_key: the AESKey object to use for AES decryption
    data: the data string to decrypt
    """
    (pad_len, data) = aes_pad_ (data)
    cipher = setup_aes_cipher_ (aes_key)
    ptext = cipher.decrypt (data)
    if (0 != pad_len):
        ptext = ptext[:-pad_len]
    return ptext


class Chk:
    """Class for the content hash key."""
    key = None
    query = None
    fsize = None

    def __init__(self, key, query):
        assert (len(key) == CHK_HASH_SIZE)
        assert (len(query) == CHK_QUERY_SIZE)
        self.key = key
        self.query = query

    def setSize(self, size):
        self.fsize = size

    def uri(self):
        sizestr = repr (self.fsize)
        if isinstance (self.fsize, long):
            sizestr = sizestr[:-1]            
        return GNUNET_FS_URI_PREFIX + GNUNET_FS_URI_CHK_INFIX + \
            encode_data_to_string(bytearray(self.key)) + "." + \
            encode_data_to_string(bytearray(self.query)) + "." + \
            sizestr


def compute_depth_(size):
    """Computes the depth of the hash tree.
    
    size: the size of the file whose tree's depth has to be computed
    Returns the depth of the tree. Always > 0.
    """
    depth = 1
    fl = DBLOCK_SIZE
    while (fl < size):
        depth += 1
        if ((fl * CHK_PER_INODE) < fl):
            return depth
        fl = fl * CHK_PER_INODE
    return depth

def compute_tree_size_(depth):
    """Calculate how many bytes of payload a block tree of the given depth MAY
     correspond to at most (this function ignores the fact that some blocks will
     only be present partially due to the total file size cutting some blocks
     off at the end).

     depth: depth of the block.  depth==0 is a DBLOCK.
     Returns the number of bytes of payload a subtree of this depth may
     correspond to.
     """
    rsize = DBLOCK_SIZE
    for cnt in range(0, depth):
        rsize *= CHK_PER_INODE
    return rsize

def compute_chk_offset_(depth, end_offset):
    """Compute the offset of the CHK for the current block in the IBlock
    above
    
    depth: depth of the IBlock in the tree (aka overall number of tree levels
             minus depth); 0 == DBLOCK
    end_offset: current offset in the overall file, at the *beginning* of the
                  block for DBLOCK (depth == 0), otherwise at the *end* of the
                  block (exclusive)
    Returns the offset in the list of CHKs in the above IBlock
    """
    bds = compute_tree_size_(depth)
    if (depth > 0):
        end_offset -= 1
    ret = end_offset / bds
    return ret % CHK_PER_INODE

def compute_iblock_size_(depth, offset):
    """Compute the size of the current IBLOCK.  The encoder is triggering the
    calculation of the size of an IBLOCK at the *end* (hence end_offset) of its
    construction.  The IBLOCK maybe a full or a partial IBLOCK, and this
    function is to calculate how long it should be.
    
    depth: depth of the IBlock in the tree, 0 would be a DBLOCK, must be > 0
             (this function is for IBLOCKs only!)
    offset: current offset in the payload (!) of the overall file, must be > 0
              (since this function is called at the end of a block).
    Returns the number of elements to be in the corresponding IBlock
    """
    assert (depth > 0)
    assert (offset > 0)
    bds = compute_tree_size_ (depth)
    mod = offset % bds
    if mod is 0:
        ret = CHK_PER_INODE
    else:
        bds /= CHK_PER_INODE
        ret = mod / bds
        if (mod % bds) is not 0:
            ret += 1
    return ret


def compute_rootchk(readin, size):
    """Returns the content hash key after generating the hash tree for the given
    input stream.

    readin: the stream where to read data from
    size: the size of data to be read
    """
    depth = compute_depth_(size);
    current_depth = 0
    chks = [None] * (depth * CHK_PER_INODE) # list buffer
    read_offset = 0
    logging.debug("Begining to calculate tree hash with depth: "+ repr(depth))
    while True:
        if (depth == current_depth):
            off = CHK_PER_INODE * (depth - 1)
            assert (chks[off] is not None)
            logging.debug("Encoding done, reading CHK `"+ chks[off].query + \
                              "' from "+ repr(off) +"\n")
            uri_chk = chks[off]
            assert (size == read_offset)
            uri_chk.setSize (size)
            return uri_chk
        if (0 == current_depth):
            pt_size = min(DBLOCK_SIZE, size - read_offset);
            try:
                pt_block = readin.read(pt_size)
            except IOError:
                logging.warning ("Error reading input file stream")
                return None
        else:
            pt_elements = compute_iblock_size_(current_depth, read_offset)
            pt_block = ""
            pt_block = \
                reduce ((lambda ba, chk:
                             ba + (chk.key + chk.query)),
                        chks[(current_depth - 1) * CHK_PER_INODE:][:pt_elements],
                        pt_block)
            pt_size = pt_elements * (CHK_HASH_SIZE + CHK_QUERY_SIZE)
        assert (len(pt_block) == pt_size)
        assert (pt_size <= DBLOCK_SIZE)
        off = compute_chk_offset_ (current_depth, read_offset)
        logging.debug ("Encoding data at offset "+ repr(read_offset) + \
                           " and depth "+ repr(current_depth) +" with block " \
                           "size "+ repr(pt_size) +" and target CHK offset "+ \
                           repr(current_depth * CHK_PER_INODE))
        pt_hash = sha512_hash (pt_block)
        pt_aes_key = AESKey (pt_hash)
        pt_enc = aes_encrypt (pt_aes_key, pt_block)
        pt_enc_hash = sha512_hash (pt_enc)
        chk = Chk(pt_hash, pt_enc_hash)
        chks[(current_depth * CHK_PER_INODE) + off] = chk
        if (0 == current_depth):
            read_offset += pt_size
            if (read_offset == size) or \
                    (0 == (read_offset % (CHK_PER_INODE * DBLOCK_SIZE))):
                current_depth += 1
        else:
            if (CHK_PER_INODE == off) or (read_offset == size):
                current_depth += 1
            else:
                current_depth = 0


def chkuri_from_path (path):
    """Returns the CHK URI of the file at the given path.
    
    path: the path of the file whose CHK has to be calculated
    """
    size = os.path.getsize (path)
    readin = open (path, "rb")
    chk = compute_rootchk (readin, size)
    readin.close()
    return chk.uri()

def usage ():
    """Prints help about using this script."""
    print """
Usage: gnunet-chk.py [options] file
Prints the Content Hash Key of given file in GNUNET-style URI.

Options:
    -h, --help                : prints this message
"""


if '__main__' == __name__:
    try:
        opts, args = getopt.getopt(sys.argv[1:], 
                                   "h", 
                                   ["help"])
    except getopt.GetoptError, err:
        print err
        print "Exception occured"
        usage()
        sys.exit(2)
    for option, value in opts:
        if option in ("-h", "--help"):
            usage()
            sys.exit(0)
    if len(args) != 1:
        print "Incorrect number of arguments passed"
        usage()
        sys.exit(1)
    print chkuri_from_path (args[0])
