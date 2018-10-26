#!/bin/sh

# FIXME: Don't use /tmp, use whatever we introduced as check for it.
export GST_DEBUG_DUMP_DOT_DIR=/tmp/ 
GST_DEBUG_DUMP_DOT_DIR=/tmp/ ./gnunet-helper-audio-record |GST_DEBUG_DUMP_DOT_DIR=/tmp/ ./gnunet-helper-audio-playback
