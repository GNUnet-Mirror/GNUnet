#!/bin/bash

export GST_DEBUG_DUMP_DOT_DIR=/tmp/ 
GST_DEBUG_DUMP_DOT_DIR=/tmp/ ./gnunet-helper-audio-record |GST_DEBUG_DUMP_DOT_DIR=/tmp/ ./gnunet-helper-audio-playback
