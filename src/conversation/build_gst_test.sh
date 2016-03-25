#!/bin/bash

colorgcc  -DIS_MIC -g gnunet_gst_test.c gnunet_gst.c -o gnunet-helper-audio-record-experimental `pkg-config --cflags --libs gstreamer-app-1.0 gnunetutil gnunetconversation gnunetenv  gstreamer-app-1.0 gstreamer-1.0 gstreamer-audio-1.0 gstreamer-pbutils-1.0 gstreamer-video-1.0` -O0 -march=native  -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-conversion  -Wformat -Wformat-security -fstack-protector -D_FORTIFY_SOURCE=2 -std=c99  -D_GNU_SOURCE

colorgcc -DIS_SPEAKER -g gnunet_gst_test.c gnunet_gst.c -o gnunet-helper-audio-playback-experimental `pkg-config --cflags --libs gstreamer-app-1.0 gnunetutil gnunetconversation gnunetenv  gstreamer-app-1.0 gstreamer-1.0 gstreamer-audio-1.0 gstreamer-pbutils-1.0 gstreamer-video-1.0` -O0 -march=native  -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-conversion  -Wformat -Wformat-security -fstack-protector -D_FORTIFY_SOURCE=2 -std=c99  -D_GNU_SOURCE



#colorgcc  -g gnunet_gst_test.c gnunet_gst.c -o gnunet_gst_test `pkg-config --cflags --libs  gstreamer-app-1.0 gstreamer-1.0 gstreamer-audio-1.0 gstreamer-pbutils-1.0 gstreamer-video-1.0` -O0 -march=native -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-conversion -Wpedantic -Wformat -Wformat-security -fstack-protector -D_FORTIFY_SOURCE=2 -std=c99  -D_GNU_SOURCE
