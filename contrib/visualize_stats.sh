#!/bin/bash
#
# This script polls gnunet-stats repeatedly to create statistics plots. 
# Use 'collect' to collect statistics and 'plot' to plot whats been
# collected. All plots will be written to $STATDIR as separate .png files.
#
# WARNING: calling 'collect' will delete all files in $STATDIR.
#
# Requires: gnuplot
#
# Note: gnuplot syntax has changed across versions. This
# script perhaps will not produce color images with older gnuplots.
# The script should work atleast with gnuplot 3.8k patchlevel 1.
#

SLEEP=120
GNUNET=$HOME/
STATDIR=$GNUNET/stats
IMAGEVIEWER='display'
TMP=/tmp/.gnuplot_error

##########################################################################

mkdir -p $STATDIR

case "$1" in
  collect)
    rm -f $STATDIR/*
  
    STARTTIME=`date +%s`
    IFS=":"
    
    while true; do
	NOW=`date +%s`
	RELAT=$[$NOW-$STARTTIME]
	gnunet-statistics | while read KEY VALUE; do
		
		# Collect stats of previous round
		if [ -e "$STATDIR/$KEY.dat" ]; then
			PREV=`tail --lines=1 "$STATDIR/$KEY.dat" | sed -e "s/.* //g"`
		else
			PREV=$VALUE
		fi

		# Write new stats
		echo $RELAT $VALUE >>"$STATDIR/$KEY.dat"
		echo $RELAT $PREV $VALUE >>"$STATDIR/$KEY.diff"
	
	done
	sleep $SLEEP
    done
  ;;
  plot)
	# Plot incremental
        ls -1 $STATDIR/*.dat | while read FILENAME; do
	        BASENAME=`basename "$FILENAME" | sed -e "s/ *\..*//g"`
		echo "set terminal png;set output '$FILENAME.png';set title '$BASENAME - incr';plot '$FILENAME' using (\$1/60):(\$2) title '' with lines;" | nice gnuplot 2> $TMP
         EC=`cat $TMP | grep "empty" | grep "Warning" | wc -l`
         if test $EC -ge 1
	 then
	   rm "$FILENAME.png"
	 fi
	done
        
	# Plot diff
	ls -1 $STATDIR/*.diff | while read FILENAME; do
	        BASENAME=`basename "$FILENAME" | sed -e "s/ *\..*//g"`
		echo "set terminal png;set output '$FILENAME.png';set title '$BASENAME - diff';plot '$FILENAME' using (\$1/60):(\$3-\$2) title '' with lines;" | nice gnuplot 2> $TMP
         EC=`cat $TMP | grep "empty" | grep "Warning" | wc -l`
         if test $EC -ge 1 
         then
          rm "$FILENAME.png"
         fi

  	done
  ;;
  view)
	$IMAGEVIEWER $STATDIR/*.png
  ;;
  *)
     echo $"Usage: $0 {collect|plot|view}"
     exit 1
    
esac

  
