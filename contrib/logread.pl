#!/usr/bin/env perl

# Usage:
#   gnunet-service |& gnunet-logread
#   gnunet-logread service.log

use strict;
use warnings;

use Term::ANSIColor qw(:constants :pushpop);
$Term::ANSIColor::AUTOLOCAL = 1;

# Message type numbers to names
my %msgtypes;
my $prefix = $ENV{GNUNET_PREFIX} || '/usr';
my $filename = "$prefix/include/gnunet/gnunet_protocols.h";

if (open HEADER, $filename)
{
    while (<HEADER>)
    {
        $msgtypes{$2} = $1 if /^\s*#define\s+GNUNET_MESSAGE_TYPE_(\w+)\s+(\d+)/i;
    }
    close HEADER;
}
else
{
    warn "$filename: $!, try setting \$GNUNET_PREFIX";
}

while (<>)
{
    # Timestamp (e.g. Nov 01 19:36:11-384136)
    s/^([A-Z][a-z]{2} .[0-9] [0-9:]{8}(?:-[0-9]{6})?)/YELLOW $1/e;

    # Log levels
    s/\b(ERROR  )\b/RED $1/ex;
    s/\b(WARNING)\b/YELLOW $1/ex;
    s/\b(INFO   )\b/GREEN $1/ex;
    s/\b(DEBUG  )\b/BRIGHT_BLACK $1/ex;

    # Service names
    # TODO: might read the list from $GNUNET_PREFIX/libexec/gnunet/
    s/\b(multicast|psyc|psycstore|social)\b/BLUE $1/ex;

    # Add message type names
    s/(message(?:\s+of)?\s+type\s+)(\d+)/
      $1 . BRIGHT_CYAN (exists $msgtypes{$2} ? $msgtypes{$2} : 'UNKNOWN') .
      CYAN " ($2)"/e;

    print;
}
