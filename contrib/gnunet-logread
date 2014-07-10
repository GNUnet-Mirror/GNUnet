#!/usr/bin/env perl

# Usage:
#   gnunet-service |& gnunet-logread
#   gnunet-logread service.log
#
# Options:
#   -n <component_name>		Name of this component to use for IPC logging.
#   -i </path/to/ipc.sock>	Path to IPC logging socket.
#  Passing on log messages to IPC socket:
#   -L <LOGLEVEL>		Minimum level of messages to pass on.
#                               Log levels: NONE, ERROR, WARNING, INFO, DEBUG.
#   -m <regex>		        Only pass on messages matching a regular expression.

use strict;
use warnings;

use Getopt::Std;
use Term::ANSIColor qw(:constants :pushpop);
$Term::ANSIColor::AUTOLOCAL = 1;

my (%opts, $name, $ipc, $msg_level, $msg_regex);
getopts ('n:i:L:m:', \%opts);

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

my %levels = ( NONE => 0, ERROR => 1, WARNING => 2, INFO => 4, DEBUG => 8 );
if (exists $opts{n})
{
    $name = $opts{n};
    $ipc = $opts{i} || '/tmp/gnunet-logread-ipc.sock';
    $msg_level = exists $levels{$opts{L}} ? $levels{$opts{L}} : 0;
    $msg_regex = $opts{m};
    print STDERR "RE: /$msg_regex/\n";
    open IPC, '>', $ipc or die "$ipc: $!\n";
}

while (<>)
{
    if (fileno IPC) {
        my ($time, $type, $size, $from, $to, $level, $msg);
        if (($time, $type, $size, $from, $to) =
            /^([A-Z][a-z]{2}\ .[0-9]\ [0-9:]{8}(?:-[0-9]{6})?)\ util-.*\b
             (?: Received | Transmitting )\ message \b.*?\b
             type \s+ (\d+) \b.*?\b
             size \s+ (\d+) \b.*?\b
             (?: from \s+ (\S+)
               | to   \s+ (\S+) ) /x)
        {
            $from ||= $name;
            $to ||= $name;
            my ($time, $type, $size, $from, $to) = ($1, $2, $3,
                                                $4 || $name, $5 || $name);
            my $msg = exists $msgtypes{$type} ? $msgtypes{$type} : $type;
            my $ofh = select IPC;
            print IPC "$time\t$from -> $to\t$msg ($size)\n";
            $|++;
            select $ofh;
        }
        if (($time, $level, $msg) =
            /^([A-Z][a-z]{2}\ .[0-9]\ [0-9:]{8}(?:-[0-9]{6})?)
              \s+\S+\s+(\S+)\s+(.+)/x
            and (exists $levels{$level}
                 && $levels{$level} <= $msg_level
                 && (!defined $msg_regex || $msg =~ /$msg_regex/i)))
        {
            print IPC "$time\t$name\t$level: $msg\n";
        }
    }

    # Timestamp (e.g. Nov 01 19:36:11-384136)
    s/^([A-Z][a-z]{2} .[0-9] [0-9:]{8}(?:-[0-9]{6})?)/YELLOW $1/e;

    # Log levels
    s/\b(ERROR  )\b/RED $1/ex;
    s/\b(WARNING)\b/YELLOW $1/ex;
    s/\b(INFO   )\b/GREEN $1/ex;
    s/\b(DEBUG  )\b/BRIGHT_BLACK $1/ex;

    # Service names
    # TODO: might read the list from $GNUNET_PREFIX/libexec/gnunet/
    s/\b(multicast|psyc|psycstore|social)\b/BLUE $1/gex;

    # Add message type names
    s/(\s+type\s+)(\d+)/
      $1 . BRIGHT_CYAN (exists $msgtypes{$2} ? $msgtypes{$2} : 'UNKNOWN') .
      CYAN " ($2)"/gei;

    # logread-ipc output
    s/(\s+)([A-Z_]+)( \(\d+\))$/$1 . BRIGHT_CYAN $2 . CYAN $3/e;

    print;
}

fileno IPC and close IPC;
