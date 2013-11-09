#!/usr/bin/env perl

# 1. Start sdedit and enable 'RT diagram server' in 'Global preferences'.
#
# 2. Start this tool (see defaults below):
#    gnunet-logread-ipc-sdedit -n buffer-name -i /path/to/ipc.sock -h <sdedit-host> -p <sdedit-port>
#
# 3. Start a gnunet-logread instance for each component with the -n <component_name> option

use strict;
use warnings;

use Getopt::Std;
use IO::Socket::INET;
use POSIX qw(mkfifo);

my %opts;
getopts ('i:n:h:p:', \%opts);

my $ipc  = $opts{i} || '/tmp/gnunet-logread-ipc.sock';
my $name = $opts{n} || 'gnunet';
my $host = $opts{h} || 'localhost';
my $port = $opts{p} || 16001;
my %svcs = map { $_ => 1 } @ARGV;

my $sdedit = IO::Socket::INET->new(PeerAddr => $host,
                                   PeerPort => $port,
                                   Proto => 'tcp')
    or die "Cannot connect to $host:$port: $!\n";

print $sdedit "$name\n";
print $sdedit "_t:time[e]\n";
print $sdedit "$_:$_\[ap\] \"$_\"\n" for @ARGV;
print $sdedit "_e:ext[e]\n";
print $sdedit "\n";

mkfifo $ipc, 0600 or die "$ipc: $!\n" unless -e $ipc;
open IPC, '<', $ipc or die "$ipc: $!\n";
while (<IPC>)
{
    print;
    my ($time, $from, $to, $msg, $svc);
    if (my ($time, $from, $to, $msg) =
        /^([A-Z][a-z]{2}\ .[0-9]\ [0-9:]{8}(?:-[0-9]{6})?)\s+
         (\S+)\s+ -> \s+(\S+)\s+ (\S+\s+ \(\d+\))/x)
    {
        $from = '_e' unless exists $svcs{$from};
        $to = '_e' unless exists $svcs{$to};
        print $sdedit "*0 _t\n$time\n*0\n", "$from:$to.$msg\n"
    }
    elsif (($time, $svc, $msg) =
           /^([A-Z][a-z]{2}\ .[0-9]\ [0-9:]{8}(?:-[0-9]{6})?)\s+
             (\S+)\s+(.+)/x)
    {
        print $sdedit "*0 _t\n$time\n*0\n", "*0 $svc\n$msg\n*0\n"
    }
}

close IPC;
