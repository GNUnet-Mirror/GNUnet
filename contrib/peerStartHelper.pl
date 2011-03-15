#!/usr/bin/perl
use strict;

my $max_outstanding = 300;

$ARGV[0] || die "No directory provided for peer information, exiting!\n";

my $directory = $ARGV[0];
my @config_files = `find $directory -iname gnunet-testing-config*`;
my @child_arr = {};
my $count = 0;
my $outstanding = 0;
foreach my $file (@config_files)
{
  chomp($file);
  #print "Starting GNUnet peer with config file $file\n";
  my $pid = fork();
  if ($pid == -1) 
  {
   die;
  } 
  elsif ($pid == 0) 
  {
    exec "gnunet-arm -q -c $file -s"  or die;
  }

  if ($pid != 0)
  {
    push @child_arr, $pid;
    $count++;
    $outstanding++;
    if ($outstanding > $max_outstanding)
    {
      for (my $i = 0; $i < $max_outstanding / 5; $i++)
      {
	#print "Too many outstanding peers, waiting!\n";
	waitpid($child_arr[0], 0);
	shift(@child_arr);
	$outstanding--;
      }
    }
  }
}

print "All $count peers started (waiting for them to finish!\n";

while ($outstanding > 0)
{
  waitpid($child_arr[0], 0);
  shift(@child_arr);
  $outstanding--;
  if ($outstanding % 50 == 0)
  {
    print "All $count peers started (waiting for $outstanding to finish!\n";
  }
}

while (wait() != -1) {sleep 1}

print "All $count peers started!\n";


