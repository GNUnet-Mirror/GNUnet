# 
#  This file is part of GNUnet
#  (C) 2008, 2009 Christian Grothoff (and other contributing authors)
# 
#  GNUnet is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published
#  by the Free Software Foundation; either version 3, or (at your
#  option) any later version.
# 
#  GNUnet is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with GNUnet; see the file COPYING.  If not, write to the
#  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
#  Boston, MA 02111-1307, USA.
# 
# 
# 
#  @file contrib/peerStartHelper.pl
#  @brief Helper process for starting gnunet-testing peers.
#  @author Nathan Evans
#
# Finds configuration files (or any files) of the format
# /path/*/gnunet-testing-config* and runs gnunet-arm with
# each as the given configuration.
#
# usage: peerStartHelper.pl /path/to/testing_dir/
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


