#!/usr/bin/env perl
#
# Quick and dirty script to change all tab characters in the named
# file to 8 spaces. Output is a new version of the input file.
#

#
# Roundup usual suspects
#
use strict;


sub say { print join(' ', @_), "\n";  }
sub croak { &say(@_); exit(1); }

sub usage { &croak("usage:", $0, "filnam"); }

#
# Reality check
#
&usage unless scalar(@ARGV) == 1;
#
# Slurp original file
#
my($fn) = shift(@ARGV);
open(F, '<'.$fn) || &croak("failed to open", $fn, ':', $!);
my($s) = '';
my($l);
while($l = <F>) {
    $s .= $l;
}
close(F);
#
# Replace all tab characters by 8 spaces
#
$s =~ s/\t/        /g;
#
# Dump result in file with same name as input
#
open(F, '>'.$fn) || &croak("failed to create", $fn, ':', $!);
printf F "%s", $s;
close(F);
#
# All done.
#
