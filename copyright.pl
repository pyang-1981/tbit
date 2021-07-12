#!/usr/bin/perl

open fd, "COPYRIGHT" or die $!;

$done = 0;
while (<>) {
	if (($done == 0) && (m/^COPYRIGHT$/)) {
		while (<fd>) {
			print; 
		}
		$done = 1;
 	}
 	else {
		print; 
 	}
}
