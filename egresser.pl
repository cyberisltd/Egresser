#!/usr/bin/perl

# Egresser client-side script, allowing outbound firewall rules to
# be enumerated. 

# Copyright (C) 2013  Cyberis Limited
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;
use warnings;
use threads;
use Thread::Queue ;
use IO::Socket::IP;
use Getopt::Long;

my $server = "egresser.ipv6labs.cyberis.co.uk";
my $server4 = "egresser.ipv4labs.cyberis.co.uk";
my $server6 = "egresser.ipv6labs.cyberis.co.uk";
my @ports = (1..1024); # The port range to scan
my $timeout = 2; 
my @results;
my $verbose;
GetOptions (	"verbose" => \$verbose,
		"4" => sub { $server = $server4 },
		"6" => sub { $server = $server6 });

my $finished_queue = new Thread::Queue ;

my $count = 10 ;        # Number of threads
my $number = @ports ;  	# Total number of threads to dispatch
my $remaining = $number;# Threads that still haven't returned
my $index = 0;		# The port to scan

print "\n*** Cyberis Ltd. - Egresser - a tool to enumerate egress filtering (TCP outbound firewall rules). ***\n\n";
print "Attempting to connect to TCP ports $ports[0]..$ports[-1] on $server:\n\n";

while ($remaining) {
	# Wait until we have an idle thread
  	while ($number && $count) {
    		my $child = threads->create(\&doRequest, $server, $ports[$index]) ;
    		$index++;
    		$number-- ;
    		$count-- ;
  	} ;

  	my $tid = $finished_queue->dequeue() ;
  	my $child = threads->object($tid) ;
  	push @results, $child->join() ;

  	$remaining --;
  	$count++ ;
} ;

sub doRequest {
  	my ($server, $port) = @_;
  	my $result = { 'port'=> $port };
	my $tid = threads->tid() ;

  	my $socket = new IO::Socket::IP (
	  	PeerHost => $server,
	  	PeerPort => $port,
	  	Proto => 'tcp',
	  	Timeout => $timeout
  	);

	if (defined $socket) {
  		# Connection was successful
  		my $data = <$socket>;
  		$result->{'data'} = $data;
		$result->{'realsrcport'} = $socket->sockport();

		# Check the format of the data
		if ($data =~ m/([0-9a-f\.\:]+) ([0-9]{1,5})\0/i) {
			$result->{'ip'} = $1;
			$result->{'reportedsrcport'} = $2;
			$result->{'rcode'} = 0;
		}
		else {
			# Data returned not in correct format
			$result->{'rcode'} = 1;
		}
  	}
  	else {
		if ($@ =~ m/refused/) {
			$result->{'rcode'} = 2;
		}
		if ($@ =~ m/timeout/) {
                	$result->{'rcode'} = 3;
        	}
  	}

#	die "$@" if ! defined;

  	$finished_queue->enqueue($tid);

  	print STDERR ".";	
  	return  $result;
} ;

# Process the results
my (@openports, @closedports, @timeoutports, @errorports,$ip,$realsrcport,$reportedsrcport);

foreach (@results) {
	my $result = $_;
	my $rcode = $result->{'rcode'};

	if ($rcode == 0) {
		push @openports, $result->{'port'};
		if (!defined $ip) {
			$ip = $result->{'ip'};
			$realsrcport = $result->{'realsrcport'};
			$reportedsrcport = $result->{'reportedsrcport'};
		}
		next;
	}
        if ($rcode == 1) {
                push @errorports, $result->{'port'};
		next;
        }
        if ($rcode == 2) {
                push @closedports, $result->{'port'};
		next;
        }
        if ($rcode == 3) {
                push @timeoutports, $result->{'port'};
        }
}

# Sort the results
@openports = sort { $a <=> $b } @openports;
@errorports = sort { $a <=> $b } @errorports;
@closedports = sort { $a <=> $b } @closedports;
@timeoutports = sort { $a <=> $b } @timeoutports;

print "\n\nEgresser found:\n\n";
print "\tOpen ports:\t".@openports."\n";
print "\tClosed ports:\t".@closedports."\n\n";

if (@timeoutports || @errorports) {
	print "The following errors were encountered (possible indicatation of egress filtering):\n\n";
	if (@timeoutports) {
		print "\tTimeouts:\t\t".@timeoutports."\n";
	}
	else {
		print "\tInvalid data returned:\t".@errorports."\n";
	}
}

if (!defined($verbose)) {
	print "\nNB: To list all open ports, specify the verbose flag (-v) when running Egresser.\n";
}
if ((@openports <= 10 && @openports > 0) || (@openports > 0 && $verbose)) {
	print "\nThe following ports were permitted outbound: " . join(',', @openports)."\n";
}
if ((@closedports <= 10 && @closedports > 0) || (@closedports > 0 && $verbose)) {
	print "\nThe following ports were rejected outbound: " . join(',', @closedports)."\n";
}
if ((@timeoutports <= 10 && @timeoutports > 0) || (@timeoutports > 0 && $verbose)) {
	print "\nThe following ports timed-out: " . join(',', @timeoutports)."\n";
}
if ((@errorports <= 10 && @errorports > 0) || (@errorports > 0 &&$verbose)) {
	print "\nThe following ports returned invalid data: " . join(',',@errorports)."\n";
}

if (defined $ip) {
	print "\nYour connecting IP address was reported by the server as $ip\n";
}

if ($realsrcport == $reportedsrcport) {
	print "\nThe reported source port matches my request - there appears to be no NAT traversal taking place.\n";
}
else {

	print "\nThe reported source port is different from my request. Possible IP masquerading (NAT) in use by an intermediary device.\n";
}

print "\n*** Egresser scan complete. ***\n\n";
