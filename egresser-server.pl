#!/usr/bin/perl

# Egresser server-side script, allowing outbound firewall rules to
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

package Egresser;

use strict;
use warnings;
use base qw(Net::Server::PreFork);

sub process_request {
        my $self = shift;

        my $connection =  $self->{server}->{peeraddr} .
                " " . $self->{server}->{peerport};

        print STDERR ".";
        print $connection . "\0";
}

Egresser->run(port => 8080, ipv => '*');
