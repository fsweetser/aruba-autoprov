#!/usr/bin/perl -w

use strict;

use Net::SSH::Expect;
use Text::CSV;
use Getopt::Long;
use Data::Dumper;

$| = 1;

# Set this to 1 to get a few more output messages.
my $debug = 0;


my %queue;

my $master = 'aruba-master';
my $user   = 'admin';
my $pass;
my $enpass;

my $want_state = 'certified-factory-cert';
my $want_certtype = 'factory-cert';
my $file = "./waps.csv";

my $usage = qq(
Command line options:

--file=<filename>
    CSV file to parse AP data from.  Defaults to waps.csv.

--master=<master>
    Hostname or IP address of controller to configure.
    Defaults to aruba-master.

--user=<username>
    Username to log in as.  Defaults to admin.

--pass=<password>
    Password for logging in.

--enpass=<enable password>
    Enable password.

--want_state=<state>
    Default state for cpsec whitelist.  Defaults to certified-factory-cert.

--want_certtype=type>
    Default cert type for cpsec whitelist.  Dfeaults to factory-cert.

--debug
    Enable additional debug output.
);

GetOptions (
    "file=s"          => \$file,
    "master=s"        => \$master,
    "user=s"          => \$user,
    "pass=s"          => \$pass,
    "enpass=s"        => \$enpass,
    "want_state=s"    => \$want_state,
    "want_certtype=s" => \$want_certtype,
    "debug"           => \$debug
    ) or die $usage;

die $usage unless(defined($pass) and defined($enpass));

my $aps = get_aplist($file);

##
## Customizable policy functions.  Hit these up to apply local site policies.
##

##
## This function generates the actual commands doing the provisioning.  If you
## want to set more properties, such as controller name or USB settings, add
## them here.
##
sub provision_ap {
    my ($ssh, $curname, $newname, $group) = @_;

    my @lines = (
	'clear provisioning-ap-list',
	'provision-ap read-bootinfo ap-name "' . $curname . '"',
	'provision-ap copy-provisioning-params ap-name "' . $curname . '"',
	'provision-ap ap-group "' . $group . '"',
	'provision-ap ap-name "' . $newname . '"',
	'provision-ap reprovision ap-name "' . $curname . '"',
	'clear provisioning-ap-list',
	'clear provisioning-params',
	);
    
    print Dumper \@lines if $debug;

    foreach my $line ( @lines ){
	$ssh->send($line . "\n");
    }
    sleep(2);
    print $ssh->read_all(5), "\n\n" if $debug;

}

##
## Create the hash of AP provisioning parameters - basically MAC,
## name, and group.  Ideally this should be pointed at your own
## dynamic data source, such as a CSV or IPAM database.  If you need
## to add more parameters in the provision_ap function, this would be
## a good place to store them.
##
## The resulting hash should be something like this:
##  my %aps = (
##	'11:22:33:44:55:66' => {
##	    'name' => 'dorm-100-a',
##	    'apgroup' => 'residential'
##	},
##	'22:33:44:55:66:77' => {
##	    'name' => 'dorm-200-a',
##	    'apgroup' => 'residential'
##	},
##	'33:44:55:66:77:88' => {
##	    'name' => 'dorm-300-a',
##	    'apgroup' => 'residential'
##	}
##    );
sub get_aplist {
    my ($file) = @_;
    my %aps;

    print "Parsing $file\n";

    my $csv = Text::CSV->new;
    open(my $fh, "<$file") or die "Cannot open $file: $!\n";

    while(my $row = $csv->getline($fh)){
	$aps{$row->[0]}{'name'} = $row->[1];
	$aps{$row->[0]}{'apgroup'} = $row->[2];
    }

    return \%aps;
}
#############################################

print Dumper($aps) if $debug;

##
## Initial connection setup
##
my $ssh = Net::SSH::Expect->new(
    host     => $master,
    password => $pass,
    user     => $user,
    raw_pty  => 1
    );

my $login_output = $ssh->login;
if ($login_output =~ /\) >/){
    warn "Login succesfull, running enable\n";
    $ssh->send("enable");
    $ssh->waitfor("Password:");
    $ssh->send($enpass);
    $ssh->waitfor('\) #\z', 5) or die "Could not enable";
} else {
    die "Could not login: $login_output";
}

$ssh->send("no paging");

##
## Query the whitelist and send any relevant modify commands
##

my $whitelist = get_whitelist($ssh);
foreach my $mac (sort keys %{$aps}){
    if(defined($whitelist->{$mac})){
	print "Found $mac in whitelist\n";

	unless ($whitelist->{$mac}{'state'} eq $want_state and
		$whitelist->{$mac}{'certtype'} eq $want_certtype){
	    print "Going to modify cpsec whitelistdb for $mac\n";
	    $ssh->send("whitelist-db cpsec modify mac-address $mac state $want_state cert-type $want_certtype\n");
	    $queue{'wl'}{$mac} = 1;
	    $queue{'prov'}{$mac} = 0;
	}
    }
}

##
## Monitor the cpsec database for completion of the above commands
##

print "", scalar keys %{$queue{'wl'}}, " whitelist queue entries\n";
while(scalar keys %{$queue{'wl'}} > 0){
    sleep(30);
    print "Checking whitelist status... (", scalar keys %{$queue{'wl'}}, " left)\n";
    $whitelist = get_whitelist($ssh);

    foreach my $mac (sort keys %{$aps}){
	next unless defined($queue{'wl'}{$mac});
	if($whitelist->{$mac}{'state'} eq $want_state and
	   $whitelist->{$mac}{'certtype'} eq $want_certtype){
	    print "$mac whitelist entry succesfull\n";
	    delete $queue{'wl'}{$mac};
	}
    }
}

print "All whitelist entries are correct.\n";


##
## Check for any already-associated APs that need provisioning
##

my $apdb = get_apdatabase($ssh);

foreach my $mac (sort keys %{$aps}){
    if(defined($apdb->{$mac})){
	print "Found $mac to provision\n";

	if ($apdb->{$mac}{'name'} eq $aps->{$mac}{'name'} and
		$apdb->{$mac}{'apgroup'} eq $aps->{$mac}{'apgroup'}){
	    print "$mac already correctly provisioned\n";
	    delete $queue{'prov'}{$mac};
	    delete $apdb->{$mac};
	} else {
	    $queue{'prov'}{$mac} = 0;
	    # 0 => needs to be provisioned, but has not yet
	}
    }
}

$ssh->send("conf terminal\n");

foreach my $mac (sort keys %{$queue{'prov'}}){
    if(defined($apdb->{$mac})){
	print "Provisioning $mac\n";
	provision_ap($ssh, $mac, $aps->{$mac}{'name'}, $aps->{$mac}{'apgroup'});
	$queue{'prov'}{$mac} = 1;
	# 1 => provisioning commands sent, needs verification
    }
}

print Dumper(\%queue);

print "", scalar keys %{$queue{'prov'}}, " provisioning queue entries\n";
while(scalar keys %{$queue{'prov'}} > 0){
    sleep(30);
    print "Checking provisioning status...(", scalar keys %{$queue{'prov'}}, " left)\n";
    $apdb = get_apdatabase($ssh);
    
    foreach my $mac (sort keys %{$aps}){
	next unless defined($apdb->{$mac});
	if ($apdb->{$mac}{'name'} eq $aps->{$mac}{'name'} and
	    $apdb->{$mac}{'apgroup'} eq $aps->{$mac}{'apgroup'}){
	    print "$mac provisioning status succesfull\n";
	    delete $queue{'prov'}{$mac};
	} else {
	    if($queue{'prov'}{$mac} == 0){
		provision_ap($ssh, $mac, $aps->{$mac}{'name'}, $aps->{$mac}{'apgroup'});
		$queue{'prov'}{$mac} = 1;
	    }
	}
    }
}

print "All provisioning entries are correct.\n";

#############################################
#
# Static helper functions.  Shouldn't need to be touched.
#

sub get_whitelist {
    my ($ssh) = @_;

    my %wl;

# See the current state of pending entries
    $ssh->send("show whitelist-db cpsec");
    while(my $line = $ssh->read_line(5)){
        last if $line =~ /\) #\z/;
        #print "Analyzing $line...\n";
        next unless $line =~ /^(..:..:..:..:..:..)\s+(\S+)\s+(\S+)\s+(\S+)\s/;
        my ($mac, $enable, $state, $certtype) = ($1, $2, $3, $4);

        $wl{$mac}{'enable'}   = $enable;
        $wl{$mac}{'state'}    = $state;
        $wl{$mac}{'certtype'} = $certtype;
    }

    return \%wl;

};

sub get_apdatabase {
    my ($ssh) = @_;

    my %apd;

    $ssh->send("show ap database long");
    while(my $line = $ssh->read_line(5)){
        last if $line =~ /\) #\z/;
        next if $line =~ /^\s|^Flags|^AP Database|^-|^Name|^Port information|^Total /;
        next unless $line =~ /\s+Up\s+/;

        $line =~ /^(\S+)\s+(\S+)\s.*([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})/;
        my ($name, $group, $mac) = ($1, $2, $3);

        next unless (defined($name) and
                     defined($group) and
                     defined($mac));

        $apd{$mac}{'name'} = $name;
        $apd{$mac}{'apgroup'} = $group;
    }

    return \%apd;
}
