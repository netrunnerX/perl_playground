#!/usr/bin/perl

use Net::Pcap qw( :functions );
use Net::Frame::Device;
use Net::Netmask;
use Net::Frame::Dump::Online;
use Net::ARP;
use Net::Frame::Simple;

my $err = "";
my $dev = lookupdev(\$err);
my $devProperties = Net::Frame::Device->new(dev => $dev);
my $ip = $devProperties->ip;
my $gateWay = $devProperties->gatewayIp;
my $netmask = Net::Netmask->new($devProperties->subnet);
my $mac = $devProperties->mac;
my $netBlock = $ip.":".$netmask->mask;
my $filterStr = "arp dst host ".$ip;
my $pcap = Net::Frame::Dump::Online->new(dev => $dev,
                                        filter => $filterStr,
                                        promisc => 0,
                                        unlinkOnStop => 1,
                                        timeoutOnNext => 10);

$pcap->start;
print "-----Device Information-----\n";
print "Device: ".$devProperties->dev."\n";
print "IP: ".$ip."\n";
print "Gateway IP: ".$gateWay."\n";
print "----------------------------\n";
print "Starting scan\n";

%foundIps = (); #we store ips as hash keys

foreach my $ipToScan ($netmask->enumerate) {

    Net::ARP::send_packet(
        $dev,
        $ip,
        $ipToScan,
        $mac,
        "ff:ff:ff:ff:ff:ff",
        "request"
    );

}

until ($pcap->timeout) {
    if (my $next = $pcap->next) {
        my $fref = Net::Frame::Simple->newFromDump($next);
        my $aliveIp = $fref->ref->{ARP}->srcIp;
        #Save ip in a hash, hash element value is the last digits for sorting purposes
        $foundIps{ $aliveIp } = getIpLastDigits($aliveIp);
    }
}

reportUpIps();

END{
    print "Exiting\n"; 
    $pcap->stop;
}

sub reportUpIps {

    @fips = sort { $foundIps{$a} <=> $foundIps{$b} } (keys %foundIps);
    foreach my $foundIp (@fips) {
        print "$foundIp is up\n";
    }
}

sub getIpLastDigits {
    my $ipstr = shift;
    $digits = (substr($ipstr, rindex($ipstr, '.')+1))+0;
    return $digits;
}
