#!/usr/bin/perl
package Net::DNSBL::MultiDaemon;

use strict;
#use diagnostics;

use vars qw(
	$VERSION @ISA @EXPORT_OK %EXPORT_TAGS *R_Sin
	$D_CLRRUN $D_SHRTHD $D_TIMONLY $D_QRESP $D_NOTME $D_ANSTOP $D_VERBOSE
);
require Exporter;
@ISA = qw(Exporter);

# DEBUG is a set of semaphores
$D_CLRRUN    = 0x1;  # clear run flag and force unconditional return
$D_SHRTHD    = 0x2;  # return short header message
$D_TIMONLY   = 0x4;  # exit at end of timer section
$D_QRESP     = 0x8;  # return query response message
$D_NOTME     = 0x10; # return received response not for me
$D_ANSTOP    = 0x20; # clear run OK flag if ANSWER present
$D_VERBOSE   = 0x40; # verbose debug statements to STDERR

$VERSION = do { my @r = (q$Revision: 0.13 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

@EXPORT_OK = qw(
        run
        bl_lookup  
);
%EXPORT_TAGS = (
	debug	=> [qw($D_CLRRUN $D_SHRTHD $D_TIMONLY $D_QRESP $D_NOTME $D_ANSTOP $D_VERBOSE)],
);
Exporter::export_ok_tags('debug');

use Socket;
use Net::DNS::Codes qw(
	TypeTxt
	T_A
	T_ANY
	T_MX
	T_CNAME
	T_NS
	T_TXT
	T_SOA
	T_AXFR
	T_PTR
	C_IN
	PACKETSZ
	HFIXEDSZ
	QUERY
	NOTIMP
	FORMERR
	NOERROR
	REFUSED
	NXDOMAIN
	SERVFAIL
	BITS_QUERY
	RD
	QR
);
use Net::DNS::ToolKit 0.16 qw(
	newhead
	gethead
	get_ns
);
use Net::DNS::ToolKit::RR;
#use Net::DNS::ToolKit::Debug qw(
#	print_head
#	print_buf
#);

use Net::DNSBL::Utilities qw(
        s_response 
        not_found  
	write_stats
	statinit
	A1271
	A1272
	A1274
	A1275
	A1276
	list2NetAddr
	matchNetAddr
);

# target for queries about DNSBL zones, create once per session
# this is a global so it can be altered during testing
*R_Sin = \scalar sockaddr_in(53,scalar get_ns());

=head1 NAME

Net::DNSBL::MultiDaemon - multiple DNSBL emulator

=head1 SYNOPSIS

  use Net::DNSBL::MultiDaemon qw(
	:debug
        run
        bl_lookup  
  );

  run($BLzone,$L,$R,$DNSBL,$STATs,$Run,$Sfile,$StatStamp,$DEBUG)
  bl_lookup($put,$mp,$rtp,$sinaddr,$alarm,$id,$rip,$type,$zone,@blist);

=head1 DESCRIPTION

B<Net::DNSBL::MultiDaemon> is the Perl module that implements the B<multi_dnsbl>
daemon.

B<multi_dnsbl> is a DNS emulator daemon that increases the efficacy of DNSBL
look-ups in a mail system. B<multi_dnsbl> may be used as a stand-alone DNSBL
or as a plug-in for a standard BIND 9 installation. 
B<multi_dnsbl> shares a common configuration file format with the
Mail::SpamCannibal sc_BLcheck.pl script so that DNSBL's can be maintained in
a common configuration file for an entire mail installation.

Because DNSBL usefulness is dependent on the nature and source of spam sent to a
specific site and because sometimes DNSBL's may provide intermittant
service, B<multi_dnsbl> interrogates them sorted in the order of B<greatest
successful hits>. DNSBL's that do not respond within the configured timeout
period are not interrogated at all after 6 consecutive failures, and
thereafter will be retried not more often than once every hour until they
come back online. This eliminates the need to place DNSBL's in a particular order in
your MTA's config file or periodically monitor the DNSBL statistics and/or update
the MTA config file.

In addition to optimizing DNSBL interrogation, B<multi_dnsbl> may be
configured to locally accept or reject specified IP's, IP ranges and to
reject specified countries by 2 character country code. By adding a DNSBL
entry of B<in-addr.arpa>, IP's will be rejected that do not return some kind
of valid reverse DNS lookup.

Reject codes are as follows:

  blocked by configured DNSBL	127.0.0.2
  no reverse DNS		127.0.0.4
  BLOCKED (local blacklist) 	127.0.0.5
  Blocked by Country		127.0.0.6

=head1 OPERATION

The configuration file for B<multi_dnsbl> contains optional IGNORE (always
pass), optional BLOCK (always reject), and optional BBC (block by country) entries against
which all received queries are checked before external DNSBL's are queried.
IP's which pass IGNORE, BLOCK, and BBC test are then checked against the
prioritized list of DNSBL's to try when looking up an IP address for blacklisting. 
Internally, B<multi_dnsbl> maintains this list in sorted order (including
'in-addr.arpa') based on the number of responses that
resulted in an acceptable A record being returned from the DNSBL query. For
each IP address query sent to B<multi_dnsbl>, a query is sent to each
configured DNSBL sequentially until all DNSBL's have been queried or an
acceptable A record is returned.

Let us say for example that blackholes.easynet.nl (below) will return an A record
and list.dsbl.org, bl.spamcop.net, dynablock.easynet.nl, will not.

		LIST
	9451    list.dsbl.org
	6516    bl.spamcop.net
	2350    dynablock.easynet.nl
	575     blackholes.easynet.nl
	327     cbl.abuseat.org
	309     dnsbl.sorbs.net
	195     dnsbl.njabl.org
	167     sbl.spamhaus.org
	22      spews.dnsbl.net.au
	6       relays.ordb.org
	1       proxies.blackholes.easynet.nl
	0       dsbl.org

A query to B<multi_dnsbl> (pseudo.dnsbl in this example) looks like this

  	QUERY
  1.2.3.4.pseudo.dnsbl
	  |
	  V
  ####################
  #    multi_dnsbl   #
  ####################
   |				      RESPONSE
   +--> 1.2.3.4.list.dsbl.org	      NXDOMAIN
   |
   +--> 1.2.3.4.bl.spamcop.net	      NXDOMAIN
   |
   +--> 1.2.3.4.dynablock.easynet.nl  NXDOMAIN
   |
   +--> 1.2.3.4.blackholes.easynet.nl A-127.0.0.2

The A record is returned to originator of the Query and the statistics count
on blackholes.easynet.nl is incremented by one.

=head1 INSTALLATION / CONFIGURATION / OPERATION

B<multi_dnsbl> can be installed as either a standalone DNSBL or as a plug-in
to a BIND 9 installation on the same host. In either case, copy the
rc.multi_daemon script to the appropriate startup directory on your host and
modify the start, stop, restart scripts as required. Operation of the script
is as follows:

  Syntax: ./rc.multi_dnsbl start    /path/to/config.file
          ./rc.multi_dnsbl start -v /path/to/config.file
          ./rc.multi_dnsbl stop     /path/to/config.file
          ./rc.multi_dnsbl restart  /path/to/config.file

  The -v switch will print the scripts 
  actions verbosely to the STDERR.

=head2 CONFIGURATION FILE

The configuration file for B<multi_dnsbl> shares a common format with the
Mail::SpamCannibal sc_BLcheck.pl script, facilitating common maintenance of
DNSBL's for your MTA installation. 

The sample configuration file
B<multi_dnsbl.conf.sample> is heavily commented with the details for each
configuration element. If you plan to use a common configuration file in a
SpamCannibal installation, simply add the following elements to the
B<sc_BlackList.conf> file:

  MDstatfile     => '/path/to/statistics/file.txt',
  MDpidpath      => '/path/to/pidfiles', # /var/run
  MDzone         => 'pseudo.dnsbl',

  # OPTIONAL
  MDstatrefresh => 300,       # seconds
  MDipaddr      => '0.0.0.0', # PROBABLY NOT WHAT YOU WANT
  MDport        => 9953,
  
=head2 STANDALONE OPERATION

For standalone operation, simply set B<MDport = 53>, nothing more is
required.

Interrogating the installation will then return the first
match from the configured list of DNSBL servers.

  i.e.  dig 2.0.0.127.pseudo.dnsbl

        .... results

Note that the results will contain all of the "authority" and "additional"
(glue) records from the responding DNSBL placed into the additional section
of the returned record that will have an authority record from of
"localhost".

=head2 PLUGIN to BIND 9

B<multi_dnsbl> may be used as a plugin helper for a standard bind 9
installation by adding a B<forward> zone to the configuration file as
follows:

  //zone pseudo.dnsbl
  zone "pseudo.dnsbl" in {
        type forward;
        forward only;
        forwarders { 
            127.0.0.1 port 9953;
        };
  };

You may also wish to add one or more of the following statements with
appropriate address_match_lists to restrict access to the facility.  

        allow-notify {};
        allow-query { address_match_list };
        allow-recursion { address_match_list };
        allow-transfer {};      

=head2 MTA CONFIGURATION

Access to DNSBL lookup is configured in the normal fashion for each MTA.
Since MTA's generally must interrogate on port 53, B<multi_dnsbl> must be
installed on a stand-alone server or as a plugin for BIND 9. 

A typical configuration line for B<sendmail M4> configuration file is shown
below:

  FEATURE(`dnsbl',`pseudo.dnsbl',
  `554 Rejected $&{client_addr} found in http://www.spamcannibal.org')dnl

=head1 SYSTEM SIGNALS

B<multi_dnsbl> responds to the following system signals:

=over 4

=item * TERM

Operations the statistics file is updated with the internal counts and the
daemon then exits.

=item * HUP

Operations are stopped including an update of the optional statistics file,
the configuration file is re-read and operations are restarted.

=item * USR1

The statistics file is updated on the next second tick.

=item * USR2

The statistics file is deleted, internal statistics then a new (empty)
statistics file is written on the next second tick.

=back

=head1 PERL MODULE DESCRIPTION

B<Net::DNSBL::MultiDaemon> provides most of the functions that implement
B<multi_dnsbl> which is an MTA helper that interrogates a list of
DNSBL servers in preferential order based on their success rate.

The following describes the workings of individual functions
used to implement B<multi_dnsbl>.

=over 4

=item * run($BLzone,$L,$R,$DNSBL,$STATs,$Run,$Sfile,$StatStamp,$DEBUG);

This function is the 'run' portion for the DNSBL multidaemon

  input:
	$BLzone	zone name,
	$L	local listen socket object pointer,
	$R	remote socket object pointer,
	$DNSBL	config hash pointer,
	$STATs	statistics hash pointer
	$Run	pointer to stats refresh time,	# must be non-zero
	$Sfile	statistics file path,
	$StatStamp	stat file initial time stamp

  returns:	nothing

=over 2

=item * $BLzone

The fully qualified domain name of the blacklist lookup

=item * $L

A pointer to a UDP listener object

=item * $R

A pointer to a unbound UDP socket 
used for interogation an receiving replies for the multiple DNSBL's

=item * $DNSBL

A pointer to the configuration hash of the form:

  $DNSBL = {
    # Always allow these addresses
	'IGNORE' => [	# OPTIONAL
	   # a single address
	'11.22.33.44',
	   # a range of ip's, ONLY VALID WITHIN THE SAME CLASS 'C'
	'22.33.44.55 - 22.33.44.65',
	   # a CIDR range
	'5.6.7.16/28',
	   # a range specified with a netmask
	'7.8.9.128/255.255.255.240',
	   # you may want these
	'10.0.0.0/8',
	'172.16.0.0/12',
	'192.168.0.0/16',
	   # this should ALWAYS be here
	'127.0.0.0/8',  # ignore all test entries and localhost
	],

    # Always reject these addresses
	'BLOCK'	=> [	# OPTIONAL
	   # same format as above
	],

    # Always block these countries
	'BBC'	=> [qw(CN TW RO )],

    # Check for reverse lookup failures - OPTIONAL
	'in-addr.arpa'	=> {
	    timeout	=> 15,  # default timeout is 30
	},

    # RBL zones as follows: OPTIONAL
	'domain.name' => {
	    accept	=> {
		'127.0.0.2' => 'comment',
		'127.0.0.3' => 'comment',
	    },
  #	    timeout	=> 30,	# default seconds to wait for dnsbl
	},

	'next.domain' = {
	    etc....
  # included but extracted external to B<run>

	MDzone		=> 'pseudo.dnsbl',
  	MDstatfile	=> '/path/to/statistics/file.txt',
	MDpidpath	=> '/path/to/pidfiles
  # OPTIONAL, defaults shown
  #	MDstatrefresh	=> 300,	# max seconds for refresh
  #	MDipaddr	=> '0.0.0.0', # PROBABLY NOT WHAT YOU WANT
  #	MDport		=> 9953,
  # syslog. Specify the facility, one of: 
  # LOG_EMERG LOG_ALERT LOG_CRIT LOG_ERR LOG_WARNING LOG_NOTICE LOG_INFO LOG_DEBUG
  #	MDsyslog	=> 'LOG_WARNING',
  };

Zone labels that are not of the form *.*... are ignored, making this hash
table fully compatible with the SpamCannibal sc_Blacklist.conf file.

=item * $STATs

A pointer to a statistics collection array of the form:

  $STATs = {
	'domain.name' => count,
	etc...,
	'CountryCode' => count,
	etc...
  };

Initialize this array with
L<cntinit($DNSBL,$cp)|Net::DNSBL::Utilities/cntinit>, then 
L<list2hash($BBC,$cp)|Net::DNSBL::Utilities/list2hash>, then
L<statinit($Sfile,$cp)|Net::DNSBL::Utilities/statinit>, below.

=item * $Run

A POINTER to the time in seconds to refresh the $STATs backing file. Even if
there is not backing file used, this value must be a positive integer.
Setting this value to zero will stop the daemon and force a restart. It is
used by $SIG{HUP} to restart the daemon.

=item * $Sfile

The path to the STATISTICS backing file.

  i.e.  /some/path/to/filename.ext

If $Sfile is undefined, then the time stamp need not be defined

=item * $StatTimestamp

Normally the value returned by
L<statinit($Sfile,$cp)|Net::DNSBL::Utilities/statinit>, below.

=back

=cut

sub run {
  my ($BLzone,$L,$R,$DNSBL,$STATs,$Run,$Sfile,$StatStamp,$DEBUG) = @_;

  local *_alarm = sub {return $DNSBL->{"$_[0]"}->{timeout} || 30};

  $BLzone = lc $BLzone;
  $DEBUG = 0 unless $DEBUG;
  my $ROK = ($DEBUG & $D_CLRRUN) ? 0:1;

  my (	$msg, $t, $targetIP, $cc, $comment,
	$Oname,$Otype,$Oclass,$Ottl,$Ordlength,$Odata,
	$off,$id,$qr,$opcode,$aa,$tc,$rd,$ra,$mbz,$ad,$cd,$rcode,
	$qdcount,$ancount,$nscount,$arcount,
	$name,$type,$class,
	$ttl,$rdl,@rdata,
	$l_Sin,$rip,$zone,@blist,
	%remoteThreads,
	$rin,$rout,$nfound,
	$BBC,@NAignore,@NAblock);

  my $LogLevel = 0;
  if ($DNSBL->{MDsyslog}) {		# if logging requested
    require Unix::Syslog;
    import  Unix::Syslog @Unix::Syslog::EXPORT_OK;
    $LogLevel = eval "$DNSBL->{MDsyslog}";
## NOTE, logging must be initiated by the caller
  }

# generate NetAddr objects for addresses to always pass
  if ($DNSBL->{IGNORE} && ref $DNSBL->{IGNORE} eq 'ARRAY' && @{$DNSBL->{IGNORE}}) {
    list2NetAddr($DNSBL->{IGNORE},\@NAignore);
  }

# generate NetAddr objects for addresses to always reject
  if ($DNSBL->{BLOCK} && ref $DNSBL->{BLOCK} eq 'ARRAY' && @{$DNSBL->{BLOCK}}) {
    list2NetAddr($DNSBL->{BLOCK},\@NAblock);
  }

# fetch pointer to Geo::IP methods
  if ($DNSBL->{BBC} && ref $DNSBL->{BBC} eq 'ARRAY' && @{$DNSBL->{BBC}}) {
    require Geo::IP::PurePerl;
    $BBC = new Geo::IP::PurePerl;
  }

  my $filenoL = fileno($L);
  my $filenoR = fileno($R);

  my $now = time;
  my $newstat = 0;			# new statistics flag
  my $refresh = $now + $$Run;		# update statistics "then"

  local $SIG{USR1} = sub {$newstat = 2}; # force write of stats now
  local $SIG{USR2} = sub {		# kill and regenerate statfile
	return unless $Sfile;
	unlink $Sfile;
	foreach(keys %$STATs) {
	  $STATs->{"$_"} = 0;
	}
	$StatStamp = statinit($Sfile,$STATs);
	syslog($LogLevel,"received USR2, clear stats\n")
		if $LogLevel;
	$newstat = 2;			# re-write on next second tick
  };

  my $SOAptr = [	# set up bogus SOA
	$BLzone,
	&T_SOA,
	&C_IN,
	0,		# ttl of SOA record
	'localhost',
	'root.localhost',
	$now,
	86400,
	43200,
	172800,
	3600,		# cache negative TTL's for an hour
  ];

  my ($get,$put,$parse) = new Net::DNS::ToolKit::RR;

  my $numberoftries = 6;

  my %deadDNSBL;
  foreach(keys %$STATs) {
    next unless $_ =~ /\./;					# only real domains
    $deadDNSBL{"$_"} = 1;					# initialize dead DNSBL timers
  }

  do {
    $rin = '';
    vec($rin,$filenoL,1) = 1;					# always listening to local port
    (vec($rin,$filenoR,1) = 1)					# listen to remote only if traffic expected
	if %remoteThreads;
    $nfound = select($rout=$rin,undef,undef,1);			# tick each second
    if ($nfound > 0) {
###################### IF PROCESS REQUEST ########################
      while (vec($rout,$filenoL,1)) {				# process request
	last unless ($l_Sin = recv($L,$msg,PACKETSZ,0));	# ignore receive errors
	if (length($msg) < HFIXEDSZ) {				# ignore if less then header size
	  return 'short header' if $DEBUG & $D_SHRTHD;
	  last;
	}
	($off,$id,$qr,$opcode,$aa,$tc,$rd,$ra,$mbz,$ad,$cd,$rcode,
		$qdcount,$ancount,$nscount,$arcount)
		= gethead(\$msg);
	if ($qr) {
	  return 'query response' if $DEBUG & $D_QRESP;
	  last;
	}
	$comment = 'no bl';
	if ($opcode != QUERY) {
	  s_response(\$msg,NOTIMP,$id,1,0,0,0);
	  $comment = 'not implemented';
	} elsif (
		$qdcount != 1 || 
		$ancount || 
		$nscount || 
		$arcount
		) {
	  s_response(\$msg,FORMERR,$id,$qdcount,$ancount,$nscount,$arcount);
	  $comment = 'format error';
	} elsif (
		(($off,$name,$type,$class) = $get->Question(\$msg,$off)) && 
		! $name) {					# name must exist
	  s_response(\$msg,FORMERR,$id,1,0,0,0);
	  $comment = 'format error';
	} elsif ($class != C_IN) {				# class must be C_IN
	  s_response(\$msg,REFUSED,$id,$qdcount,$ancount,$nscount,$arcount);
	  $comment = 'refused';
	} elsif ($name !~ /$BLzone$/i) {			# question must be for this zone
	  s_response(\$msg,NXDOMAIN,$id,1,0,0,0);
	  $comment = 'not this zone';
	} else {

# THIS IS OUR ZONE request, generate a thread to handle it

	  print STDERR $name,' ',TypeTxt->{$type},' ' if $DEBUG & $D_VERBOSE;

	  if (	$type == T_A ||
		$type == T_ANY) {
	    if ($name =~ /^((\d+)\.(\d+)\.(\d+)\.(\d+))\.(.+)/ &&
		($rip = $1) &&
		($targetIP = "$5.$4.$3.$2") &&
		($zone = $6) &&
		$BLzone eq lc $zone) {
	      if (@NAignore && matchNetAddr($targetIP,\@NAignore)) {	# check for IP's to always pass
		not_found($put,$name,$type,$id,\$msg,$SOAptr);		# return unconditional NOT FOUND
		$STATs->{WhiteList} += 1;				# bump WhiteList count
		$comment = 'IGNORE';
	      }
	      elsif (@NAblock && matchNetAddr($targetIP,\@NAblock)) {	# check for IP's to always block
		($msg) = _ansrbak($put,$id,1,$rip,$zone,$type,3600,A1275);	# answer 127.0.0.5
		$STATs->{BlackList} += 1;				# bump BlackList count
		$comment = 'BLOCK';
	      }
	      elsif ($BBC &&						# check for IP's to block by country
		     ($cc = $BBC->country_code_by_addr($targetIP)) &&
		     (grep($cc eq $_,@{$DNSBL->{BBC}}))) {
		($msg) = _ansrbak($put,$id,1,$rip,$zone,$type,3600,A1276);	# answer 127.0.0.6
		$STATs->{$cc} += 1;					# bump statistics count
		$newstat = 1;						# notify refresh that update may be needed
		$comment = "block $cc";
	      }
	      else {
		@blist = ();
		foreach(sort {$STATs->{"$b"} <=> $STATs->{"$a"}} keys %$STATs) {
		  next unless $_ =~ /\./;				# drop passed,white,black,bbc entries
		  push @blist, $_;
		}
		bl_lookup($put,\$msg,\%remoteThreads,$l_Sin,_alarm($blist[0]),$id,$rip,$type,$zone,@blist);
		send($R,$msg,0,$R_Sin);				# udp may not block
		print STDERR $blist[0] if $DEBUG & $D_VERBOSE;
		last;
	      }
	    } else {
	      not_found($put,$name,$type,$id,\$msg,$SOAptr);
	    }
	  } elsif ($type == T_NS ||				# answer common queries with a not found
		 $type == T_MX ||
		 $type == T_SOA ||
		 $type == T_CNAME ||
		 $type == T_TXT) {
	    not_found($put,$name,$type,$id,\$msg,$SOAptr);
	  } elsif ($type == T_AXFR) {
	    s_response(\$msg,REFUSED,$id,1,0,0,0);
	    $comment = 'refused AXFR';
	  } else {
	    s_response(\$msg,NOTIMP,$id,1,0,0,0);
	    $comment = 'not implemented';
	  }
	}
	send($L,$msg,0,$l_Sin);					# udp may not block on send
	print STDERR " $comment\n" if $DEBUG & $D_VERBOSE;
	last;
      }
##################### IF RESPONSE  ###############################
      while (vec($rout,$filenoR,1)) {				# A response
	undef $msg;
	last unless recv($R,$msg,,PACKETSZ,0);			# ignore receive errors
	if (length($msg) < HFIXEDSZ) {				# ignore if less then header size
	  return 'short header' if $DEBUG & $D_SHRTHD;
	  last;
	}
	($off,$id,$qr,$opcode,$aa,$tc,$rd,$ra,$mbz,$ad,$cd,$rcode,
		$qdcount,$ancount,$nscount,$arcount)
		= gethead(\$msg);
	unless (  $tc == 0 &&
		  $qr == 1 &&
		  $opcode == QUERY &&
		  ($rcode == NOERROR || $rcode == NXDOMAIN || $rcode == SERVFAIL) &&
		  $qdcount == 1 &&
		  exists $remoteThreads{$id}) {			# must not be my question!
	  return 'not me 1' if $DEBUG & $D_NOTME;
	  last;
	}
	($l_Sin,$rip,$type,$zone,@blist) = @{$remoteThreads{$id}->{args}};

	($off,$name,$t,$class) = $get->Question(\$msg,$off);

	my $answer;
	if ($ancount && $rcode == &NOERROR) {
	  $name =~ /^(\d+\.\d+\.\d+\.\d+)\.(.+)$/;
	  my $z = lc $2;
	  unless (  $z eq lc $blist[0] &&			# not my question
	  	    $1 eq $rip &&				# not my question
		    ($t == T_A || $t == T_PTR) &&		# not my question
		    $class == C_IN) {				# not my question
	    return 'not me 2' if $DEBUG & $D_NOTME;
	    last;
	  }
	  undef $answer;

	ANSWER:
	  foreach(0..$ancount -1) {
	    ($off,$name,$t,$class,$ttl,$rdl,@rdata) = $get->next(\$msg,$off);
	    next if $answer;					# throw away unneeded answers
	    if ($t == T_A) {
	      while($answer = shift @rdata) {			# see if answer is on accept list
		my $IP = inet_ntoa($answer);
		if (grep($IP eq $_,keys %{$DNSBL->{"$blist[0]"}->{accept}})) {
		  $answer = A1272;
		  last;
		}
		undef $answer;
	      } # end of rdata
	    }
	  } # end of each ANSWER
	}
	elsif ($t == T_PTR && ($rcode == NXDOMAIN || $rcode == SERVFAIL)) { # no reverse lookup
	  $answer = A1274;
	  $ttl = 3600;
	  $nscount = $arcount = 0;
	}

	if ($answer) {						# if valid answer
	  delete $remoteThreads{$id};
	  $STATs->{"$blist[0]"} += 1;				# bump statistics count
	  $newstat = 1;						# notify refresh that update may be needed
	  my($nmsg,$noff,@dnptrs) =				# make proto answer
		_ansrbak($put,$id,$nscount + $arcount +1,$rip,$zone,$type,$ttl,$answer);

# add the ns section from original reply into the authority section so we can see where it came from, it won't hurt anything
	  foreach(0..$nscount -1) {
	    ($off,$Oname,$Otype,$Oclass,$Ottl,$Ordlength,$Odata)
		= $get->next(\$msg,$off);
	    ($noff,@dnptrs) = $put->NS(\$nmsg,$noff,\@dnptrs,
		$Oname,$Otype,$Oclass,$Ottl,$Odata);
	  }

# add the authority section from original reply so we can see where it came from
	  foreach(0..$arcount -1) {
	    ($off,$Oname,$Otype,$Oclass,$Ottl,$Ordlength,$Odata)
		= $get->next(\$msg,$off);
	    ($noff,@dnptrs) = $put->A(\$nmsg,$noff,\@dnptrs,
		$Oname,$Otype,$Oclass,$Ottl,$Odata);
	  }
	  $msg = $nmsg;
	  $ROK = 0 if $DEBUG & $D_ANSTOP;
	}
	elsif (do {
		print STDERR '+' if $DEBUG & $D_VERBOSE;
		my $rv = 0;
		while(!$rv) {
		  shift @blist;
		  unless (@blist) {
		    $rv = 1;
		  } else {
		    last unless $deadDNSBL{"$blist[0]"} > $numberoftries; # ignore hosts that don't answer
		  }
		}
		$rv;
	      }) {	# if no more hosts
	  delete $remoteThreads{$id};
	  not_found($put,$rip .'.'. $zone,$type,$id,\$msg,$SOAptr);	# send not found response
	  $STATs->{Passed} += 1;
	  $newstat = 1;							# notify refresh that update may be needed
	} else {
	  $deadDNSBL{"$blist[0]"} = 1;					# reset retry count
	  bl_lookup($put,\$msg,\%remoteThreads,$l_Sin,_alarm($blist[0]),$id,$rip,$type,$zone,@blist);
	  print STDERR $blist[0] if $DEBUG & $D_VERBOSE;
	  send($R,$msg,0,$R_Sin);					# udp may not block
	  last;
	}
	send($L,$msg,0,$l_Sin);

	if ($DEBUG & $D_VERBOSE) {
	  if ($answer) {
	    print STDERR ' ',inet_ntoa($answer),"\n";
	  } else {
	    print STDERR " no bl\n";
	  }
	}
	last;
      }
    }
##################### TIMEOUT, do busywork #######################
    else {							# must be timeout
      $now = time;						# check various alarm status
      foreach $id (keys %remoteThreads) {
	next unless $remoteThreads{$id}->{expire} < $now;	# expired??

	($l_Sin,$rip,$type,$zone,@blist) = @{$remoteThreads{$id}->{args}};

	if (++$deadDNSBL{"$blist[0]"} > $numberoftries) {
	  $deadDNSBL{"$blist[0]"} = 3600;			# wait an hour to retry
	  if ($LogLevel) {
	    syslog($LogLevel, "timeout connecting to $blist[0]\n");
	  }
	}

	if ($blist[0] eq 'in-addr.arpa') {			# expired reverse DNS lookup ?
	  delete $remoteThreads{$id};
	  $deadDNSBL{"$blist[0]"} = 0;				# reset timeout (this one never expires)
	  $STATs->{"$blist[0]"} += 1;				# bump statistics count
	  $newstat = 1;						# notify refresh that update may be needed
	  ($msg) = _ansrbak($put,$id,1,$rip,$zone,$type,3600,A1274);
	  send($L,$msg,0,$l_Sin);
	  print STDERR " expired Rdns\n" if $DEBUG & $D_VERBOSE;
	}
	elsif (do {
		print STDERR '?' if $DEBUG & $D_VERBOSE;
		my $rv = 0;
		while(!$rv) {
		  shift @blist;
		  unless (@blist) {
		    $rv = 1;
		  } else {
		    last unless $deadDNSBL{"$blist[0]"} > $numberoftries; # ignore hosts that don't answer
		  }
		}
		$rv;
	      }) {	# if no more hosts
	  delete $remoteThreads{$id};
	  not_found($put,$rip .'.'. $BLzone,$type,$id,\$msg,$SOAptr);# send not found response
	  $STATs->{Passed} += 1;				# count messages that pass thru this filter
	  $newstat = 1;						# notify refresh that update may be needed
	  send($L,$msg,0,$l_Sin);
	  print STDERR " no bl\n" if $DEBUG & $D_VERBOSE;
	} else {
	  bl_lookup($put,\$msg,\%remoteThreads,$l_Sin,_alarm($blist[0]),$id,$rip,$type,$zone,@blist);
	  send($R,$msg,0,$R_Sin);				# udp may not block
	  print STDERR $blist[0] if $DEBUG & $D_VERBOSE;
	}
      }
      foreach(keys %deadDNSBL) {				# eventually retry dead DNSBL
	--$deadDNSBL{"$_"} if $deadDNSBL{"$_"} > $numberoftries;
      }
      if ($newstat > 1 ||
	  ($refresh < $now && $newstat)) {			# update stats file
	write_stats($Sfile,$STATs,$StatStamp);
	$refresh = $now + $$Run;
	$newstat = 0;
      }
      return 'caught timer' if $DEBUG & $D_TIMONLY;
    }
  } while($$Run && $ROK);
  write_stats($Sfile,$STATs,$StatStamp) if $newstat;	# always update on exit if needed
}

# answer back prototype
#
# input:	$put,$id,$arcount,$rip,$zone,$type,$ttl,$answer
# returns:	$message,$off,@dnptrs
#
sub _ansrbak {
  my($put,$id,$arc,$rip,$zone,$type,$ttl,$ans) = @_;
  my $nmsg;
  my $noff = newhead(\$nmsg,
	$id,
	BITS_QUERY | QR,
	1,1,1,$arc,
  );
  ($noff,my @dnptrs) = $put->Question(\$nmsg,$noff,	# 1 question
	$rip .'.'. $zone,$type,C_IN);			# type is T_A or T_ANY
  ($noff,@dnptrs) = $put->A(\$nmsg,$noff,\@dnptrs,		# 1 answer
	$rip .'.'. $zone,T_A,C_IN,$ttl,$ans);
  ($noff,@dnptrs) = $put->NS(\$nmsg,$noff,\@dnptrs,	# 1 authority
	$zone,T_NS,C_IN,86400,'localhost');
  ($noff,@dnptrs) = $put->A(\$nmsg,$noff,\@dnptrs,	# 1 additional glue
	'localhost',T_A,C_IN,86400,A1271);		# lie about nameserver 127.0.0.1
  return($nmsg,$noff,@dnptrs)
}

=item * bl_lookup($put,$mp,$rtp,$sinaddr,$alarm,$id,$rip,$type,$zone,@blist);

Generates a query message for the first DNSBL in the @blist array. Creates
a thread entry for the response and subsequent queries should the first one fail.

  input:	put,
		message pointer,
		remote thread pointer,
		sockinaddr,
		connection timeout,
		id of question,
		reverse IP address in text
		type of query received, (used in response)
		ORIGINAL zone (case preserved),
		array of remaining DNSBL's in sorted order
  returns:	nothing, puts stuff in thread queue

=back

=cut

sub bl_lookup {
  my($put,$mp,$rtp,$sinaddr,$alarm,$id,$rip,$type,$zone,@blist) = @_;
  my $off = newhead($mp,
	$id,
	BITS_QUERY | RD,
	1,0,0,0,
  );
  my $Qtype = ($blist[0] eq 'in-addr.arpa')
	? &T_PTR
	: &T_A;
  $put->Question($mp,$off,$rip .'.'. $blist[0],$Qtype,C_IN);
  $rtp->{$id} = {
	args	=> [$sinaddr,$rip,$type,$zone,@blist],
	expire	=> time + $alarm,
  };
}

=head1 DEPENDENCIES

	Unix::Syslog
	Geo::IP::PurePerl
	NetAddr::IP
	Net::DNS::Codes
	Net::DNS::ToolKit

=head1 EXPORT_OK

        run
        bl_lookup  

=head1 EXPORT_TAGS :debug

  DEBUG is a set of semaphores for the 'run' function

  $D_CLRRUN    = 0x1;  # clear run flag and force unconditional return
  $D_SHRTHD    = 0x2;  # return short header message
  $D_TIMONLY   = 0x4;  # exit at end of timer section
  $D_QRESP     = 0x8;  # return query response message
  $D_NOTME     = 0x10; # return received response not for me
  $D_ANSTOP    = 0x20; # clear run OK flag if ANSWER present
  $D_VERBOSE   = 0x40; # verbose debug statements to STDERR 

=head1 AUTHOR

Michael Robinton, michael@bizsystems.com

=head1 COPYRIGHT

Copyright 2003, Michael Robinton & BizSystems
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or 
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of 
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the  
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

=head1 SEE ALSO

L<Net::DNSBL::Utilities>, L<Net::DNS::Codes>, L<Net::DNS::ToolKit>, L<Mail::SpamCannibal>

=cut

1;
