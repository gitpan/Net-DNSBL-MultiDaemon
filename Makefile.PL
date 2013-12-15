use ExtUtils::MakeMaker;
use Config;

my $pkg = 'Net::DNSBL::MultiDaemon';
$pkg =~ /[^:]+$/;
my $module = $& .'.pm';

my $now = time;
my $then = (stat('./Makefile.old'))[9] || 0;
# set number of seconds to view
my $view = $then +86400 < $now ? 5:0;

my $doview = 0;
unless (eval {
	require Geo::IP::PurePerl &&
	$Geo::IP::PurePerl::VERSION >= 1.10
	} ) {
  print q|
Geo::IP::PurePerl v1.10 or greater is required if you
want to use Country Codes to reject connections.
Net::DNSBL::MultiDaemon will run without this module
but will not provide Block Country Code service.

|;
  $doview = 1;
}

unless (eval {
	require URBL::Prepare
	} ) {
  print q|
URBL::Prepare is required if you want to do RHBL 
checking of URBL domains.
Net::DNSBL::MultiDaemon will run without this 
module but will not provide URBL lookups

|;
  $doview = 1;
}
sleep $view if $doview && $view;

WriteMakefile(
    'NAME'		=> $pkg,
    'VERSION_FROM'	=> $module, # finds $VERSION
    'PREREQ_PM'		=> {
				Test::More		=> 0,
				File::SafeDO		=> 0.12,
				Net::DNS::Codes		=> 0.09,
				Net::DNS::ToolKit	=> 0.47,
				Unix::Syslog		=> 0.97,
				NetAddr::IP		=> 4.067,
				Net::NBsocket		=> 0.23,
			},
    'clean'		=> { FILES    => "*~ tmp*"},
    'dist'		=> {COMPRESS=>'gzip', SUFFIX=>'gz'}
);

#eval {
#	require Net::DNS::ToolKit;
#};
#die "prerequisite Net::DNS::ToolKit not found\n"
#	if $@;
#@_ = &Net::DNS::ToolKit::get_ns();
#if (@_) {
#  foreach(@_) {
#    print 'found nameserver ',&Net::DNS::ToolKit::inet_ntoa($_),"\n";
#  }
#} else {
#  print STDERR "resolver not configured, Net::DNSBLS::MultiDaemon will not run\n";
#  exit 0;
#}

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

sub MY::top_targets {
  package MY;
  my $inherited = shift->SUPER::top_targets(@_);
  $inherited =~ s/(pure_all\s+::.+)/$1 README/;
  $inherited;
}

sub MY::post_constants {
  my $post_constants = q|
MY_POD2TEXT = |. $Config{scriptdirexp} .'/pod2text' .q|   
|;
} 

sub MY::postamble {
  package MY;
  my $postamble = q|
README  : |. $module .q|
	@$(MY_POD2TEXT) |. $module .q| > README

|;
}
