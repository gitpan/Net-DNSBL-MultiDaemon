use ExtUtils::MakeMaker;
use Config;

my $pkg = 'Net::DNSBL::MultiDaemon';
$pkg =~ /[^:]+$/;
my $module = $& .'.pm';

eval {
	require Net::DNS::ToolKit;
};
die "prerequisite Net::DNS::ToolKit not found\n"
	if $@;
@_ = &Net::DNS::ToolKit::get_ns();
if (@_) {
  foreach(@_) {
    print 'found nameserver ',&Net::DNS::ToolKit::inet_ntoa($_),"\n";
  }
} else {
  die "resolver not configured, Net::DNSBLS::MultiDaemon will not run\n";
}

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
    'NAME'		=> $pkg,
    'VERSION_FROM'	=> $module, # finds $VERSION
    'PREREQ_PM'		=> {	Net::DNS::Codes		=> 0.08,
				Net::DNS::ToolKit	=> 0.24,
				Unix::Syslog		=> 0.97,
				NetAddr::IP::Lite	=> 0.02,
				Geo::IP::PurePerl	=> 1.10,
			},
    'clean'		=> { FILES    => "*~ tmp*"},
    'dist'		=> {COMPRESS=>'gzip', SUFFIX=>'gz'}
);

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
