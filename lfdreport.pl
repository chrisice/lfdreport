#!/usr/bin/perl

use Term::ANSIColor;

open FILE, "/var/log/lfd.log";
print "\n";
print color 'red';
print "Files recently detected as modified by LFD: " . color 'reset';
print "\n\n";

while ( $modified_files = <FILE> ){
if ( $modified_files=~/(\*System Integrity\* has detected modified file\(s\)\:)(.+$)/i ) {
$modified_file = join("\n", split(' ', $2));
print $modified_file . "\n\n";
}
}

open FILE, "/var/log/lfd.log";
print "\n";
print color "red";
print "Warnings for processes that WERE NOT killed (Kill:0) :  " . color 'reset';

@warnings = "";
while ($warnings = <FILE>) {
if ( $warnings=~/(Kill\:0)(.+?)(User:)(.+?\s)(.+?EXE\:)(.+?\s)(CMD\:)(.+?\s)(.+$)/i) {
my $warning_number = $1;
push (@warnings, $warning_number);
}
}
my %warnings;
$warnings{$_}++ foreach @warnings;
while (my ($key, $value) = each(%warnings)) {
	if ($key =~ /.*$/) {
		delete($warnings[$key]);
}
}
print scalar (@warnings). "\n\n";


open FILE, "/var/log/lfd.log";
print "\n";
print color "red";
print "Warnings for processes that WERE killed (Kill:1) :  " . color 'reset';

@warnings = "";
while ($warnings = <FILE>) {
if ( $warnings=~/(Kill\:1)(.+?)(User:)(.+?\s)(.+?EXE\:)(.+?\s)(CMD\:)(.+?\s)(.+$)/i) {
my $warning_number = $1;
push (@warnings, $warning_number);
}
}
my %warnings;
$warnings{$_}++ foreach @warnings;
while (my ($key, $value) = each(%warnings)) {
        if ($key =~ /.*$/) {
                delete($warnings[$key]);
}
}
print scalar (@warnings). "\n\n";


print color "red";
print "\n\nRecent SSH logins:\n\n". color 'reset';

@ssh = "";
open FILE, "/var/log/lfd.log";
while ($logins = <FILE>) {
if ( $logins =~ /(\*SSH login\*.+?)([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).+?using\s(.+$)/i) {
my $ip = $2;
my $logintype = $3;
print "Login IP: " . $ip . "\nLogin Type: " . $logintype . "\n\n";
}
}



close FILE;
