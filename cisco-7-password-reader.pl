#!/usr/bin/perl -w
#
#  cisco-7-password-reader.pl
#
# Credits for orginal code and description hobbit@avian.org,
# SPHiXe, .mudge et al. and for John Bashinski <jbash@CISCO.COM>
# for Cisco IOS password encryption facts.
#
# Use for any malice or illegal purposes strictly prohibited!
#
#   Syntax is: cisco-7-crack.pl [filename]
#   Example:  cisco-7-crack.pl /var/consoles/current/sw1-5 
#
#  If you don't point it to a valid file, you will get an error.
#
#  The script only looks for "password 7" strings, and will
# translate the password.
#
#  If you specify the -v argument before the filename, if you
# want to see all the lines in the file, with the translated passwords.
#    Verbose Syntax is: cisco-7-crack.pl -v [filename]

$debug = "silent";
@xlat = ( 0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41,
          0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c,
          0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53 , 0x55, 0x42 );

my $userinput = $ARGV[0];
my $userarg = $ARGV[1];

if(lc($userinput) eq '-v') {
        $debug = "verbose";
        }

while (<>) {
        if (/(password|md5)\s+7\s+([\da-f]+)/io) {
            if (!(length($2) & 1)) {
                $ep = $2; $dp = "";
                ($s, $e) = ($2 =~ /^(..)(.+)/o);
                for ($i = 0; $i < length($e); $i+=2) {
                    $dp .= sprintf "%c",hex(substr($e,$i,2))^$xlat[$s++];
                }
                s/7\s+$ep/$dp/;
            }
        if (($debug) eq "silent") { print; }
        }
if (($debug) eq "verbose") { print; }
}
# eof
