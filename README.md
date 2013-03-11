perl-cisco-passwd7-reader
========================

Greps through a file (or files...) to find and decode crpyt-7-type Cisco passwords.

Many useful tools can be traced back to one or two key contributors. (I really love author attributions!)
In the case of Cisco type-7 passwords, almost every road that gives credit, gives the credit to jbash. :-)

I've merely embelished on the best of the basic decrypt scripts that I could find.  This version will;
  +  take a filename as the source of the crypt (rather than just a password string)
  +  It can also take a bunch of files! Try using the wildcard (*) on your log directory!
    +  The script prepends the password string output with the filename where it was found!
  +  The -v flag prints all lines found, replacing the crypted passwords with cleartext

I made this public for two reasons;
  1) It was tough to find a good, working example on the web. Maybe this will help?
  
  2) There are many websites which will let you paste in a password cipher and return the 
  clear text to you. And I'm certain that some very large number of them are merely there to 
  collect passwords from the unsuspecting, and add them to a crackers dictionary. Paranoid?
  Perhaps. But, with a "local" tool that doesn't use the cloud, I sleep better at night. :-)

You may also be interested in one of my other projects;
   http://www.conserver.com/consoles/Cisco/ciscocons.html
