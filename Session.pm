

package CGI::AIS::Session;

 use strict;

use vars qw{ *SOCK @ISA @EXPORT $VERSION };

require Exporter;

 @ISA = qw(Exporter);
 @EXPORT = qw(Authenticate);

 $VERSION = '0.01';

use Carp;


use Socket qw(:DEFAULT :crlf);
use IO::Handle;
sub miniget($$$$){
        my($HostName, $PortNumber, $Desired, $agent)  = @_;
        $PortNumber ||= 80;
        # print STDERR ~~localtime,"Trying to connect to $HostName $PortNumber to retrieve $Desired\n";
        my $iaddr       = inet_aton($HostName)  || die "Cannot find host named $HostName";
        my $paddr       = sockaddr_in($PortNumber,$iaddr);
        my $proto       = getprotobyname('tcp');
                                                        
        socket(SOCK, PF_INET, SOCK_STREAM, $proto)  || die "socket: $!";
        connect(SOCK, $paddr)    || die "connect: $!";
        SOCK->autoflush(1);

        print SOCK
                "GET $Desired HTTP/1.1$CRLF",
                # Do we need a Host: header with an "AbsoluteURI?"
                # not needed: http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html#sec5.2
                # but this is trumped by an Apache error message invoking RFC2068 sections 9 and 14.23
                "Host: $HostName$CRLF",
                "User-Agent: $agent$CRLF",
                "Connection: close$CRLF",
                $CRLF;

        join('',<SOCK>);

};



sub Authenticate{

        my %Param = (agent => 'AISclient', @_);
        my %Result;
        my $AISXML;

        # print STDERR "cookie string is $ENV{HTTP_COOKIE}\n";

        my ($Cookie) = ($ENV{HTTP_COOKIE} =~  /AIS_Session=(\w+)/);
        tie my %Session, $Param{tieargs}->[0],
        $Param{tieargs}->[1],$Param{tieargs}->[2],$Param{tieargs}->[3],
        $Param{tieargs}->[4],$Param{tieargs}->[5],$Param{tieargs}->[6],
        $Param{tieargs}->[7],$Param{tieargs}->[8],$Param{tieargs}->[9]
                or croak "failed to tie @{$Param{tieargs}}";

        if ($Cookie and ! $Session{$Cookie}){
                $Cookie = '';

        };

        my $OTUkey;
        my $SessionKey;
        if ($ENV{QUERY_STRING} =~ /AIS_OTUkey=(\w+)/){
           $OTUkey = $1;

           my ($method, $host, $port, $path) =
             ($Param{aissri} =~ m#^(\w+)://([^:/]+):?(\d*)(.+)$#)
              or die "Could not get meth,hos,por,pat from <$Param{aissri}>";
           unless ($method eq 'http'){
                croak "aissri parameter must begin 'http://' at this time";
           };

           # print STDERR "about to miniget for: ${CRLF}GET $Param{aissri}query?$OTUkey$CRLF$CRLF";
           # my $Response = `lynx -source $Param{aissri}query?$OTUkey$CRLF$CRLF`
           my $Response = miniget $host, $port,
           "$Param{aissri}query?$OTUkey", $Param{agent};

           $SessionKey = join('',time,(map {("A".."Z")[rand 26]}(0..19)));
           print "Set-Cookie: AIS_Session=$SessionKey;$CRLF";
           ($AISXML) =
                $Response =~ m#<aisresponse>(.+)#si
                   or die "no <aisresponse> element from $Param{aissri}query?$OTUkey\n";
           $Session{$SessionKey} = $AISXML;

        }elsif (!$Cookie){
                print "Location: $Param{aissri}present?http://$ENV{SERVER_NAME}$ENV{REQUEST_URI}?AIS_OTUkey=\n\n";
                exit;
        }else{ # We have a cookie
                $AISXML = $Session{$Cookie};
                delete  $Session{$Cookie} if $ENV{QUERY_STRING} eq 'AIS_LOGOUT';
        };

        foreach (qw{
                        identity
                        error
                        aissri
                        user_remote_addr
                       },
                    @{$Param{XML}}
        ){
                # print STDERR "Looking for $_ in XML\n";
                $AISXML =~ m#<$_>(.+)#si or next;
                $Result{$_} = $1;
                # print STDERR "Found $Result{$_}\n";
        };

        if ( defined($Param{timeout})){
                my $TO = $Param{timeout};
                delete @Session{ grep { time - $_ > $TO } keys %Session };

        };

        #Suppress caching NULL and ERROR
        if( $Result{identity} eq 'NULL' or $Result{identity} eq 'ERROR'){
                print "Set-Cookie: AIS_Session=$CRLF";
                $SessionKey and delete $Session{$SessionKey} ;
        };
        # print STDERR "About to return session object\n";
        # print STDERR "@{[%Result]}\n";
        return \%Result;
};


# Preloaded methods go here.

1;
__END__

=head1 NAME

CGI::AIS::Session - Perl extension to manage CGI user sessions with external identity authentication via AIS

=head1 SYNOPSIS
  use DirDB;    # or any other concurrent-access-safe
                # persistent hash abstraction
  use CGI::AIS::Session;
  my $Session = Authenticate(
             aissri <= 'http://www.pay2send.com/cgi/ais/',
             tieargs <= ['DirDB', './data/Sessions'],
             XML <= ['name','age','region','gender'],
             agent <= 'Bollow',      # this is the password for the AIS service, if needed
             ( $$ % 100 ? () : (timeout <= 4 * 3600)) # four hours
  );
  if($$Session{identity} eq 'NULL'){
        print "Location: http://www.pay2send.com/cgi/ais/login\n\n"
        exit;
  }elsif($Session->{identity} eq 'ERROR'){
        print "Content-type: text/plain\n\n";
        print "There was an error with the authentication layer",
              " of this web service: $Session->{error}\n\n",
              "please contact $ENV{SERVER_ADMIN} to report this.";
        exit;
  }
  tie my %UserData, 'DirDB', "./data/$$Session{identity}";
 

=head1 DESCRIPTION

Creates and maintains a read-only session abstraction based on data in
a central AIS server.

The session data provided by AIS is read-only.  A second
database keyed on the identity provided by AIS should be
used to store persistent local information such as shopping cart
contents. This may be repaired in future releases, so the 
session object will be more similar to the session objects
used with the Apache::Session modules, but for now, all the
data in the object returned by C<Authenticate> comes from the
central AIS server.

On the first use, the user is redirected to the AIS server
according to the AIS protocol. Then the identity, if any,
is cached
under a session key in the session database as tied to by
the 'tieargs' parameter.

This module will create a http cookie named AIS_Session.

Authenticate will croak on aissri methods other than
http in this version.

Additional expected XML fields can be listed in an XML parameter.

If a 'timeout' paramter is provided,  Sessions older than
the timeout get deleted from the tied sessions hash.

'ERROR' and 'NULL' identities are not cached.

Internally, the possible states of this system are:

no cookie, no OTU
OTU
cookie

Only the last one results in returning a session object. The
other two cause redirection.

if a query string of AIS_LOGOUT is postpended to any url in the
domain protected by this module, the session will be deleted before
it times out.

=head1 EXPORTS

the Authenticate routine is exported.

=head1 AUTHOR

David Nicol, davidnico@cpan.org

=head1 SEE ALSO

http://www.pay2send.com/ais/ais.html

The Apache::Session family of modules on CPAN


=cut



