#!/usr/bin/perl

# Point string processor
# (c) Stas Degteff 2:5080/102

# $Id$
#
#
#

$helpmsg = <<HELP ;
USAGE:
	$0

Pntstr scan secure inbound directory for files pointstr.* (* = point number)
and parse its.

Point string file format (with line numbers):
1: Session_password_for_point
2: Pointlist string

HELP

#-----------------------------------------------------------------------------#
#
# $Log$
# Revision 1.3  2002/10/28 08:25:50  stas_degteff
# Fix shebang
#
# Revision 1.2  2002/06/04 11:37:05  stas
# Some bugs fixed.
#
# Revision 1.6  2002/06/03 18:48:27  User
# Many, many fixes.
#
# Revision 1.5  2002/06/02 14:20:30  User
# First release.
# Fidoconfig parsing implement (include not supported).
# Add log support.
#
# Revision 1.4  2002/06/01 14:31:21  User
# RCS tag 'log' inserted
#
# Revision 1.3  2002/06/01 14:30:22  User
# Reading fidoconfig implemented
#
# Revision 1.2  2002/06/01 12:52:37  User
# .bak file create
#
# Revision 1.1  2002/06/01 11:53:34  User
# First beta
#
#
#=============================================================================#

# Setup section --------------------------------------------------------------#

#DOS/WIN
$fidoconfig = "\\ftn\\config";
#UNIX
#$fidoconfig = "/usr/local/etc/fido/links";

$PntStrFileMask   = "PNTSTR.*";
$PointSegmentFile = "segNNNN.ptn";  # NNNN replace to node number in future

# read from fidoconfig
$address = "2:5080/102";
$logfiledir  = "\\ftn\\log";
#$logfiledir = ".";
$nodelistdir = "\\ftn\\nodelist";
$protinbound = "\\ftn\\inbound";

# Variables (& constants) section

%password = ();
%pointName = ();

@validflags = ( V34, V32, V32B, VFC, HST, X2C, X2S, V90C, V90S, HST, H14, H16,
                ZYX, Z19, V32T, CSP, PEP, MAX, H96, MNP, V42B, V42, V29, V22,
                V110L, V110H, V120L, V120H, X75, ISDN, # ISDN
                IBN, IFT, IFC, ITN, IVM, IP, # IP-based
                IMI, IUC, ITX, ISE, IEM, # SMTP-based
                EVY, EMA,                # email-based
#                RPK, NPK, NEC, REC, NC, SMH # coordinators & secure mail hub
                CM, MN, MO, LO,
                PING, # auto-reply
                UUCP, # internet email gate (official)
                "G[A-Z1-90]+", # gateway to other FTN domain
                "#01", "#02", "#08", "#09", "#18", "#20", # MH (bell-212)
                "!01", "!02", "!08", "!09", "!18", "!20", # MH (CCITT)
                "T[A-Xa-x][A-Xa-x]", # Answer time
                XA, XB, XC, XP, XR, XW, XX, # FREQ
                K12, ENC, CDP, SDS );

$pntnumFieldNo = 1;
$phoneFieldNo=5;
$flagFieldNo=7;

@fields = ();

# Program section

if( $ENV{FIDOCONFIG} ){
   $fidoconfig = $ENV{FIDOCONFIG};
}elsif( $ENV{fidoconfig} ){
   $fidoconfig = $ENV{fidoconfig};
}

# $DIRSEP - directory char (slash in unix and backslash in DOS-like OS
if( $fidoconfig =~ /\\/ ){
  $DIRSEP = "\\";
}else{
  $DIRSEP = "/";
}


&readconfig($fidoconfig);


open(LOG, ">>$logfiledir" . "pntstr.log") || print STDERR "Can't open log file (", $logfiledir, "pntstr.log)\n";
print LOG "\n---Starting at $curdate\n";
print LOG "Fidoconfig \"$fidoconfig\" readed\n";


($a = $address) =~ s|\d+:\d+/(\d+)|$1|;
if( $a >0 ){
  $a = sprintf "%04u", $a ;
  $PointSegmentFile =~ s/NNNN/$a/;
}elsif( $a == "0" ){
  die "Hmmmmmmm! Host with points is BAD idea!\n";
}else{
  die "\n";
}

@lt = localtime(time); $lt[5]=$lt[5]+1900; $lt[4]++;
$curdate = "$lt[3]-$lt[4]-$lt[5] $lt[2]:$lt[1]:$lt[0]";
@lt=();

@inbound = glob("$protinbound$PntStrFileMask");

for $ff ( @inbound ){
   @fields = ();
   if( $ff =~ /\.([0-9]+)/ ){
#     $pointNum = $1;
     $pointNum = "$address.$1";
     if( !open( FF, $ff) ){  print "can't open \"$ff\", skip file\n"; next; }
     print LOG "Process $ff (point number $pointNum)...\n";
     $pass = <FF>;
#     chomp($pass);
     $pass =~ s/[\n\r]$//g;  # chomp is platform-dependent
     if( !defined($password{$pointNum}) ){
       $pass = $ff . ".bad";
       print LOG "Point $pointNum not found\n",
                 "Rename $ff to $pass\n";
       print "Point $pointNum not found\n";
       rename $ff, $pass;
     }elsif( length($password{$pointNum})==0 ){
       $pass = $ff . ".bad";
       print LOG "Empty password for point $pointNum\n",
                 "Rename $ff to $pass\n";
       print "Empty password for point '$pointNum' ($password{$pointNum})\n";
       rename $ff, $pass;
     }elsif( $pass =~ /^$password{$pointNum}$/ ){
       print LOG "... $ff : password OK\n";
       $pointString = <FF>;
       chomp($pointString);
       $pointString = parsePointString($pointString);
       if( length($pointString)>0 ){
         writePointString($pointString);
         print LOG "Remove input file \"$ff\"...";
         close FF;
         unlink $ff || die "Error!\n";
         print LOG "OK\n";
       }else{
         ($bb = $ff) =~ s/...\.$pointNum$/ERR.$pointNum/;
         print LOG "Rename $ff to $bb ...";
         close FF;
         rename $ff, $bb || die "Error!\n";
         print LOG "OK\n";
       }
     }else{
       print "Error: Invalid password \"$pass\" for point \"$pointNum\"\n";
       print LOG "...Invalid password \"$pass\" for point \"$pointNum\"\n";
       ($bb = $ff) =~ s/...\.$pointNum$/SEC.$pointNum/;
       print LOG "Rename $ff to $bb ...";
       close FF;
       rename $ff, $bb || die "Error!\n";
       print LOG "OK\n";
     }
     close FF;
   }
}

print LOG "---End---\n";
close LOG;

#END

sub readconfig{
# Read husky configuration: pathnames, points passwords.

  my $config = $_[0]; # fidoconfig file name
  my $pointNo=0, $pointName="";
  my @line,$line;
  my $t, $a=1;

  open FIDOCONFIG, "$config" || die "Can't open $config: $!";

  print LOG "\nReading fidoconfig \"$config\"...";
  while( ($line = <FIDOCONFIG>) ){
    chomp($line);
    $line =~ s/\t/ /g;
    $line =~ s/ +/ /g;
    @line = split / /, $line;
#    if( $line[0] =~ /^include/i ){
#       readconfig($line[1]);
#    }
    if( $line[0] =~ /^address$/i ){
       $address = $line[1] if($a);
       $a=0;
    }elsif( $line[0] =~ /^protinbound$/i ){
       $protinbound = $line[1];
    }elsif( $line[0] =~ /^logfiledir$/i ){
       $logfiledir  = $line[1];
    }elsif( $line[0] =~ /^nodelistdir$/i ){
       $nodelistdir = $line[1];
    }elsif( $line[0] =~ /^PntStrFileMask$/i ){
       $PntStrFileMask = $line[1];
    }elsif( $line[0] =~ /^PointSegmentFile$/i ){
       $PointSegmentFile = $line[1];
#    }elsif( $line[0] =~ /^$/i ){
    }elsif( $line[0] =~ /^link$/i ){
       # Write previous item if point
       if( $pointNo ){
          $password{$pointNo} = $password;
          $pointName{$pointNo} = $pointName;
          if( !$password ){
            print LOG "\nEmpty password for point $address.$pointNo, ignored\n";
          }
       }
       # clear vars
       $pointNo = 0;
       $pointName = "";
       $password = "";
       # store new pointname
       shift @line;
       $pointName = join " ", @line;
    }elsif( $line[0] =~ /^aka$/i ){
#       if( $address && ($line[1] =~ /$address.([1-9]\d*)/) ){
#         $pointNo = $1;
       if( $address && ($line[1] =~ /$address.[1-9][0-9]*/) ){
         $pointNo = $line[1];
       }
    }elsif( !$pointNo ){
       next;
    }elsif( $line[0] =~ /^sessionpwd$/i ){
       $password = $line[1];
    }elsif( ($line[0] =~ /^password$/i) ){
       $password = $line[1] if( length($password)==0 );
    }
#    if( $line[0] =~ //i ){
#       $ = $line[1];
#    }
  }
  if( $pointNo ){
    $password{$pointNo} = $password;
    $pointName{$pointNo} = $pointName;
    if( !$password ){
      print LOG "\nEmpty password for point $address.$pointNo, ignored\n";
    }
  }
  close FIDOCONFIG;
  print LOG "OK\n";

  # Add slash (or backslash) if omitted
  $nodelistdir .= $DIRSEP if( length($nodelistdir)>0 && ($nodelistdir !~ /$DIRSEP$/) );
  $protinbound .= $DIRSEP  if( length($protinbound)>0 && ($protinbound !~ /$DIRSEP$/) );
  $logfiledir  .= $DIRSEP  if( length($logfiledir)>0 && ($logfiledir !~ /$DIRSEP$/) );

# debug output #
#for $pointNo (keys %password){
#  print "$pointNo:$password{$pointNo}:$pointName{$pointNo}\n";
#}

}


sub parsePointString{
  my $i, $ii;
  my $line = $_[0];

  # check for spaces & tabs
  if( $line =~ / / ){
     print "Error: space in line! Replaced to \"_\"\n";
     print LOG "Error: space in line! Replaced to \"_\"\n";
  }
  if( $line =~ /\t/ ){
     print "Error: tab stop in line! Replaced to \"_\"\n";
     print LOG "Error: tab stop in line! Replaced to \"_\"\n";
  }
  $line =~ s/[ \t]/_/g;

  @fields = split /,/, $line;

  if($pointNum != $fields[$pntnumFieldNo]){
    print LOG "Can't match point number: \"$fields[$pntnumFieldNo]\", not $pointNum\n";
    print "Can't match point number: \"$fields[$pntnumFieldNo]\", not $pointNum\n";
    return "";
  }

  # print point string fields (log)
  print <<FIELDS;

Point:   $fields[$pntnumFieldNo]
Station: $fields[2]
City:    $fields[3]
Sysop:   $fields[4]
Phone:   $fields[$phoneFieldNo]
Speed:   $fields[6]
FIELDS
  print "Flags:   " ;
  print "$fields[$flagFieldNo]";
  for( $i=$flagFieldNo+1; $i<=$#fields; $i++ ){ print ",$fields[$i]"; }
  print "\n\n";

  # validate "Point" (1st) field
  if( $fields[0] !~ /^Point$/ ){
    print LOG "Error: Invalid first field \"$fields[0]\", valid value is \"Point\". Process failed.\n";
    print "Error: Invalid first field \"$fields[0]\", valid value is \"Point\". Process failed.\n";
  }else{
    if( $fields[0] != "Point" ){
      $fields[0] = "Point";
      print LOG "Warning: Invalid first field \"$fields[0]\", replace to valid value \"Point\"\n";
      print  "Warning: Invalid first field \"$fields[0]\", replace to valid value \"Point\"\n";
    }
  }

  # validate phone
  if( $fields[$phoneFieldNo] =~ /^-Unpublished-$/i ){
    if( $fields[$phoneFieldNo] != "-Unpublished-" ){
     $fields[$phoneFieldNo] = "-Unpublished-";
     print LOG "Warning: Invalid \"magic\" phone number \"$fields[$phoneFieldNo]\": it's case-cencitivity, replace to valid value \"-Unpublished-\"\n";
     print "Warning: Invalid \"magic\" phone number \"$fields[$phoneFieldNo]\": it's case-cencitivity, replace to valid value \"-Unpublished-\"\n";
    }
  }elsif( $fields[$phoneFieldNo] !~ /^[0-9-]+$/i ){
     print LOG "Invalid phone number \"$fields[$phoneFieldNo]\" (only digits & dash is legal, also "-Unpublished-")\n";
     print "Invalid phone number \"$fields[$phoneFieldNo]\" (only digits & dash is legal, also "-Unpublished-")\n";
     return "";
  }
  # validate flags
  for( $i=$#fields; $i>=$flagFieldNo; $i-- ){
    for( $ii=$#validflags; $ii>=0 && $fields[$i] !~ /$validflags[$ii]/ ; $ii-- ){
       if( uc($fields[$i]) =~ /$validflags[$ii]/ ){
         $fields[$i] = uc($fields[$i]);
         print LOG "Warning: flag \"$fields[$i]\" converted to uppercase\n";
         print "Warning: flag \"$fields[$i]\" converted to uppercase\n";
       }
    }
    if( $fields[$i] !~ /$validflags[$ii]/ ){
      return "";
      print LOG "Illegal flag \"$fields[$i]\"\n";
      print "Illegal flag \"$fields[$i]\"\n";
    }
  }
  return join(",",@fields);     # return valid point string
}

sub writePointString(){
  my @fields = split /,/, $_[0];
  my @aflds = (), $tmpname;
  my $doit=1;

  if( !open(SEGMENT, "$nodelistdir$PointSegmentFile") ){
    print LOG "Can't open $PointSegmentFile ($!), abort.\n";
    die "Can't open $PointSegmentFile, abort. (See log for details.)\n";
  }
  ($tmpname = $PointSegmentFile ) =~ s/\.[\w\d_-]*$//;
  $tmpname .= ".tmp";
  if( !open(TMP, ">$tmpname") ){
    print LOG "Can't open temporary file \"$tmpname\" ($!), abort.\n";
    die "Can't open temporary file \"$tmpname\", abort. (See log for details.)\n";
  }
  print LOG "Write to $tmpname...";
  while( $line = <SEGMENT> ){
    chomp($line);
    @aflds = split /,/, $line;
    if( "$aflds[$pntnumFieldNo]" == "$fields[$pntnumFieldNo]" ){
       print TMP join(",",@fields), "\n"; # replace point string
       $doit=0;
    }else{
       print TMP "$line\n";
    }
  }
  print TMP (join(",",@fields), "\n") if($doit); # add point string

  print LOG "OK\n";
  close SEGMENT;
  close TMP;

  ($line = $PointSegmentFile ) =~ s/\.[\w\d_-]*$//;
  $line .= ".bak";
  print LOG "Backup $PointSegmentFile to $line...";
  unlink $line if( -f $line );
  rename $PointSegmentFile, $line || die "Error!\n";
  print LOG "OK\n";
  print LOG "Rename $tmpname to $PointSegmentFile...";
  rename $tmpname, $PointSegmentFile || die "Error!\n";
  print LOG "OK\n";
}
