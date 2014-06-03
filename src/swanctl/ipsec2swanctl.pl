#!/usr/bin/perl -w

my $etc = "/etc";
my $debug = 3;
my $tab = "\t";
my $min_connection_name = 4;

my %debug_level =
(
   'MIN'            => 0,
   'ERROR'          => 1,
   'WARN'           => 2,
   'INFO'           => 3,
   'DEBUG'          => 4,
);

my %any_ike_sa =
(
    'keyexchange'   => 'version',
    'left'          => 'local_addrs',
    'right'         => 'remote_addrs',
    'leftikeport'   => 'local_port',
    'rightikeport'  => 'remote_port',
    'ike'           => 'proposals',
    'leftsourceip'  => 'vips',
    'aggressive'    => 'aggressive',
    'modeconfig'    => 'pull',
    'forceencaps'   => 'encap',
    'mobike'        => 'mobike',
    'dpddelay'      => 'dpd_delay',
    'dpdtimeout'    => 'dpd_timeout',
    'fragmentation' => 'fragmentation',
    'rightsendcert' => 'send_certreq',
    'leftsendcert'  => 'send_cert',
    'keyingtries'   => 'keyingtries',
    'uniqueids'     => 'unique',
    'ikelifetime'   => 'reauth_time',
#    'ikelifetime'   => 'rekey_time',
    'rekeymargin'   => 'over_time',
    'rekeyfuzz'     => 'rand_time',
);

my %child_sa =
(
    'ah'            => 'ah_proposals',
    'esp'           => 'esp_proposals',
    'leftsubnet'    => 'local_ts',
    'rightsubnet'   => 'remote_ts',
    'leftprotoport' => 'local_ts',
    'rightprotoport'=> 'remote_ts',
    'leftupdown'    => 'update',
    'lefthostaccess'=> 'hostaccess',
    'type'          => 'mode',
    'dpdaction'     => 'dpd_action',
    'compress'      => 'ipcomp',
    'inactivity'    => 'inactivity',
    'reqid'         => 'reqid',
    'mark'          => 'mark_in',
    'mark_in'       => 'mark_in',
    'mark_out'      => 'mark_out',
    'tfc'           => 'tfc_padding',
    'margintime'    => 'rekey_time',
    'lifetime'      => 'life_time',
    'rekeyfuzz'     => 'rand_time',
    'marginpackets' => 'rekey_packets',
    'lifepackets'   => 'life_packets',
    'rekeyfuzz'     => 'rand_packets',
    'marginbytes'   => 'rekey_bytes',
    'lifebytes'     => 'life_bytes',
    'auto'          => 'start_action',
);

my %local =
(
    'leftcert'      => 'certs',
    'leftca'        => 'cacerts',
    'leftcacert'    => 'cacerts',
    'leftauth'      => 'auth',
    'leftid'        => 'id',
    'eap_identity'  => 'eap_id',
    'aaa_identity'  => 'aaa_id',
    'xauth_identity'=> 'xauth_id',
    'rightgroups'   => 'groups',
    'strictcrlpolicy'=> 'revocation',
);

my %remote =
(
    'rightcert'     => 'certs',
    'rightca'       => 'cacerts',
    'rightcacert'   => 'cacerts',
    'rightauth'     => 'auth',
    'rightid'       => 'id',
    'eap_identity'  => 'eap_id',
    'aaa_identity'  => 'aaa_id',
    'xauth_identity'=> 'xauth_id',
    'rightgroups'   => 'groups',
    'strictcrlpolicy'=> 'revocation',
);

my %cert_dirs =
(
    'certs'         => 'x509',
    'cacerts'       => 'x509ca',
    'aacerts'       => 'x509aa',
    'crls'          => 'x509crl',
    'acerts'        => 'x509ac',
);

my %ipsec_rename =
(
    'ipsec.d'       => 'swanctl',
    'ipsec.conf'    => 'swanctl.conf',
#    'ipsec.secrets' => 'swanctl.conf',
);

sub cmd
{
   my $shell_cmd = $_[0];

   my $shell_out = `$shell_cmd`;

   if ( $? != 0 )
     {
     if ( $debug > $debug_level{ 'WARN' } )
       {
       print "WARN: EXEC $shell_cmd\n";
       print "WARN: cmd returned with code $?";
       }
     }
   elsif ( $debug > $debug_level{ 'DEBUG' } )
       {
       print "DEBUG: EXEC: $shell_cmd\n";
       }

   return $shell_out;
}

sub copy_ipsec_d
{
   my $ipsec_dir = "$etc/ipsec.d";

   if ( $debug > $debug_level{ 'INFO' } )
     { print "INFO: creating $etc/swanctl from $ipsec_dir\n"; }

   if ( ! -d $ipsec_dir ) { die ( "Cannot locate $ipsec_dir cert directory !" ); }

   &cmd( "mkdir -p $etc/swanctl" );

   &cmd( "cp -pR $etc/ipsec.d/* $etc/swanctl/" );

   foreach my $dir ( keys %cert_dirs )
      {
      &cmd( "mv $etc/swanctl/$dir $etc/swanctl/$cert_dirs{ $dir }" );
      }

   &cmd( "mkdir $etc/swanctl/rsa" );
   &cmd( "mkdir $etc/swanctl/ecdsa" );
   &cmd( "mkdir $etc/swanctl/pkcs8" );

   &cmd( "mv -v $etc/swanctl/private/*.der $etc/swanctl/ecdsa" );
   &cmd( "mv -v $etc/swanctl/private/*.rsa $etc/swanctl/rsa" );
   &cmd( "mv -v $etc/swanctl/private/* $etc/swanctl/pkcs8" );

   &cmd( "rmdir $etc/swanctl/private" );
}

my @connections = ();

my %conn_values = ();

my %conn_order = ();

my %conn_remark = ();

my %conn_deps = ();

my %leftright_groups = ();

my %also_list = ();

my @ipsec_conf = ();

sub any_ike_sa_count
{
  my ( $val ) = ( @_ );
  my $count = 0;

  foreach my $k ( keys %$val )
    {
    if ( defined( $any_ike_sa{ $k } ) )
      { $count++; }
    }
  return $count;
}

sub get_leftright_key
{
  my ( $vals ) = ( @_ );

  if ( defined $$vals{ 'left' } && defined $$vals{ 'right' } )
    {
    return $$vals{ 'left' }.'-'.$$vals{ 'right' };
    }
  return undef
}

sub push_leftright_group
{
  my ( $conn_name, $left, $right, $vals ) = ( @_ );

  $leftright = "$left-$right";
  my $group = [];

  if ( defined( $leftright_groups{ $leftright } ) )
    {
    $group = $leftright_groups{ $leftright };
    }

  push @$group, $conn_name;

  $leftright_groups{ $leftright } = $group;
}

sub parse_ipsec_conf
{
  my $conn_name = undef;
  my $comments = [];
  my $vals = {};
  my $order = [];
  my $also = [];
  my $any_ike_sa_count = 0;
  my $left = undef;
  my $right = undef;
  my $ipsec_file = "$etc/ipsec.conf";

  if ( $debug > $debug_level{ 'INFO' } )
    { print "INFO: parsing $ipsec_file\n"; }

  open( IPSEC_FILE, "< $ipsec_file" ) || die "Could not open $ipsec_file: $!\n";
  @ipsec_conf = <IPSEC_FILE>;

  close( IPSEC_FILE );

   foreach my $l ( 0..$#ipsec_conf )
     {
     my $line = $ipsec_conf[ $l ];

     if ( $line =~ /^\s*conn\s+(.+)/ ||
          $line =~ /^\s*config\s+(.+)/ )
       {
       if ( defined ( $conn_name ) )
         {
         push @connections, $conn_name;
         $conn_values{ $conn_name } = $vals;
         $conn_order{ $conn_name } = $order;

         if ( defined( $left ) && defined( $right ) )
           {
           &push_leftright_group( $conn_name, $left, $right, $vals );
           undef $left;
           undef $right;
           }

         if ( 0 < scalar( @$also ) )
           {
           $conn_deps{ $conn_name } = $also;
           $also = [];
           }

         $vals = {};
         $order = [];
         }

       $conn_name = $1;

       if ( @$comments )
          {
          $conn_remark{ $conn_name } = $comments;
          $comments = [];
          }
       }
     elsif ( $line =~ /^\s*(#.+)/ )
       {
       push @$comments, $1;
       }
     elsif ( $line =~ /^\s*$/ )
       {
       push @$comments, "";
       }
     elsif ( $line =~ /^\s*(\w+)\s*=\s*(.+)$/ )
       {
       if ( @$comments )
         {
         push @$order, @$comments;
         $comments = [];
         }
       my $key = $1;
       my $val = $2; # note this may include value and comments !
       my $value = $val;

       # sanitize remarks out of value for post-processing:
       if ( $val =~ /^(\S+)\s*#.*/ )
         { $value = $1; }

       if ( $key eq 'also' )
         {
         $also_list{ $value }++;
         push @$also, $value;
         next;
         }
       elsif ( $key eq "right" )
         { $right = $value; }
       elsif ( $key eq "left" )
         { $left = $value; }

       push @$order, $key;
       $$vals{ $key } = $val;
      }
   }

  if ( defined ( $conn_name ) )
    {
    push @connections, $conn_name;
    $conn_values{ $conn_name } = $vals;
    $conn_order{ $conn_name } = $order;

    if ( defined( $left ) && defined( $right ) )
      { &push_leftright_group( $conn_name, $left, $right, $vals ); }
    }
}

sub dump_ipsec_conf
{
  foreach my $conn ( @connections )
    {
    if ( defined $conn_remark{ $conn } )
      {
      my $remark = $conn_remark{ $conn };

      foreach my $l ( @$remark )
        {
        print $l."\n";
        }
      }

    print "conn $conn\n";
    my $order = $conn_order{ $conn };
    my $vals  = $conn_values{ $conn };

    foreach my $l ( @$order )
      {
      if ( $l eq "" || '#' eq substr( $l, 0, 1 ) )
        {
        print $l."\n";
        }
      else
        {
        print $l."=".$$vals{ $l }."\n";
        }
      }
    }
}

sub process_dependencies
{
  my @new_conn = ();

  my $default = undef;

  if ( defined( $conn_order{ '%default' } ) )
    { $default = $conn_order{ '%default' }; }

  foreach my $conn ( @connections )
    {
    my $exclude = 0;

    # exclude the "setup" and "conn %default" from getting converted:
    if ( $conn eq "setup" ||
         $conn eq "%default" )
      {
      if ( $debug > $debug_level{ 'DEBUG' } )
        { print "DEBUG: excluding conn $conn\n"; }
      $exclude = 1;
      }
    # Check if any "also" referenced conn are valid
    elsif ( defined( $also_list{ $conn } ) )
      {
      $exclude = 1;

      my $vals  = $conn_values{ $conn };

      # Look for a "left" and "right" keyword
      if ( defined( &get_leftright_key( $vals ) ) )
        {
        $exclude = 0;
        }
      }
    # check if a conn has "also" references, add the "also" ordered
    # set of values to conn's ordered set of values
    else
      {
      if ( defined( $conn_order{ $conn } ) )
        {
        my $order = [];
        push @$order, @{$conn_order{ $conn }};

        if ( defined $conn_deps{ $conn } )
          {
          foreach my $also ( @{ $conn_deps{ $conn } } )
            {
            if ( defined( $conn_order{ $also } ) )
              {
              push @$order, @{ $conn_order{ $also } };
              }
            }
          }

        if ( defined( $default ) )
          { push @$order, @{ $default }; }

        $conn_order{ $conn } = $order;

        if ( $debug > $debug_level{ 'DEBUG' } )
          {
          print "DEBUG: new_order $conn\n";
          foreach my $o( @$order )
            { print "DEBUG: $o\n"; }
          }
        }
      }

    if ( ! $exclude )
        { push @new_conn, $conn; }
    elsif ( $debug > $debug_level{ 'DEBUG' } )
        { print "DEBUG: excluding conn $conn\n"; }
    }

  @connections = @new_conn;
}

sub get_conn_values
{
  my ( $conn_name, $default ) = ( @_ );
  my %conn_union_vals = %$default;
  my $conn_vals = $conn_values{ $conn_name };

  # Overlay also dependant values
  if ( defined $conn_deps{ $conn_name } )
    {
    foreach my $also ( @{ $conn_deps{ $conn_name } } )
      {
      my $also_vals = &get_conn_values( $also, $default );
      @conn_union_vals{ keys %$also_vals } = values %$also_vals;
      }
    }

  # Overlay the specific conn values
  @conn_union_vals{ keys %$conn_vals } = values %$conn_vals;

  # add id:
  $conn_union_vals{ 'CONNECTION_NAME' } = $conn_name;

  # fix some obsolete variable values
  foreach my $direction ( 'left', 'right' )
    {
    if ( defined( $conn_union_vals{ $direction.'protoport' } ) &&
         defined( $conn_union_vals{ $direction } ) )
      {

      if ( defined( $conn_union_vals{ $direction.'subnet' } ) )
        {
        print "ERROR: cannot convert ".$direction.'protoport because  '.$direction.'subnet already exists\n';
        }

      my $val = $conn_union_vals{ $direction.'protoport' };
      my $host = $conn_union_vals{ $direction };
      my $remark = "";

      # first sanitize for comment
      if ( $val =~ /^([^#]+)(#.*)/ )
        {
        $remark = $2;
        my $val_space = $1;

        if ( $val_space =~ /^(\S+)(\s*)/ )
          {
          $remark = $2.$remark;
          $val = $1;
          }
        }
      # set {left,right}protoport equal to the {left,right}subnet format
      $conn_union_vals{ $direction.'protoport' } = $host.'['.$val.']'.$remark;
      }
   }

 if ( $debug > $debug_level{ 'DEBUG' } )
    {
    print "DEBUG: GET_CONN_VALUES ".$conn_union_vals{ 'CONNECTION_NAME' }."\n";

    foreach my $k ( keys %conn_union_vals )
      {
      print "DEBUG: ".$k." = ".$conn_union_vals{ $k }."\n";
      }
  }

  return \%conn_union_vals;
}

sub output_section
{
  my ( $SWANCTL, $conn_vals, $section_keys, $indent, $info, $conn_child ) = ( @_ );

  my $conn_name = $$conn_vals{ 'CONNECTION_NAME' };
  my $order = $conn_order{ $conn_name };
  if ( $debug > $debug_level{ 'DEBUG' } )
    { print "DEBUG: output_section $conn_name\n"; }
  for( my $o = 0; $o < $#$order; $o++ )
    {
    my $oldkey = $$order[ $o ];
    if ( $debug > $debug_level{ 'DEBUG' } )
      { print "DEBUG: $conn_name $oldkey\n"; }
    next if ( ! defined( $$conn_vals{ $oldkey } ) );
    next if ( ! defined( $$section_keys{ $oldkey } ) );
    my $newkey = $$section_keys{ $oldkey };

    if ( $info ne "" )
      {
      print $SWANCTL $indent.$info."\n";
      # only output this info section once
      $info = "";
      }
    # check if there were comments associated with this key/value:
    my $p = $o;
    $o--;
    while( $o >= 0 && substr( $$order[ $o ], 0, 1 ) eq "#" )
      { $o--; }
    $o++;
    for(; $o < $p; $o++ )
      {
      print $SWANCTL $indent.$$order[ $o ]."\n";
      }

    # write out the $newkey = $value.
    my $value = $$conn_vals{ $oldkey };
    delete $$conn_vals{ $oldkey };
    print $SWANCTL $indent.$newkey." = ".$value."\n";

    next if ( ! defined( $conn_child ) || ref( $conn_child ) ne 'ARRAY' );

    # loop through all the children. For any values *not* the same leave a WARN comment
    foreach my $child_vals ( @$conn_child )
      {
      next if ( ! defined ( $$child_vals{ $oldkey } ) );
      my $child_val = $$child_vals{ $oldkey };
      delete $$child_vals{ $oldkey };

      # sanitize remarks out for comparison
      if ( $value =~ /^(\S+)\s*#.*/ )
        { $value = $1; }
      if ( $child_val =~ /^(\S+)\s*#.*/ )
        { $child_val = $1; }

      if ( $debug > $debug_level{ 'DEBUG' } )
        { print "DEBUG: $conn_name compare $value eq $child_val\n"; }

      if ( $child_val ne $value )
        {
        print $SWANCTL $indent."# WARN ".$$child_vals{ 'CONNECTION_NAME' }." ".$newkey." = ".$value."\n";
        }
      }
   }

  # loop through all the children. For any values that weren't in the
  # main conn add them with an INFO comment
  foreach my $child_vals ( @$conn_child )
    {
    &output_section( $SWANCTL, $child_vals, $section_keys, $indent, "# INFO: from conn ".$$child_vals{ 'CONNECTION_NAME' } );
    }

  return;
}

sub output_block
{
  my ( $SWANCTL, $conn_vals, $section_keys, $indent, $block, $conn_child ) = ( @_ );

  if ( $debug > $debug_level{ 'DEBUG' } )
    { print "DEBUG: output_block $block\n"; }

  print $SWANCTL "\n";
  print $SWANCTL $indent.$block." {\n";

  &output_section( $SWANCTL, $conn_vals, $section_keys, $indent.$tab, "", $conn_child );

  print $SWANCTL $indent."}\n";
}

sub output_swanctl_conf
{
  my $swanctl_file = "$etc/swanctl/swanctl.conf";

  if ( $debug > $debug_level{ 'INFO' } )
    { print "INFO: output $swanctl_file\n"; }

  open( my $SWANCTL, "> $swanctl_file" ) || die ( "ERROR: could not open $swanctl_file: $!\n" );

  my @indent = ( "" );
  print $SWANCTL $indent[0]."connections {\n";

  my $default = {};

  if ( defined( $conn_values{ '%default' } ) )
    { $default = $conn_values{ '%default' }; }

  # We want to quasi follow the ordered structure of the original ipsec.conf,
  # in that we will write the swanctl.conf connections based on $leftright pairs
  # as they appeared in the ipsec.conf
  foreach my $conn ( @connections )
    {
    my @name_chars = split( //, $conn );
    my $name_len   = $#name_chars;
    my $conn_vals  = &get_conn_values( $conn, $default );
    my @conn_child = ();

    my $leftright = &get_leftright_key( $conn_vals );

    next if ( ! defined( $leftright ) );
    next if ( ! defined( $leftright_groups{ $leftright } ) );

    my $conn_count = &any_ike_sa_count( $conn_vals );

    # figure out which of the connections that share the same $leftright key
    # should be considered the master because it has the most values:
    foreach my $child ( @{ $leftright_groups{ $leftright } } )
      {
      next if ( $child eq $conn );

      my $child_vals  = &get_conn_values( $child, $default );
      my $child_count = &any_ike_sa_count( $child_vals );

      # Figure out the name for the connection - hopefully there is commonality !
      my @child_name = split( //, $child );
      my $name_len   = $name_len > $#child_name ? $#child_name : $name_len;
      foreach my $i ( 0 .. $name_len )
        {
        if ( $name_chars[ $i ] ne $child_name[ $i ] )
          {
          $name_len = $i;
          last;
          }
        }

      if ( $child_count > $conn_count )
        {
        push @conn_child, $conn_vals;
        $conn_vals  = $child_vals;
        $conn_count = $child_count;
        $conn       = $child;
        @name_chars = @child_name;
        }
      else
        {
        push @conn_child, $child_vals;
        }
      }

    # at this point, we should have the "master" to use for the $leftright conn
    delete $leftright_groups{ $leftright };

    # name to use: check min, length, sanitize any "_-" ending chars
    my $conn_name = $conn;

    foreach my $char ( [ '-', '_' ] )
      {
      my $len = index( $conn_name, '-' );
      if ( $len >= $min_connection_name && $len < $name_len )
        { $name_len = $len; }
      }

    if ( $name_len >= $min_connection_name )
      { $conn_name = substr( $conn, 0, $name_len ); }

    if ( $debug > $debug_level{ 'DEBUG' } )
      { print "DEBUG: connection name = $conn_name\n"; }

    # Done processing. Now write to swanctl.conf
    unshift @indent, $indent[0].$tab;

    if ( defined $conn_remark{ $conn } )
      {
      my $remark = $conn_remark{ $conn };

      foreach my $l ( @$remark )
        {
        print $SWANCTL $indent[0].$l."\n";
        }
      }

    # conn block
    print $SWANCTL $indent[0].$conn_name." {\n";
    unshift @indent, $indent[0].$tab;

    &output_section( $SWANCTL, $conn_vals, \%any_ike_sa, $indent[0], "", \@conn_child );

    # local block
    &output_block( $SWANCTL, $conn_vals, \%local, $indent[0], "local", \@conn_child );

    # remote block
    &output_block( $SWANCTL, $conn_vals, \%remote, $indent[0], "remote", \@conn_child );

    # add the master $conn_vals to $conn_child so simple iteration
    # for remaining of output
    unshift @conn_child, $conn_vals;

    # children block
    print $SWANCTL "\n";
    print $SWANCTL $indent[0]."children {";
    unshift @indent, $indent[0].$tab;
    foreach my $children ( @conn_child )
      {
      &output_block( $SWANCTL, $children, \%child_sa, $indent[0], $$children{ 'CONNECTION_NAME' } );
      }

    shift @indent;
    print $SWANCTL $indent[0]."}\n";

    # WARN about any remaining variables that haven't been mapped
    unshift @indent, $indent[0]."# ";
    foreach my $remain ( @conn_child )
      {
      my %remain_keys = map{ $_ => $_ } keys %$remain;

      &output_section( $SWANCTL, $remain, \%remain_keys, $indent[0], "WARN: nomap ".$$remain{ 'CONNECTION_NAME' } );
      }
    # remove just add "# "
    shift @indent;

    shift @indent;
    print $SWANCTL $indent[0]."}\n";
    shift @indent;
    }

  print $SWANCTL $indent[0]."} # connections\n";

  my $secrets_file = "$etc/ipsec.secrets";

  if ( -f $secrets_file )
    {
    if ( $debug > $debug_level{ 'INFO' } )
      { print "INFO: processing $secrets_file\n"; }

    print $SWANCTL "\n";
    print $SWANCTL "secrets {\n";
    print $SWANCTL $tab."eap {\n";
    print $SWANCTL $tab."}\n";
    print $SWANCTL $tab."ike {\n";
    print $SWANCTL $tab."}\n";
    print $SWANCTL "} # secrets\n";
    }

  close( $SWANCTL );
}

sub print_usage
{
  print <<END;
USAGE: ipsec2swanctl.pl - converts a strongswan pre-5.2.0 configuration to
USAGE:   the new format. Takes the path the configuration directory, usually
USAGE:   /etc, converts the ipsec.conf, ipsec.secrets to swanctl.conf,
USAGE:   and creates a swanctl directory from the ipsec.d cert directory.
USAGE:   All the original configuration and directories are read-only.
USAGE:
USAGE: ./ipsec2swanctl.pl [etc_dir] [debug_level] [tab] [min_conn_name_len]
USAGE:   [etc_dir] - optional directory containing pre-5.2.0 configuration
USAGE:               defaults to /etc
USAGE:   [debug_level] - optional debug level of ERROR, WARN, INFO, DEBUG.
USAGE:                   defaults to WARN.
USAGE:   [tab] - optional tab character, defaults to tab "\t" charactor
USAGE:   [min_conn_name_len] - when attempting to calculate simplified
USAGE:     connection name, minimum length of new name. If less than that
USAGE:
USAGE: For example:
USAGE: ./ipsec2swanctl.pl ./etc DEBUG "   " 10

END
   exit(1);
}

sub parse_cmd_line
{
  if ( defined( $ARGV[ 0 ] ) )
     {
     $etc = $ARGV[ 0 ];
     }

  if ( $etc =~ /^-*he?l?p?/i )
    {
    &print_usage();
    }
  elsif ( ! -d "$etc" )
    {
    print "ERROR: $etc is not valid\n";
    &print_usage();
    }

  if ( defined( $ARGV[ 1 ] ) )
     {
     my $level = $ARGV[ 1 ];
     if ( ! defined( $debug_level{ $level } ) )
       {
       print "ERROR: valid debug values are ERROR, WARN, INFO, DEBUG\n";
       &print_usage();
       }
     $debug = $debug_level{ $level };
     # Require at least WARN level:
     if ( $debug < $debug_level{ 'WARN' } )
        { $debug = $debug_level{ 'WARN' }; }
     }
  $debug++;

  if ( defined( $ARGV[ 2 ] ) )
     {
     my $tab = $ARGV[ 2 ];
     }

  if ( defined( $ARGV[ 3 ] ) )
     {
     my $min_connection_name = $ARGV[ 3 ];
     }
}

sub main
{
  &parse_cmd_line();

  &copy_ipsec_d();

  &parse_ipsec_conf();

  if ( $debug > $debug_level{ 'DEBUG' } )
    { &dump_ipsec_conf(); }

  &process_dependencies();

  &output_swanctl_conf();
}

&main();
