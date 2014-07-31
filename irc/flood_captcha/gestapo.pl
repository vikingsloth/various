#!/usr/bin/perl

use strict;
use Net::IRC;
use Digest::MD5 "md5_base64";
use DBI;
use URI::Escape;
use Data::Dumper;

my $server_host = 'irc.example.coom';
my $server_name = 'irc.example.com';
my $oper_nick   = 'opernick';
my $oper_pass   = 'operpass';
my $oper_chan   = '#opers';

my $db_host     = 'localhost';
my $db_name     = 'gestapo';
my $db_user     = 'gestapo';
my $db_pass     = 'mysqlpass';

my @exclude_hosts = (
  "htols.net",
  "operhost.com"
);

my $dc_trigger  = 2;
my $dc_falloff  = 2;    # Every X seconds defcon--

my ($users, $auth_keys, $conn_rate, $last_update, $defcon);

my $captcha_all = 0;
my $ircd_reconn = 0;

my $irc     = new Net::IRC;
my $ircconn = $irc->newconn(Nick     => 'gestapo',
                            Username => 'gestapo',
                            Server   => $server_host,
                            Port     =>  6667,
                            Ircname  => 'Sicherheitspolizei');

my $dbh = DBI->connect("DBI:mysql:$db_name:$db_host", $db_user, $db_pass)
  or die "Error: couldn't connect to mysql: " . DBI->errstr;

$dbh->do("DELETE FROM captcha");

$ircconn->add_global_handler('376', \&on_connect);

print " [+] " . time . "Connecting to $server_host:6667...\n";
$irc->start;

sub main_loop {
  my $conn = shift;

  while(1) {
    adjust_rate($conn);
    check_auth($conn);
    $irc->do_one_loop();
  }
}

sub adjust_rate {
  my $conn = shift;

  if($ircd_reconn > 0) {
    $ircd_reconn--;
  }

  if(!$last_update || (time - $last_update) > $dc_falloff) {
    $last_update = time;

    if($defcon > 0) {
      $defcon--;
    }

  }

}

sub on_connect {
  my ($conn, $event) = @_;

  print " [+] Connected\n";
  $conn->oper($oper_nick, $oper_pass);
  $conn->add_handler('notice', \&on_notice);
  $conn->add_handler('public', \&on_public);

  main_loop($conn);
}

sub on_notice {
  my ($conn, $event) = @_;

print "from: $event->{from}\n";
    my $text = join(' ', @{$event->{args}});
print "text: $text\n";
  # If the notice comes from the server and not another user
  if (($event->{from} =~ /^$server_name$/) && ($event->{user} =~ /^$/)) {

    my $text = join(' ', @{$event->{args}});
print "text: $text\n";

    # start timer on reconnect to ignore split rejoined users
    if ($text =~ /^\(.link.\) .* link (.*) -> (.*)\[/) {
      $ircd_reconn = 5;
      $conn->privmsg($oper_chan, "Network reconnect: $1 <-> $2. Delaying captchas");
    }

    elsif ($text =~ /^\*\*\* Global -- from (.*): No response from (.*)\[/) {
      $ircd_reconn = 10;
      $conn->privmsg($oper_chan, "Split detected: $1 <-> $2. Delaying captchas");
    }

    # antirandom increases defcon
    elsif ($text =~ /^\*\*\* Notice -- \[antirandom\] denied access/) {
      $defcon++;
    }

    # Find clients connecting/exiting
    # *** Notice -- Client connecting on port 6667: klulz_ (klulz@ww88.org)
    # *** Notice -- Client exiting: klulz_ (klulz@ww88.org)
    elsif (my ($type, $nick, $ident, $hostname, $host ) = ($text =~ /^\*\*\* REMOTE.*: Client (\S+) at .*: (\S+)!(\S+)@(\S+)\((\S+)\) .*/)) {
      print " [-] $type: $nick $ident\@$hostname $host\n";

      if ($type =~ /^connecting$/) {

        # XXX do reputation check

        $defcon++;

        $dbh->do("INSERT INTO connections (nick,host,ident) VALUES (" .
                 $dbh->quote($nick) . "," .
                 $dbh->quote($host) . "," .
                 $dbh->quote($ident) . ");");

        my $key = md5_base64($nick . $host . time);

        $users->{$nick} = {
                            'nick'      => $nick,
                            'connected' => time,
                            'ident'     => $ident,
                            'host'      => $host,
                            'key'       => $key
                          };

        # Reverse defcon scoring
        if(($defcon > $dc_trigger || $captcha_all) && !$ircd_reconn &&
            !grep(/^$host$/, @exclude_hosts)) {

          $conn->privmsg($oper_chan, "JUDEN RAUS -> $nick ($ident\@$host) " .
                                     "[$defcon]");

          $conn->notice($nick, "HALT! You've been selected for additional " .
                               "screening. Until you solve the captcha, you " .
                               "will be unable to use this network.");
          $conn->notice($nick, "http://irc.ww88.org/gestapo?key=" .
                               uri_escape($users->{$nick}->{"key"}));

          $conn->sl("TEMPSHUN $nick Gestapo waiting for captcha");

          $dbh->do("INSERT INTO captcha (user_key) VALUES (" .
                 $dbh->quote($users->{$nick}->{"key"}) . ");");

          print " [+] " . time . "CAPTCHA: $nick ($ident\@$host) $key\n";

          $auth_keys->{$users->{$nick}->{"key"}} = $nick;

        }

      }
      elsif ($type =~ /^exiting$/) {

        delete($users->{$nick});

        if($auth_keys->{$users->{$nick}->{key}}) {
          delete($auth_keys->{$users->{$nick}->{key}});
        }

      }

    }

  }

}

sub on_public {
  my ($conn, $event) = @_;

  my $text = join(' ', @{$event->{args}});
print "public: $text\n";

  if(grep(/^$oper_chan$/, @{ $event->{"to"} })) {
     if($event->{"nick"} =~ /^bopm/) {
       $defcon++;
     }

     if($text =~ /^gestapo on$/i) {
       $conn->privmsg($oper_chan, "gestapo default action: ON");
       $captcha_all = 1;
     }
     elsif ($text =~ /^gestapo off$/i) {
       $conn->privmsg($oper_chan, "gestapo default action: OFF");
       $defcon      = 0;
       $captcha_all = 0;
     }

  }
}

sub check_auth {
  my $conn = shift;

  my $qh = $dbh->prepare("SELECT * FROM captcha WHERE completed!=0");

  $qh->execute();

  while(my $res = $qh->fetchrow_hashref()) {
    my $user_key = $res->{"user_key"};
    my $nick     = $auth_keys->{$user_key};

    print "Access Granted: $nick $user_key\n";

    $conn->notice($nick, "Access granted");
    $conn->sl("TEMPSHUN -$nick");

    my $query = "DELETE FROM captcha WHERE user_key=" . $dbh->quote($user_key);
    print "query = $query\n";

    $dbh->do($query);
  }
}

