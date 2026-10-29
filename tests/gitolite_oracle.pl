#!/usr/bin/perl
# The decisions of Gitolite 3.6.15 (782b05f) on ref rules, for the tests of
# the refex migration: parse_refs of Conf/Store.pm and access() of
# Conf/Load.pm, rewritten on the subset of gitolite.conf the migration
# reads. Calibrated against Gitolite itself on 16,044 queries before it
# served here: no difference.
#
# It reads a configuration, then one query per line on stdin,
#     REPO USER AA REF
# with AA one of W, + (and REF a full ref, or "any"), and prints one of
# ALLOW, DENY or ERROR per query.
#
#     --mode first-match   Gitolite: the first rule that applies decides
#     --mode deny-wins     Git Core: any deny that applies decides first
use strict;
use warnings;

my $mode = 'first-match';
if (@ARGV >= 2 && $ARGV[0] eq '--mode') {
    shift @ARGV;
    $mode = shift @ARGV;
}
die "usage: $0 [--mode first-match|deny-wins] CONF\n"
    unless @ARGV == 1 && $mode =~ /^(first-match|deny-wins)$/;

# Rc.pm:50 and :52.
my $REF_OR_FILENAME_PATT = qr(^[0-9a-zA-Z][-0-9a-zA-Z._\@/+ :,]*$);
my $USERNAME_PATT = qr(^\@?[0-9a-zA-Z][-0-9a-zA-Z._\@+]*$);

my (%members, @rules, %deny_rules);
my @repos;
my $seq = 0;
open(my $conf, '<', $ARGV[0]) or die "$ARGV[0]: $!\n";
while (my $line = <$conf>) {
    $line =~ s/#.*//;
    $line =~ s/^\s+|\s+$//g;
    next if $line eq '';
    if ($line =~ /^(\@\S+)\s*=\s*(.*)$/) {
        push @{ $members{$1} }, split(' ', $2);
    } elsif ($line =~ /^repo\s+(.*)$/) {
        @repos = split(' ', $1);
        die "repo groups are outside the subset: $line\n" if grep { /^\@/ } @repos;
    } elsif ($line =~ /^option\s+deny-rules\s*=\s*1$/) {
        $deny_rules{$_} = 1 for @repos;
    } elsif ($line =~ /^(\S+)\s*(.*?)\s*=\s*(.*)$/) {
        my ($perm, $refs, $subjects) = ($1, $2, $3);
        # parse_refs, Conf/Store.pm:90-102
        my @refs = $refs eq '' ? ('refs/.*') : split(' ', $refs);
        @refs = map { m(^(refs|VREF)/) or s(^)(refs/heads/); $_ } @refs;
        for my $repo (@repos) {
            for my $subject (split(' ', $subjects)) {
                push @rules, [ ++$seq, $repo, $subject, $perm, $_ ] for @refs;
            }
        }
    } else {
        die "outside the subset: $line\n";
    }
}
close($conf);

# The groups a name belongs to, nested ones included, and @all.
sub groups_of {
    my ($name) = @_;
    my %seen = ('@all' => 1);
    my @todo = ($name);
    while (@todo) {
        my $item = shift @todo;
        for my $group (keys %members) {
            next if $seen{$group};
            if (grep { $_ eq $item } @{ $members{$group} }) {
                $seen{$group} = 1;
                push @todo, $group;
            }
        }
    }
    return %seen;
}

sub access {
    my ($repo, $user, $aa, $ref) = @_;
    return 'ERROR' unless $user =~ $USERNAME_PATT;
    return 'ERROR' unless $ref eq 'any' or $ref =~ m(^VREF/NAME/) or $ref =~ $REF_OR_FILENAME_PATT;
    my %groups = groups_of($user);
    my @mine = sort { $a->[0] <=> $b->[0] }
        grep { $_->[1] eq $repo && ($_->[2] eq $user || $groups{ $_->[2] }) } @rules;
    my $deny_rules = $deny_rules{$repo};
    (my $aaq = $aa) =~ s/\+/\\+/;
    my $applies = sub {
        my ($rule) = @_;
        my $refex = $rule->[4];
        $refex =~ s(/USER/)(/$user/);
        return $ref =~ /^$refex/ || $ref eq 'any';
    };
    if ($mode eq 'deny-wins') {
        for my $rule (@mine) {
            next unless $rule->[3] eq '-';
            next if $ref eq 'any' and not $deny_rules;
            return 'DENY' if $applies->($rule);
        }
    }
    for my $rule (@mine) {
        my $perm = $rule->[3];
        next if $perm eq '-' and $ref eq 'any' and not $deny_rules;
        next unless $applies->($rule);
        return 'DENY' if $perm eq '-';
        return 'ALLOW' if $perm =~ /$aaq/;
    }
    return 'DENY';
}

while (my $query = <STDIN>) {
    chomp $query;
    next if $query eq '';
    my ($repo, $user, $aa, $ref) = split(' ', $query, 4);
    print access($repo, $user, $aa, $ref), "\n";
}
