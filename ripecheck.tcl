#
# ripecheck.tcl  Version: 3.2.3-dev  Author: Stefan Wold <ratler@stderr.eu>
###
# Info:
# This script check unresolved ip addresses against a RIPE database
# and ban the user if the country match your configured top domains.
# Features:
# * Configuration through dcc console
# * Per channel settings
# * Can handle top domain banning for name based hosts
# * Custom bantime
# * Support extra resolving for domains like info, com, net, org
#   to find hosts that actually have an ip from a country
#   you wish to ban.
# * Customizable ban messages with simple keyword support, see .help ripeconfig
# * Builtin help pages, see .help ripecheck or .help
# * !ripeinfo <host> to get verbose information from whois about the <host>
# * !ripeinfo and !ripecheck are available as public commands and through private
#   /msg to the bot (if enabled)
# * Ban counter, number of times ripecheck have banned someone in the channel
# * !ripestatus show settings and bancount stats for the channel
# * Whitelist mode. Only let hosts from a country specified by the TLD list
#   enter the channel, everyone else get banned.
###
# Require / Depends:
# tcllib >= 1.8  (http://www.tcl.tk/software/tcllib/)
###
# Usage:
# Load the script and change the topdomains you
# wish to ban.
#
# testripecheck <channel> <host>
# Test host or ip from dcc console with your current settings
#
# chanset <channel> <+/->ripecheck
# This will either enable (+) or disable (-) the script for the
# specified channel
#
# chanset <channel> ripecheck.bantime <number>
# For how long should the ban be active in minutes
#
# chanset <channel> <+/->ripecheck.topchk
# Enable (+) or disable (-) top domain resolve check
#
# chanset <channel> <+/->ripecheck.topban
# Enable (+) or disable (-) top domain banning based on
# the topdomain list
#
# chanset <channel> <+/->ripecheck.pubcmd
# Enable (+) or disable (-) public commands (!ripecheck)
#
# chanset <channel> <+/->ripecheck.whitelist
# Enable (+) or disable (-) whitelist mode
# The whitelist mode reverse the ripecheck behavior when matching
# a country against the topdomain list. Instead of banning a country that
# exist in the topdomain list it will let that host enter the channel and ban
# everyone else.
#
# +ripetopresolv <channel> <topdomain|*>
# Add a top domain or regexp pattern that you want to resolve for
# further ripe checking. It's possible that domains like com, info, org
# could be from a country that is banned in the top domain list.
# Example (match .com): .+ripetopresolv #channel com
# Example (match everything): .+ripetopresolv #channel *
#
# -ripetopresolv <channel> <topdomain|*>
# Remove a top resolve domain or regexp pattern from the channel that
# you no longer wish to resolve.
#
# +ripetopdom <channel> <topdomain>
# Add a top domain for the channel that you wish to ban
# Example: .+ripetopdom #channel ro
#
# -ripetopdom <channel> <topdomain>
# Remove a top domain from the channel that you no longer
# wish to ban
#
# ripesettings
# List current channel settings
#
# ripeconfig <option> [value]
#  Options:
#   banreason [string]    : Set custom ban reason, support substitutional keywords, see below
#   bantopreason [string] : Set custom TLD ban reason, support substitutional keywords, see below
#   msgcmds [on|off]      : Enable or Disable commands through private message
#   fallback [on|off]     : EXPERIMENTAL!!! Use with caution!
#                           This function will _try_ to detect country for an host where the whois server
#                           only return a few NET-XXX-XXX-XXX-XXX entries.
#                           The intention is to replace lastResortMask.
#  Examples:
#   TLD ban reason: .ripeconfig bantopreason Hello %nick%, TLD '%tld%' is not allowed here
#   Ban reason: .ripeconfig banreason Sorry %country%(%tld%) is not allowed in here
#   Enable msgcmds: .ripeconfig msgcmds on
#   Disable msgcmds: .ripeconfig msgcmds off
#  Substitutional keywords, current keywords are:
#   %tld% = Top level domain, ie .us, .se, .no
#   %country% = Country name
#   %nick% = Nickname of the user being banned
#  *NOTE*:
#   To completely remove an option from the configuration leave \[value\] blank, ie .ripeconfig msgcmds
#
# help ripecheck
# View ripecheck command help page through dcc console
#
# Public channel commands:
# !ripecheck <host>
# !ripeinfo <host>
# !ripestatus <*|#channel>
#
# Private msg commands:
# !ripecheck <host>
# !ripeinfo <host>
###
# Tested:
# eggdrop v1.6.19 GNU/Linux with tcl 8.5 and tcllib 1.10
###
# BUGS?!
# If you discover any problems please send an e-mail
# to ratler@stderr.eu with as detailed information as possible
# on how to reproduce the issue.
###
# LICENSE:
# Copyright (C) 2006 - 2010  Stefan Wold <ratler@stderr.eu>
#
# This code comes with ABSOLUTELY NO WARRANTY
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# RIPE Country Checker

if {[namespace exists ::ripecheck]} {namespace delete ::ripecheck}
namespace eval ::ripecheck {
    # --- Settings ---

    # RIPE query timeout setting, default 5 seconds
    variable rtimeout 5

    # Set console output flag, for debug purpose (default d, ie .console +d)
    variable conflag d

    # Path to netmask file
    variable iplistfile "scripts/iplist.txt"

    # Path to channel settings file
    variable chanfile "ripecheckchan.dat"

    # Path to tld country list file
    variable tldfile "scripts/tld_country_list.txt"

}
# ---- Only edit stuff below this line if you know what you are doing ----

# Channel flags
setudef flag ripecheck
setudef flag ripecheck.topchk
setudef flag ripecheck.topban
setudef flag ripecheck.pubcmd
setudef flag ripecheck.whitelist
setudef int ripecheck.bantime

# Packages
package require ip

# Bindings
bind join - *!*@* ::ripecheck::onJoin
bind dcc -|- testripecheck ::ripecheck::test
bind dcc m|ov +ripetopdom ::ripecheck::addTopDom
bind dcc m|ov -ripetopdom ::ripecheck::delTopDom
bind dcc m|ov +ripetopresolv ::ripecheck::addTopResolve
bind dcc m|ov -ripetopresolv ::ripecheck::delTopResolve
bind dcc m|ov ripeconfig ::ripecheck::config
bind dcc -|- ripesettings ::ripecheck::settings
bind dcc -|- help ::ripecheck::help
bind pub -|- !ripecheck ::ripecheck::pubRipeCheck
bind msg -|- !ripecheck ::ripecheck::msgRipeCheck
bind pub -|- !ripeinfo ::ripecheck::pubRipeInfo
bind msg -|- !ripeinfo ::ripecheck::msgRipeInfo
bind pub -|- !ripestatus ::ripecheck::pubRipeStatus

namespace eval ::ripecheck {
    # Global variables
    variable version "3.2.3-dev"

    variable maskarray
    variable chanarr
    variable topresolv
    variable config
    variable constate
    variable tldtocountry
    variable bancount

    # Parse ip list file
    if {[file exists $::ripecheck::iplistfile]} {
        set fid [open $::ripecheck::iplistfile r]
        while { ![eof $fid] } {
            gets $fid line
            if {[regexp {^[0-9]} $line]} {
                regexp -nocase {^([0-9\.\/]+)[[:space:]]+([a-z0-9\.]+)} $line dummy mask whoisdb
                lappend ::ripecheck::maskarray $mask
                set ::ripecheck::maskhash($mask) $whoisdb
            }
        }
        close $fid
        # These two variables should _ALWAYS_ be of the same size, otherwise something is wrong
        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - IP file loaded with [llength $::ripecheck::maskarray] netmask(s)"
        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - IP file loaded with [array size ::ripecheck::maskhash] whois entries"
    }

    # Read settings - only at startup
    if {[file exists $::ripecheck::chanfile]} {
        set fchan [open $::ripecheck::chanfile r]
        while { ![eof $fchan] } {
            gets $fchan line
            if {[regexp {^\#} $line]} {
                set ::ripecheck::chanarr([string tolower [lindex [split $line :] 0]]) [split [lindex [split $line :] 1] ,]
            } elseif {[regexp {^topresolv} $line]} {
                set ::ripecheck::topresolv([string tolower [lindex [split $line :] 1]]) [split [lindex [split $line :] 2] ,]
            } elseif {[regexp {^config} $line]} {
                set ::ripecheck::config([lindex [split $line :] 1]) [lindex [split $line :] 2]
            } elseif {[regexp {^stats:bancount} $line]} {
                set ::ripecheck::bancount([lindex [split $line :] 2]) [lindex [split $line :] 3]
            }
        }
        close $fchan
        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Channel file loaded with settings for [array size ::ripecheck::chanarr] channel(s)"
        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Top resolv domains loaded for [array size ::ripecheck::topresolv] channel(s)"
    }

    # Read tld_country_list
    if {[file exists $::ripecheck::tldfile]} {
        set ftld [open $::ripecheck::tldfile r]
        while { ![eof $ftld] } {
            gets $ftld line
            if {[regexp {^[a-z]} $line]} {
                regexp -nocase {^([a-z]{2,6})[[:space:]]+(.*)} $line -> tld country
                set ::ripecheck::tldtocountry($tld) $country
            }
        }
        close $ftld
        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - TLD country list loaded with [array size ::ripecheck::tldtocountry] entries"
    }

    # Functions
    proc onJoin { nick host handle channel } {
        # Lower case channel
        set channel [string tolower $channel]

        # Only run if channel is defined
        if {![channel get $channel ripecheck]} { return 1 }

        # Exclude ops, voice, friends
        if {[matchattr $handle fov|fov $channel]} {
            putloglev $::ripecheck::conflag * "ripecheck: $nick is on exempt list"
            return 1
        }

        # Check if channel has a domain list or complain about it and then abort
        if {![info exists ::ripecheck::chanarr($channel)]} {
            putlog "ripecheck: Ripecheck is enabled but '$channel' has no domain list!"
            return 1
        }

        # Get IP/Host part
        regexp ".+@(.+)" $host matches iphost
        set iphost [string tolower $iphost]

        # Top domain ban if enabled
        if {[channel get $channel ripecheck.topban] && ![regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $iphost]} {
            set htopdom [lindex [split $iphost "."] end]
            if {(![channel get $channel ripecheck.whitelist] && [lsearch -exact $::ripecheck::chanarr($channel) $htopdom] != -1) || \
                ([channel get $channel ripecheck.whitelist] && [lsearch -exact $::ripecheck::chanarr($channel) $htopdom] == -1 && ![::ripecheck::isInTopResolve $channel $htopdom])} {
                set country [::ripecheck::getCountry $htopdom]
                set template [list %nick% $nick \
                                   %domain% $htopdom \
                                   %tld% $htopdom \
                                   %country% $country]
                set bantime [channel get $channel ripecheck.bantime]
                if {[info exists ::ripecheck::config(bantopreason)]} {
                    set banreason [::ripecheck::templateReplace $::ripecheck::config(bantopreason) $template]
                } else {
                    set banreason "RIPE Country Check: Top domain .$htopdom is banned."
                }
                putlog "ripecheck: Matched top domain '$htopdom' banning *!*@*.$htopdom on $channel for $bantime minute(s)"
                ::ripecheck::incrBanCount $channel
                newchanban $channel "*!*@*.$htopdom" ripecheck $banreason $bantime

                return 1
            }
        }

        # Only run RIPE check on numeric IP unless ripecheck.topchk is enabled
        if {[regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $iphost]} {
            putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Found numeric IP $iphost ... scanning"
            ::ripecheck::whoisFindServer $iphost $iphost 1 $nick $channel $host ripecheck
        } elseif {[channel get $channel ripecheck.topchk]} {
            # Check if channel has a resolve domain list or complain about it and then abort
            if {![info exists ::ripecheck::topresolv($channel)]} {
                putlog "ripecheck: Ripecheck is enabled but '$channel' has no resolve domain list!"
                return 0
            }

            putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Checking if host match the top resolve list..."

            set htopdom [lindex [split $iphost "."] end]
            if {[::ripecheck::isInTopResolve $channel $htopdom]} {
                putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Matched top resolve domain '$htopdom' for host '$iphost'"
                dnslookup $iphost ::ripecheck::whoisFindServer $nick $channel $host ripecheck
            }
        }
    }

    proc notifySender { nick channel rtype msg } {
        putloglev $::ripecheck::conflag * "ripecheck: DEBUG: Entering notifySender()"
        if {$rtype == "pubRipeCheck" || $rtype == "pubRipeInfo"} {
            puthelp "PRIVMSG $channel :$nick: \[ripecheck\] $msg"
        } elseif {$rtype == "msgRipeInfo" || $rtype == "msgRipeCheck"} {
            puthelp "PRIVMSG $nick :ripecheck: $msg"
        }
    }

    proc ripecheck { ip host nick channel orghost ripe } {
        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Entering ripecheck()"
        set bantime [channel get $channel ripecheck.bantime]
        if {(![channel get $channel ripecheck.whitelist] && [lsearch -exact $::ripecheck::chanarr($channel) $ripe] != -1) || \
            ([channel get $channel ripecheck.whitelist] && [lsearch -exact $::ripecheck::chanarr($channel) $ripe] == -1)} {
            putloglev $::ripecheck::conflag * "ripecheck: DEBUG - ripecheck() matched '$ripe'"
            set country [::ripecheck::getCountry $ripe]
            set template [list %nick% $nick \
                               %ripe% $ripe \
                               %tld% $ripe \
                               %country% $country]
            if {[info exists ::ripecheck::config(banreason)]} {
                set banreason [::ripecheck::templateReplace $::ripecheck::config(banreason) $template]
            } else {
                set banreason "RIPE Country Check: Matched $country \[$ripe\]"
            }
            putlog "ripecheck: Matched country $country \[$ripe\] banning $nick!$orghost on $channel for $bantime minute(s)"
            ::ripecheck::incrBanCount $channel
            newchanban $channel "*!*@$host" ripecheck $banreason $bantime
        }
    }

    proc incrBanCount { channel } {
        if {![info exists ::ripecheck::bancount($channel)]} {
            set ::ripecheck::bancount($channel) 1
        } else {
            set ::ripecheck::bancount($channel) [expr $::ripecheck::bancount($channel) + 1]
        }
        ::ripecheck::writeSettings
    }

    proc getBanCount { channel } {
        if {![info exists ::ripecheck::bancount($channel)]} {
            return 0
        }
        return $::ripecheck::bancount($channel)
    }

    proc test { nick idx arg } {
        if {[llength [split $arg]] != 2} {
            ::ripecheck::help $nick $idx testripecheck; return 0
        }

        foreach {channel ip} $arg {break}
        set ip [string tolower $ip]
        set channel [string tolower $channel]

        if {[validchan $channel]} {
            # First we check if topban is enabled
            if {[channel get $channel ripecheck.topban] && ![regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]} {
                set htopdom [lindex [split $ip "."] end]
                if {(![channel get $channel ripecheck.whitelist] && [lsearch -exact $::ripecheck::chanarr($channel) $htopdom] != -1) || \
                    ([channel get $channel ripecheck.whitelist] && [lsearch -exact $::ripecheck::chanarr($channel) $htopdom] == -1 && ![::ripecheck::isInTopResolve $channel $htopdom])} {
                    putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Topban matched '$htopdom' for host '$ip', host would get banned!"

                    return 1
                }
            }

            if {[regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]} {
                ::ripecheck::whoisFindServer $ip "" ""  $nick $channel "" testRipeCheck
            } else {
                putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Resolving..."
                set htopdom [lindex [split $ip "."] end]
                if {[lsearch -exact $::ripecheck::topresolv($channel) "*"] != -1 || [lsearch -exact $::ripecheck::topresolv($channel) $htopdom] != -1} {
                    putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Matched top resolve domain '$htopdom' for host '$ip' on '$channel'"
                    dnslookup $ip ::ripecheck::whoisFindServer $nick $channel "" testRipeCheck
                } else {
                    putidx $idx "ripecheck: TEST - Host '$ip' did not match one of the top resolve domains, would not get banned."
                }
            }
        } else {
            putdcc $idx "\002RIPECHECK\002: Invalid channel $channel"
        }
    }

    proc ripeInfo { target inetnum netname mntby country descr } {
        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Entering ripeInfo()"
        set countryname [::ripecheck::getCountry $country]

        putquick "PRIVMSG $target :Inetnum: $inetnum"
        putquick "PRIVMSG $target :Netname: $netname"
        putquick "PRIVMSG $target :mnt-by: $mntby"
        if {$countryname == ""} {
            putquick "PRIVMSG $target :Country: $country"
        } else {
            putquick "PRIVMSG $target :Country: $countryname \[[string toupper $country]\]"
        }
        putquick "PRIVMSG $target :Description: $descr"
    }

    proc testripecheck { nick ip host channel ripe } {
        # Get idx from nick (handle)
        set idx [hand2idx $nick]
        if {$idx != -1} {
            if {(![channel get $channel ripecheck.whitelist] && [lsearch -exact $::ripecheck::chanarr($channel) $ripe] != -1) || \
                ([channel get $channel ripecheck.whitelist] && [lsearch -exact $::ripecheck::chanarr($channel) $ripe] == -1)} {
                putidx $idx "ripecheck: TEST - Testripecheck matched country '$ripe' for host '$host ($ip)' on channel '$channel', host would get banned!"
            } else {
                putidx $idx "ripecheck: TEST - Testripecheck host '$host ($ip)' would not get banned!"
            }
        }
    }

    proc status { outchannel channel} {
        if {[info exists ::ripecheck::topresolv($channel)]} {
            set topresolve [join $::ripecheck::topresolv($channel) ", "]
        } else {
            set topresolve "No TLD set"
        }

        if {[info exists ::ripecheck::chanarr($channel)]} {
            set tlds [join $::ripecheck::chanarr($channel) ", "]
        } else {
            set tlds "No TLD set"
        }

        putquick "PRIVMSG $outchannel :Status $channel -- Bans set by ripecheck: [::ripecheck::getBanCount $channel]"
        if {[channel get $channel ripecheck.whitelist]} {
            putquick "PRIVMSG $outchannel : Allowed TLD(s): $tlds | Resolve TLD(s): $topresolve"
        } else {
            putquick "PRIVMSG $outchannel : Banned TLDs(s): $tlds | Resolve TLD(s): $topresolve"
        }
    }

    proc pubParseIp { nick host handle channel ip rtype } {
        if {[regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]} {
            set iptype [::ip::type $ip]
            if {$iptype != "normal"} {
                ::ripecheck::notifySender $nick $channel $rtype "Sorry but '$ip' is from a '$iptype' range"
            } else {
                ::ripecheck::whoisFindServer $ip $ip "" $nick $channel "" $rtype
            }
        } else {
            dnslookup $ip ::ripecheck::whoisFindServer $nick $channel "" $rtype
        }
    }

    proc pubRipeCheck { nick host handle channel ip } {
        set channel [string tolower $channel]
        if {![channel get $channel ripecheck.pubcmd]} { return 0 }
        ::ripecheck::pubParseIp $nick $host $handle $channel $ip pubRipeCheck
    }

    proc msgRipeCheck { nick host handle ip } {
        # Check if msgcmds is enabled
        if {[::ripecheck::isConfigEnabled msgcmds]} {
            ::ripecheck::pubParseIp $nick $host $handle "" $ip msgRipeCheck
        }
        return 0
    }

    proc pubRipeInfo { nick host handle channel ip } {
        set channel [string tolower $channel]
        if {![channel get $channel ripecheck.pubcmd]} { return 0 }
        ::ripecheck::pubParseIp $nick $host $handle $channel $ip pubRipeInfo
    }

    proc msgRipeInfo { nick host handle ip } {
        # Check if msgcmds is enabled
        if {[::ripecheck::isConfigEnabled msgcmds]} {
            ::ripecheck::pubParseIp $nick $host $handle "" $ip msgRipeInfo
        }
        return 0
    }

    proc pubRipeStatus { nick host handle channel arg } {
        set channel [string tolower $channel]
        if {![channel get $channel ripecheck.pubcmd]} { return 0 }

        # Grab only first arg and ignore the rest
        set arg [string tolower [lindex [split $arg] 0]]

        if {$arg == "*"} {
            foreach chan [channels] {
                if {[channel get $chan ripecheck]} {
                    ::ripecheck::status $channel $chan
                }
            }
        } elseif {$arg != "" && [channel get $arg ripecheck]} {
            ::ripecheck::status $channel $arg
        } else {
            ::ripecheck::status $channel $channel
        }
    }

    # Lookup which whois server to query and call whois_connect
    proc whoisFindServer { ip host status nick channel orghost rtype } {
        if {$status == 0} {
            ::ripecheck::notifySender $nick $channel $rtype "Failed to resolve '$host'!"
            putlog "ripecheck: Couldn't resolve '$host'. No further action taken."
            return 0
        }

        # Abort if we stumble upon a private or reserved net range
        set iptype [::ip::type $ip]
        if {$iptype != "normal"} {
            putlog "ripecheck: '$ip' is from a '$iptype' range. No further action taken."
            return 0
        }

        set matchmask [::ip::longestPrefixMatch $ip $::ripecheck::maskarray]
        set whoisdb [string tolower $::ripecheck::maskhash($matchmask)]
        set whoisport 43

        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Matching mask $matchmask using whois DB: $whoisdb"

        if {$whoisdb == "unallocated"} {
            ::ripecheck::notifySender $nick $channel $rtype "Unallocated netmask!"
            putlog "ripecheck: Unallocated netmask, bailing out!"
            return 0
        }

        ::ripecheck::whoisConnect $ip $host $nick $channel $orghost $whoisdb $whoisport $rtype
    }

    proc whoisConnect { ip host nick channel orghost whoisdb whoisport rtype } {
        # Setup timeout
        after [expr {int($::ripecheck::rtimeout * 1000)}] set ::ripecheck::constate "timeout"

        if {[catch {socket -async $whoisdb $whoisport} sock]} {
            ::ripecheck::notifySender $nick $channel $rtype "ERROR: Failed to connect to '$whoisdb'!"
            putlog "ripecheck: ERROR: Failed to connect to server $whoisdb!" ; return -1
        }
        fconfigure $sock -buffering line
        fileevent $sock writable [list ::ripecheck::whoisCallback $ip $host $nick $channel $orghost $sock $whoisdb $rtype]
        vwait ::ripecheck::constate
        if { $::ripecheck::constate == "timeout" } {
            ::ripecheck::notifySender $nick $channel $rtype "ERROR: Connection timeout using '$whoisdb'!"
            putlog "ripecheck: ERROR: Connection timeout against $whoisdb"; return -1
        }
    }

    proc whoisCallback { ip host nick channel orghost sock whoisdb rtype } {
        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Entering whois_callback..."
        set whoisdata(inetnum) "No info"
        set whoisdata(netname) "No info"
        set whoisdata(mntby) "No info"
        set whoisdata(descr) "No info"

        if {[string equal {} [fconfigure $sock -error]]} {
            puts $sock $ip
            flush $sock

            putloglev $::ripecheck::conflag * "ripecheck: DEBUG - State 'connected' with '$whoisdb'"

            set ::ripecheck::constate "connected"

            while {![eof $sock]} {
                set row [gets $sock]
                if {[regexp -line -nocase {referralserver:\s*(.*)} $row -> referral]} {
                    set referral [string tolower $referral]
                    putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Found whois referral server: $referral"

                    # Extract the whois server from $referral
                    if {[regexp -line -nocase {^whois://(.*[^/])/?} $referral -> referral]} {
                        foreach {referral whoisport} [split $referral :] { break }

                        # Set default port if empty
                        if {$whoisport == ""} {
                            set whoisport 43
                        }

                        # Close socket, don't want to many sockets open simultaneously
                        close $sock

                        # Time for some recursive looping ;)
                        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Following referral server, new server is '$referral', port '$whoisport'"
                        ::ripecheck::whoisConnect $ip $host $nick $channel $orghost $referral $whoisport $rtype

                        return 1
                    } elseif {[regexp -line -nocase {^rwhois://.*} $referral]} {
                        # Ignore rwhois for now
                        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Ignoring rwhois referral"
                        continue
                    } else {
                        putlog "ripecheck: ERROR: Unknown referral type from '$whoisdb' for ip '$ip', please bug report this line."
                        close $sock; return 0
                    }
                } elseif {[regexp -line -nocase {country:\s*([a-z]{2,6})} $row -> data]} {
                    set whoisdata(country) [string tolower $data]
                    putloglev $::ripecheck::conflag * "ripecheck: DEBUG - $whoisdb answer: $whoisdata(country)"
                } elseif {[regexp -line -nocase {netname:\s*(.*)} $row -> data]} {
                    set whoisdata(netname) $data
                } elseif {[regexp -line -nocase {descr:\s*(.*)} $row -> data] && ![info exists whoisdata(descr)]} {
                    set whoisdata(descr) $data
                } elseif {[regexp -line -nocase {mnt-by:\s*(.*)} $row -> data]} {
                    set whoisdata(mntby) $data
                } elseif {[regexp -line -nocase {inetnum:\s*(.*)} $row -> data]} {
                    set whoisdata(inetnum) $data
                } elseif {[regexp -line {.*\((NET-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}.*)\)} $row -> data]} {
                    set whoisdata(fallback) $data
                }
            }

            close $sock
            putloglev $::ripecheck::conflag * "ripecheck: DEBUG - End of while-loop in whois_callback"

            # Experimental feature that might replace lastResortMasks in the future
            if {[::ripecheck::isConfigEnabled fallback] && ![info exists whoisdata(country)] && [info exists whoisdata(fallback)]} {
                putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Using fallback method (EXPERIMENTAL) for '$whoisdata(fallback)' original host was $host ($ip)"
                ::ripecheck::whoisConnect $whoisdata(fallback) $host $nick $channel $orghost $whoisdb 43 $rtype
                return 1
            }

            # Last resort, check if we get a match from hardcoded netmasks
            if {![info exists whoisdata(country)] && [::ripecheck::lastResortMasks $ip] != ""} {
                set whoisdata(country) [::ripecheck::lastResortMasks $ip]
                putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Got '$whoisdata(country)' from lastResortMasks"
            }

            if {[info exists whoisdata(country)]} {
                putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Running mode: '$rtype' for country: $whoisdata(country)"
                set country [::ripecheck::getCountry $whoisdata(country)]
                switch -- $rtype {
                    ripecheck {
                        ::ripecheck::ripecheck $ip $host $nick $channel $orghost $whoisdata(country)
                    }
                    testRipeCheck {
                        ::ripecheck::testripecheck $nick $ip $host $channel $whoisdata(country)
                    }
                    pubRipeCheck {
                        ::ripecheck::notifySender $nick $channel $rtype "$host is located in $country \[[string toupper $whoisdata(country)]\]"
                    }
                    msgRipeCheck {
                        ::ripecheck::notifySender $nick $channel $rtype "$host is located in $country \[[string toupper $whoisdata(country)]\]"
                    }
                    pubRipeInfo {
                        ::ripecheck::ripeInfo $channel $whoisdata(inetnum) $whoisdata(netname) $whoisdata(mntby) $whoisdata(country) $whoisdata(descr)
                    }
                    msgRipeInfo {
                        ::ripecheck::ripeInfo $nick $whoisdata(inetnum) $whoisdata(netname) $whoisdata(mntby) $whoisdata(country) $whoisdata(descr)
                    }
                    default {
                        ::ripecheck::ripecheck $ip $host $nick $channel $orghost $whoisdata(country)
                    }
                }
            } else {
                # Respond that something went wrong
                ::ripecheck::notifySender $nick $channel $rtype "Whois query failed for '$host'!"
                putlog "ripecheck: No country found for '$ip'. No further action taken. (Possible bug?)"
            }
        } else {
            set ::ripecheck::constate "timeout"
        }
    }

    # Add top resolv domain for channel and write settings to file
    proc addTopResolve { nick idx arg } {
        if {[llength [split $arg]] != 2} {
            ::ripecheck::help $nick $idx +ripetopresolv; return 0
        }

        foreach {channel topdom} $arg {break}

        set channel [string tolower $channel]
        set topdom [string tolower $topdom]

        if {[validchan $channel]} {
            # It's pointless to set a resolv domain if no domains have been added for banning on the
            # current channel.
            if {[info exists ::ripecheck::chanarr($channel)]} {
                # If data exist extract into a list
                if {[info exists ::ripecheck::topresolv($channel)]} {
                    putloglev $::ripecheck::conflag * "ripecheck: DEBUG - topresolv exists"
                    set dlist $::ripecheck::topresolv($channel)
                    # top domain doesn't exist so lets add it
                    if {[lsearch -exact $dlist $topdom] == -1 } {
                        lappend dlist $topdom
                        set ::ripecheck::topresolv($channel) $dlist
                    } else {
                        putdcc $idx "\002RIPECHECK\002: Resolve domain '$topdom' already exist on $channel"; return 0
                    }
                } else {
                    putloglev $::ripecheck::conflag * "ripecheck: DEBUG - topresolv doesn't exist"
                    set dlist [list $topdom]
                    set ::ripecheck::topresolv($channel) $dlist
                }
                # Write to the ripecheck channel file
                ::ripecheck::writeSettings
                putdcc $idx "\002RIPECHECK\002: Top resolve domain '$topdom' successfully added to $channel."
            } else {
                putdcc $idx "\002RIPECHECK\002: You need to add a top domain for $channel before adding a resolve domain."
            }
        } else {
            putdcc $idx "\002RIPECHECK\002: Invalid channel: $channel"
        }
    }

    # Remove resolve domain from channel and write settings to file
    proc delTopResolve { nick idx arg } {
        if {[llength [split $arg]] != 2} {
            ::ripecheck::help $nick $idx -ripetopresolv; return 0
        }

        foreach {channel topdom} $arg {break}

        set channel [string tolower $channel]
        set topdom [string tolower $topdom]

        if {[validchan $channel]} {
            if {[info exists ::ripecheck::topresolv($channel)]} {
                putloglev $::ripecheck::conflag * "ripecheck: DEBUG - topresolv($channel) exists"
                set dlist $::ripecheck::topresolv($channel)
                # resolve domain exist so lets remove it
                set dlist_index [lsearch -exact $dlist $topdom]
                if {$dlist_index != -1 } {
                    set dlist [lreplace $dlist $dlist_index $dlist_index]
                    # More magic, lets clear array if the list is empty
                    if {[llength $dlist] > 0} {
                        set ::ripecheck::topresolv($channel) $dlist
                    } else {
                        unset ::ripecheck::topresolv($channel)
                    }
                } else {
                    putdcc $idx "\002RIPECHECK\002: Resolve domain '$topdom' doesn't exist on $channel"; return 0
                }

            } else {
                putdcc $idx "\002RIPECHECK\002: Nothing to do, no settings found for $channel."; return 0
            }
            # Write to the ripecheck channel file
            ::ripecheck::writeSettings
            putdcc $idx "\002RIPECHECK\002: Resolve domain '$topdom' successfully removed from $channel."

        } else {
            putdcc $idx "\002RIPECHECK\002: Invalid channel: $channel"
        }
    }

    # List channel and top resolv domains
    proc settings { nick idx arg } {
        putdcc $idx "### \002Settings\002 - Ripecheck v$::ripecheck::version by Ratler ###"
        if {[array size ::ripecheck::chanarr] > 0} {
            foreach channel [array names ::ripecheck::chanarr] {
                if {[validchan $channel]} {
                    putdcc $idx "### \002Channel:\002 $channel"
                    if {[channel get $channel ripecheck.whitelist]} {
                        putdcc $idx "    Whitelist mode: On"
                        putdcc $idx "    \002Allowed domains:\002 [join $::ripecheck::chanarr($channel) ", "]"
                    } else {
                        putdcc $idx "    Whitelist mode: Off"
                        putdcc $idx "    \002Banned domains:\002 [join $::ripecheck::chanarr($channel) ", "]"
                    }
                    if {[info exists ::ripecheck::topresolv($channel)]} {
                        putdcc $idx "    \002Resolve domains:\002 [join $::ripecheck::topresolv($channel) ", "]"
                    }
                }
            }
        } else {
            putdcc $idx "### No channel settings exist."
        }
        foreach option [array names ::ripecheck::config] {
            putdcc $idx "### \002$option:\002 $::ripecheck::config($option)"
        }
    }

    # Function to set general options
    proc config { nick idx arg } {
        if {!([llength [split $arg]] > 0)} {
            ::ripecheck::help $nick $idx ripeconfig; return 0
        }

        # Allowed string options
        set allowed_str_opts [list banreason bantopreason]

        # Allowed boolean options
        set allowed_bool_opts [list msgcmds fallback]

        set option [string tolower [lindex [split $arg] 0]]
        set value [join [lrange [split $arg] 1 end]]


        # Check option type
        if {[lsearch -exact $allowed_str_opts $option] != -1} {
            if {$value != ""} {
                set ::ripecheck::config($option) $value
                putdcc $idx "\002RIPECHECK\002: Option '$option' set with the value '$value'"
            } else {
                if {[info exists ::ripecheck::config($option)]} {
                    unset ::ripecheck::config($option)
                }
                # Always output unset msg for convenience
                putdcc $idx "\002RIPECHECK\002: Option '$option' unset"
            }
        } elseif {[lsearch -exact $allowed_bool_opts $option] != -1} {
            set value [string tolower $value]
            if {[string is boolean $value] && $value != ""} {
                set ::ripecheck::config($option) $value
                putdcc $idx "\002RIPECHECK\002: Option '$option' set with the value '$value'"
            } elseif { $value == "" } {
                if {[info exists ::ripecheck::config($option)]} {
                    unset ::ripecheck::config($option)
                }
                # Always output unset msg for convenience
                putdcc $idx "\002RIPECHECK\002: Option '$option' unset"
            } else {
                putdcc $idx "\002RIPECHECK\002: Value '$value' is not a boolean, should be true|false|on|off|1|0"
                return 0
            }
        } else {
            putdcc $idx "\002RIPECHECK\002: Invalid option '$option', valid options are: [join $allowed_str_opts ", "], [join $allowed_bool_opts ", "]"
            return 0
        }

        ::ripecheck::writeSettings
    }

    # Add top domain to channel and write settings to file
    proc addTopDom { nick idx arg } {
        if {[llength [split $arg]] != 2} {
            ::ripecheck::help $nick $idx +ripetopdom; return 0
        }

        foreach {channel topdom} $arg {break}

        set channel [string tolower $channel]
        set topdom [string tolower $topdom]

        if {[validchan $channel]} {
            # If data exist extract into a list
            if {[info exists ::ripecheck::chanarr($channel)]} {
                putloglev $::ripecheck::conflag * "ripecheck: DEBUG - chanarr exists"
                set dlist $::ripecheck::chanarr($channel)
                # top domain doesn't exist so lets add it
                if {[lsearch -exact $dlist $topdom] == -1 } {
                    lappend dlist $topdom
                    set ::ripecheck::chanarr($channel) $dlist
                } else {
                    putdcc $idx "\002RIPECHECK\002: Domain '$topdom' already exist on $channel"; return 0
                }
            } else {
                putloglev $::ripecheck::conflag * "ripecheck: DEBUG - chanarr doesn't exist"
                set dlist [list $topdom]
                set ::ripecheck::chanarr($channel) $dlist
            }
            # Write to the ripecheck channel file
            ::ripecheck::writeSettings
            putdcc $idx "\002RIPECHECK\002: Top domain '$topdom' successfully added to $channel."
        } else {
            putdcc $idx "\002RIPECHECK\002: Invalid channel: $channel"
        }
    }

    # Remove top domain for channel and write settings to file
    proc delTopDom { nick idx arg } {
        if {[llength [split $arg]] != 2} {
            ::ripecheck::help $nick $idx -ripetopdom; return 0
        }

        foreach {channel topdom} $arg {break}

        set channel [string tolower $channel]
        set topdom [string tolower $topdom]

        if {[validchan $channel]} {
            if {[info exists ::ripecheck::chanarr($channel)]} {
                putloglev $::ripecheck::conflag * "ripecheck: DEBUG - chanarr($channel) exists"
                set dlist $::ripecheck::chanarr($channel)
                # top domain doesn't exist so lets add it
                set dlist_index [lsearch -exact $dlist $topdom]
                if {$dlist_index != -1 } {
                    set dlist [lreplace $dlist $dlist_index $dlist_index]
                    # More magic, clear array if list is empty
                    if {[llength $dlist] > 0} {
                        set ::ripecheck::chanarr($channel) $dlist
                    } else {
                        unset ::ripecheck::chanarr($channel)
                    }
                } else {
                    putdcc $idx "\002RIPECHECK\002: Domain '$topdom' doesn't exist on $channel"; return 0
                }

            } else {
                putdcc $idx "\002RIPECHECK\002: Nothing to do, no settings found for $channel."; return 0
            }
            # Write to the ripecheck channel file
            ::ripecheck::writeSettings
            putdcc $idx "\002RIPECHECK\002: Top domain '$topdom' successfully removed from $channel."

        } else {
            putdcc $idx "\002RIPECHECK\002: Invalid channel: $channel"
        }
    }

    # Define whois overrides for netmasks with incomplete records
    proc lastResortMasks { ip } {
        set masks(24.16.0.0/13) "us"
        set masks(24.239.32.0/19) "us"
        set masks(208.151.241.0/24) "us"
        set masks(208.151.242.0/23) "us"
        set masks(208.151.244.0/22) "us"
        set masks(208.151.248.0/21) "us"

        # Create a list from the masks array
        foreach mask [array names masks] {
            lappend masklist $mask
        }

        set matchmask [::ip::longestPrefixMatch $ip $masklist]
        if {$matchmask != ""} {
            return $masks($matchmask)
        }
    }

    # Return a country based on tld or return "" if no country is found
    proc getCountry { tld } {
        if {[array size ::ripecheck::tldtocountry] > 0} {
            set country $::ripecheck::tldtocountry($tld)
            if {$country != ""} {
                return $country
            }
        }
        return ""
    }

    # Return modified text based on template list
    proc templateReplace { text subs } {
        foreach {arg1 arg2} $subs {
            regsub -all -- $arg1 $text $arg2 text
        }
        return $text
    }

    proc isConfigEnabled { option } {
        if {[info exists ::ripecheck::config($option)] && [string is boolean $::ripecheck::config($option)] && [string is true $::ripecheck::config($option)]} {
            return true
        }
        return false
    }

    proc isInTopResolve { channel htopdom } {
        if {[lsearch -exact $::ripecheck::topresolv($channel) "*"] != -1 || [lsearch -exact $::ripecheck::topresolv($channel) $htopdom] != -1} {
            return true
        }
        return false
    }

    proc writeSettings { } {
        # Backup file in case something goes wrong
        if {[file exists $::ripecheck::chanfile]} {
            # Don't backup a zero byte file
            if {[file size $::ripecheck::chanfile] > 0} {
                file copy -force $::ripecheck::chanfile $::ripecheck::chanfile.bak
            }
        }
        set fp [open $::ripecheck::chanfile w]

        foreach key [array names ::ripecheck::chanarr] {
            puts $fp "$key:[join $::ripecheck::chanarr($key) ,]"
        }
        foreach key [array names ::ripecheck::topresolv] {
            puts $fp "topresolv:$key:[join $::ripecheck::topresolv($key) ,]"
        }
        foreach key [array names ::ripecheck::config] {
            puts $fp "config:$key:[join $::ripecheck::config($key)]"
        }
        foreach key [array names ::ripecheck::bancount] {
            puts $fp "stats:bancount:$key:$::ripecheck::bancount($key)"
        }
        close $fp
    }

    proc help { hand idx arg } {
        switch -- $arg {
            ripecheck {
                putidx $idx "### \002ripecheck v$::ripecheck::version\002 by Ratler ###"; putidx $idx ""
                putidx $idx "### \002chanset <channel> <+/->ripecheck\002"
                putidx $idx "    Enable (+) or disable (-) the script for specified channel"
                putidx $idx "### \002chanset <channel> ripecheck.bantime <minutes>\002"
                putidx $idx "    For how long should the ban be active in minutes"
                putidx $idx "### \002chanset <channel> <+/->ripecheck.topchk\002"
                putidx $idx "    Enable (+) or disable (-) top domain resolve check"
                putidx $idx "### \002chanset <channel> <+/->ripecheck.topban\002"
                putidx $idx "    Enable (+) or disable (-) top domain banning based on the topdomain list"
                putidx $idx "### \002chanset <channel> <+/->ripecheck.pubcmd\002"
                putidx $idx "    Enable (+) or disable (-) public commands (!ripecheck)"
                putidx $idx "### \002chanset <channel> <+/->ripecheck.whitelist\002"
                putidx $idx "    Enable (+) or disable (-) whitelist mode"
                putidx $idx "    The whitelist mode reverse the ripecheck behavior when matching"
                putidx $idx "    a country against the topdomain list. Instead of banning a country that"
                putidx $idx "    exist in the topdomain list it will let that host enter the channel and ban"
                putidx $idx "    everyone else."
                ::ripecheck::help $hand $idx +ripetopresolv
                ::ripecheck::help $hand $idx -ripetopresolv
                ::ripecheck::help $hand $idx +ripetopdom
                ::ripecheck::help $hand $idx -ripetopdom
                ::ripecheck::help $hand $idx ripesettings
                ::ripecheck::help $hand $idx ripeconfig
                ::ripecheck::help $hand $idx testripecheck
                putidx $idx "### \002help ripecheck\002"
                putidx $idx "    This help page you're currently viewing"
            }
            +ripetopresolv {
                putidx $idx "### \002+ripetopresolv <channel> <topdomain|*>\002"
                putidx $idx "    Add a top domain or regexp pattern that you want to resolve for"
                putidx $idx "    further ripe checking. It's possible that domains like com, info, org"
                putidx $idx "    could be from a country that is banned in the top domain list."
                putidx $idx "    Example (match .com): .+ripetopresolv #channel com"
                putidx $idx "    Example (match everything): .+ripetopresolv #channel *"
            }
            -ripetopresolv {
                putidx $idx "### \002-ripetopresolv <channel> <topdomain|*>\002"
                putidx $idx "    Remove a top resolve domain or * from the channel that"
                putidx $idx "    you no longer wish to resolve."
            }
            +ripetopdom {
                putidx $idx "### \002+ripetopdom <channel> <topdomain>\002"
                putidx $idx "    Add a top domain for the channel that you wish to ban"
                putidx $idx "    Example: .+ripetopdom #channel ro"
            }
            -ripetopdom {
                putidx $idx "### \002-ripetopdom <channel> <topdomain>\002"
                putidx $idx "    Remove a top domain from the channel that you no longer"
                putidx $idx "    wish to ban"
            }
            ripeconfig {
                putidx $idx "### \002ripeconfig <option> \[value\]\002"
                putidx $idx "    \002Options\002:"
                putidx $idx "     banreason \[string\]    : Set custom ban reason, support substitutional keywords, see below"
                putidx $idx "     bantopreason \[string\] : Set custom TLD ban reason, support substitutional keywords, see below"
                putidx $idx "     msgcmds \[on|off\]      : Enable or Disable commands through private message"
                putidx $idx "     fallback \[on|off\]     : \002EXPERIMENTAL!!! Use with caution!\002"
                putidx $idx "                             This function will _try_ to detect country for an host where the whois server"
                putidx $idx "                             only return a few NET-XXX-XXX-XXX-XXX entries."
                putidx $idx "                             The intention is to replace lastResortMask."
                putidx $idx "    \002Examples\002:"
                putidx $idx "     TLD ban reason: .ripeconfig bantopreason Hello %nick%, TLD '%tld%' is not allowed here"
                putidx $idx "     Ban reason: .ripeconfig banreason Sorry %country%(%tld%) is not allowed in here"
                putidx $idx "     Enable msgcmds: .ripeconfig msgcmds on"
                putidx $idx "     Disable msgcmds: .ripeconfig msgcmds off"
                putidx $idx "    \002Substitutional keywords, current keywords are\002:"
                putidx $idx "     %tld% = Top level domain, ie .us, .se, .no"
                putidx $idx "     %country% = Country name"
                putidx $idx "     %nick% = Nickname of the user being banned"
                putidx $idx "    \002*NOTE*\002:"
                putidx $idx "      To completely remove an option from the configuration leave \[value\] blank, ie .ripeconfig msgcmds"
            }
            ripesettings {
                putidx $idx "### \002ripesettings\002"
                putidx $idx "    View current settings"
            }
            testripecheck {
                putidx $idx "### \002testripecheck <channel> <host>\002"
            }
            default {
                *dcc:help $hand $idx [join $arg]
                if {[llength [split $arg]] == 0} {
                    putidx $idx "\n\nripecheck v$::ripecheck::version commands:"
                    putidx $idx "   \002+ripetopresolv    -ripetopresolv    +ripetopdom    -ripetopdom\002"
                    putidx $idx "   \002ripesettings      ripeconfig        testripecheck\002"
                }
                return 1
            }
        }
    }
}
putlog "\002Ripecheck v$::ripecheck::version\002 by Ratler loaded"
