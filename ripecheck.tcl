#
# ripecheck.tcl  Version: 2.6.1  Author: Stefan Wold <ratler@stderr.eu>
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
#   you wish to ban. Now also support regexp pattern matching.
# * Custom ban messages
# * Now has help pages, see .help ripecheck
###
# Require / Depends:
# tcllib >= 1.8
###
# Usage:
# Load the script and change the topdomains you
# wish to ban.
#
# You can test ip addresses from dcc console
# against your current settings by enabling debug output
# (.console +d) and running .testripecheck <channel> <host>
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
# +ripetopresolv <channel> <pattern>
# Add a top domain or regexp pattern that you want to resolve for
# further ripe checking. It's possible that domains like com, info, org
# could be from a country that is banned in the top domain list.
# Example (match .com): .+ripetopresolv #channel com
# Example (match everything): .+ripetopresolv #channel .*
# Example (match .a-f*): .+ripetopresolv #channel [a-f]*
#
# -ripetopresolv <channel> <pattern>
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
# ripebanr <banreason|bantopreson> [text]
# Set custom ban reasons for 'banreason' and 'bantopreason'.
# To restore the default message run the above command without [text]"
# The [text] support substitutional keywords, current keywords are:
# %domain% = Topdomain used in 'bantopreason'"
# %ripe% = Country code from the whois server, used in 'banreason'"
# %nick% = Nickname for the user being banned, used in both 'banreason' and 'bantopreason'"
# Example (topdomain reason): .ripebanr bantopreason Hello '%nick%, TLD '%domain%' is not allowed here"
# Example (standard reason): .ripebanr banreason Sorry '%ripe' not allowed in here"
# Example (restore default ban reason): .ripebanr banreason"
#
# ripesettings
# List current channel settings
#
# help ripecheck
# View ripecheck command help page through dcc console
#
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
# Copyright (C) 2006 - 2009  Stefan Wold <ratler@stderr.eu>
#
# This code comes with ABSOLUTELY NO WARRANTY
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

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
}
# ---- Only edit stuff below this line if you know what you are doing ----

# Channel flags
setudef flag ripecheck
setudef flag ripecheck.topchk
setudef flag ripecheck.topban
setudef flag ripecheck.pubcmd
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
bind dcc m|ov ripebanr ::ripecheck::banReason
bind dcc -|- ripesettings ::ripecheck::settings
bind dcc -|- help ::ripecheck::help
bind pub -|- !ripecheck ::ripecheck::pubRipeCheck

namespace eval ::ripecheck {
    # Global variables
    variable version "3.0-testing"
    variable maskarray
    variable chanarr
    variable topresolv
    variable config

    # Parse ip list file
    if {[file exists $::ripecheck::iplistfile]} {
        set fid [open $::ripecheck::iplistfile r]
        while { ![eof $fid] } {
            gets $fid line
            if {[regexp {^\#} $line]} {
                continue
            }
            regexp {^([0-9\.\/]+)[[:space:]]+([a-z\.]+)} $line dummy mask whoisdb
            lappend ::ripecheck::maskarray $mask
            set maskhash($mask) $whoisdb
        }
        close $fid
        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - IP file loaded with [llength $::ripecheck::maskarray] netmasks"
    }

    # Read settings - only at startup
    if {[file exists $::ripecheck::chanfile]} {
        set fchan [open $::ripecheck::chanfile r]
        while { ![eof $fchan] } {
            gets $fchan line
            if {[regexp {^\#} $line]} {
                set chanarr([string tolower [lindex [split $line :] 0]]) [split [lindex [split $line :] 1] ,]
            } elseif {[regexp {^topresolv} $line]} {
                set topresolv([string tolower [lindex [split $line :] 1]]) [split [lindex [split $line :] 2] ,]
            } elseif {[regexp {^config} $line]} {
                set config([lindex [split $line :] 1]) [lindex [split $line :] 2]
            }
        }
        close $fchan
        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Channel file loaded with settings for [array size ::ripecheck::chanarr] channel(s)"
        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Top resolv domains loaded for [array size ::ripecheck::topresolv] channel(s)"
    }

    # Functions
    proc onJoin { nick host handle channel } {
        # Lower case channel
        set channel [string tolower $channel]

        # Only run if channel is defined
        if {![channel get $channel ripecheck]} { return 0 }

        # Exclude ops, voice, friends
        if {[matchattr $handle fov|fov $channel]} {
            putloglev $::ripecheck::conflag * "ripecheck: $nick is on exempt list"
            return 0
        }

        # Check if channel has a domain list or complain about it and then abort
        if {![info exists ::ripecheck::chanarr($channel)]} {
            putlog "ripecheck: Ripecheck is enabled but $channel has no domain list!"
            return 0
        }

        # Get IP/Host part
        regexp ".+@(.+)" $host matches iphost

        # Top domain ban if enabled
        if {[channel get $channel ripecheck.topban]} {
            set htopdom [lindex [split $iphost "."] end]
            foreach domain $::ripecheck::chanarr($channel) {
                if {![string compare $htopdom $domain]} {
                    set template [list %nick% $nick \
                                      %domain% $domain]
                    set bantime [channel get $channel ripecheck.bantime]
                    if {[info exists ::ripecheck::config(bantopreason)]} {
                        set banreason [::ripecheck::templateReplace $::ripecheck::config(bantopreason) $template]
                    } else {
                        set banreason "RIPE Country Check: Top domain .$domain is banned."
                    }
                    putlog "ripecheck: Matched top domain '$domain' banning *!*.$domain for $bantime minute(s)"
                    newchanban $channel "*!*@*.$domain" ripecheck $banreason $bantime
                    
                    return 0
                }
            }
        }

        # Only run RIPE check on numeric IP unless ripecheck.topchk is enabled
        if {[regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $iphost]} {
            putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Found numeric IP $iphost ... scanning"
            ::ripecheck::whoisFindServer $iphost $iphost 1 $nick $channel $host 0
        } elseif {[channel get $channel ripecheck.topchk]} {
            # Check if channel has a resolv domain list or complain about it and then abort
            if {![info exists topresolv($channel)]} {
                putlog "ripecheck: Ripecheck is enabled but $channel has no resolv domain list!"
                return 0
            }

            putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Trying to resolve host ..."

            set htopdom [lindex [split $iphost "."] end]
            foreach domain $topresolv($channel) {
                putloglev $::ripecheck::conflag * "ripecheck: DEBUG - domain: $domain ip: $iphost"
                if {[regexp "^$domain$" $htopdom]} {
                    putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Matched resolve domain '$domain'"
                    dnslookup $iphost ::ripecheck::whoisFindServer $nick $channel $host 0
                    # Break the loop since we found a match
                    break
                }
            }
        }
    }

    proc ripecheck { ip host nick channel orghost ripe } {
        set bantime [channel get $channel ripecheck.bantime]
        foreach country $::ripecheck::chanarr($channel) {
            if {![string compare $ripe $country]} {
                set template [list %nick% $nick \
                                  %ripe% $ripe]
                if {[info exists ::ripecheck::config(banreason)]} {
                    set banreason [ripe_replace $::ripecheck::config(banreason) $template]
                } else {
                    set banreason "RIPE Country Check: Matched .$ripe"
                }
                putlog "ripecheck: Matched country '$ripe' banning $nick!$orghost for $bantime minute(s)"
                newchanban $channel "*!*@$host" ripecheck $banreason $bantime
                # Break the loop since we found a match
                break
            }
        }
    }

    proc test { nick idx arg } {
        global topresolv conflag

        if {[llength [split $arg]] != 2} {
            _ripe_help_dcc $nick $idx testripecheck; return 0
        }

        foreach {channel ip} $arg {break}
        set ip [string tolower $ip]
        set channel [string tolower $channel]

        if {[validchan $channel]} {
            if {[regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]} {
                whois_find_server $ip "" ""  $nick $channel "" 1
            } else {
                putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Resolving..."
                set htopdom [lindex [split $ip "."] end]
                foreach domain $topresolv($channel) {
                    putloglev $::ripecheck::conflag * "ripecheck: DEBUG - channel: $channel domain: $domain ip: $ip top domain: $htopdom"
                    if {[regexp "^$domain$" $htopdom]} {
                        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Matched resolve domain '$domain' for $channel"
                        dnslookup $ip whois_find_server $nick $channel "" 1
                        # Break the loop since we found a match
                        break
                    }
                }
            }
        } else {
            putdcc $idx "\002RIPECHECK\002: Invalid channel $channel"
        }
    }

    proc testripecheck { ip host channel ripe } {
        global chanarr conflag
        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Got country: $ripe"
        foreach country $chanarr($channel) {
            if {![string compare $ripe $country]} {
                putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Matched '$ripe' for $ip on channel $channel."
                # Break the loop since we found a match
                break
            }
        }
    }

    proc pubRipeCheck { nick host handle channel ip } {
        set channel [string tolower $channel]

        if {![channel get $channel ripecheck.pubcmd]} { return 0 }

        if {[regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]} {
            whois_find_server $ip $ip "" $nick $channel "" 2
        } else {
            dnslookup $ip whois_find_server $nick $channel "" 2
        }
    }

    # Lookup which whois server to query and call whois_connect
    proc whoisFindServer { ip host status nick channel orghost test } {
        if {$status == 0} {
            putlog "ripecheck: Couldn't resolve '$host'. No further action taken."
            return 0
        }

        set matchmask [::ip::longestPrefixMatch $ip $::ripecheck::maskarray]
        set whoisdb [string tolower $::ripecheck::maskhash($matchmask)]
        set whoisport 43

        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Matching mask $matchmask using whois DB: $whoisdb"

        if { $whoisdb == "unallocated" } {
            putlog "ripecheck: Unallocated netmask, bailing out!"
            return -1
        }

        ::ripecheck::whoisConnect $ip $host $nick $channel $orghost $whoisdb $whoisport $test
    }

    proc whoisConnect { ip host nick channel orghost whoisdb whoisport test } {
        # Setup timeout
        after $rtimeout * 1000 set ::state "timeout"

        if {[catch {socket -async $whoisdb $whoisport} sock]} {
            putlog "ripecheck: ERROR: Failed to connect to server $whoisdb!" ; return -1
        }
        fconfigure $sock -buffering line
        fileevent $sock writable [list ::ripecheck::whoisCallback $ip $host $nick $channel $orghost $sock $whoisdb $test]
        vwait ::state
        if { $::state == "timeout" } {
            putlog "ripecheck: ERROR: Connection timeout against $whoisdb"; return -1
        }
    }

    proc whoisCallback { ip host nick channel orghost sock whoisdb test } {
        global ::state

        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Entering whois_callback..."

        if {[string equal {} [fconfigure $sock -error]]} {
            puts $sock $ip
            flush $sock
            
            putloglev $::ripecheck::conflag * "ripecheck: DEBUG - State 'connected' with '$whoisdb'"

            set ::state "connected"

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
                        ::ripecheck::whoisConnect $ip $host $nick $channel $orghost $referral $whoisport $test

                        return 0
                    } elseif {[regexp -line -nocase {^rwhois://.*} $referral]} {
                        # Ignore rwhois for now  
                        putloglev $::ripecheck::conflag * "ripecheck: DEBUG - Ignoring rwhois referral"
                        continue
                    } else {
                        putlog "ripecheck: ERROR: Unknown referral type from '$whoisdb' for ip '$ip', please bug report this line."
                        close $sock; return -1
                    }
                } elseif {[regexp -line -nocase {country:\s*([a-z]{2,4})} $row -> country]} {
                    set country [string tolower $country]
                }
            }

            putloglev $::ripecheck::conflag * "ripecheck: DEBUG - End of while-loop in whois_callback"
            
            if {[info exists country]} {
                putloglev $::ripecheck::conflag * "ripecheck: DEBUG - $whoisdb answer: $country Test: $test"
                if {$test == 1} {
                    ::ripecheck::testripecheck $ip $host $channel $country
                } elseif {$test == 2} {
                    puthelp "PRIVMSG $channel :ripecheck: $host is located in '$country'"
                } else {
                    ::ripecheck::ripecheck $ip $host $nick $channel $orghost $country
                }
            } else {
                putlog "ripecheck: No country found for '$ip'. No further action taken. (Possible bug?)"
            }
            
            close $sock
        } else {
            set ::state "timeout"
        }
    }

    # Add top resolv domain for channel and write settings to file
    proc addTopResolve { nick idx arg } {
        global chanarr topresolv conflag

        if {[llength [split $arg]] != 2} {
            _ripe_help_dcc $nick $idx +ripetopresolv; return 0
        }
        
        foreach {channel topdom} $arg {break}

        set channel [string tolower $channel]
        set topdom [string tolower $topdom]

        if {[validchan $channel]} {
            # It's pointless to set a resolv domain if no domains have been added for banning on the
            # current channel.
            if {[info exists chanarr($channel)]} {
                # If data exist extract into a list
                if {[info exists topresolv($channel)]} {
                    putloglev $::ripecheck::conflag * "ripecheck: DEBUG - topresolv exists"
                    set dlist $topresolv($channel)
                    # top domain doesn't exist so lets add it
                    if {[lsearch -exact $dlist $topdom] == -1 } {
                        lappend dlist $topdom
                        set topresolv($channel) $dlist
                    } else {
                        putdcc $idx "\002RIPECHECK\002: Resolve domain '$topdom' already exist on $channel"; return 0
                    }
                } else {
                    putloglev $::ripecheck::conflag * "ripecheck: DEBUG - topresolv doesn't exist"
                    set dlist [list $topdom]
                    set topresolv($channel) $dlist
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
            _ripe_help_dcc $nick $idx -ripetopresolv; return 0
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
                putdcc $idx "\002RIPECHECK\002: Nothing to do, no settings found for $channel."
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
        if {[array size ::ripecheck::chanarr] > 0 && [array size ::ripecheck::topresolv] > 0} {
            foreach channel [array names ::ripecheck::chanarr] {
                putdcc $idx "### \002Channel:\002 $channel"
                putdcc $idx "    \002Banned domains:\002 [join $::ripecheck::chanarr($channel) ", "]"
                putdcc $idx "    \002Resolve domains:\002 [join $::ripecheck::topresolv($channel) ", "]"
            }
        } else {
            putdcc $idx "### No channel settings exist."
        }
        if {[info exists ::ripecheck::config(banreason)]} {
            putdcc $idx "### \002Ban reason:\002 [join $::ripecheck::config(banreason)]"
        }
        if {[info exists ::ripecheck::config(bantopreason)]} {
            putdcc $idx "### \002Ban TLD reason:\002 [join $::ripecheck::config(bantopreason)]"
        }
    }

    # Add top domain to channel and write settings to file
    proc addTopDom { nick idx arg } {
        if {[llength [split $arg]] != 2} {
            _ripe_help_dcc $nick $idx +ripetopdom; return 0
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
            _ripe_help_dcc $nick $idx -ripetopdom; return 0
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
                putdcc $idx "\002RIPECHECK\002: Nothing to do, no settings found for $channel."
            }
            # Write to the ripecheck channel file
            ::ripecheck::writeSettings
            putdcc $idx "\002RIPECHECK\002: Top domain '$topdom' successfully removed from $channel."

        } else {
            putdcc $idx "\002RIPECHECK\002: Invalid channel: $channel"
        }
    }

    proc banRreason { nick idx arg } {
        global ripeconfig

        if {!([llength [split $arg]] > 0)} {
            _ripe_help_dcc $nick $idx ripebanr; return 0
        }

        set type [lindex [split $arg] 0]
        set text [lrange [split $arg] 1 end]

        if {($type == "banreason") || ($type == "bantopreason") } {
            # Lets clear the ban reason
            if {$text == "" && [info exists ::ripecheck::config($type)]} {
                unset ::ripecheck::config($type)
                putdcc $idx "\002RIPECHECK\002: Successfully removed '$type'"
            } elseif {$text != ""} {
                variable config($type) $text
                putdcc $idx "\002RIPECHECK\002: Successfully added '$type' value '$text'"
            }
            ::ripecheck::writeSettings
        } else {
            _ripe_help_dcc $nick $idx ripebanr; return 0
        }
    }

    proc templateReplace { text subs } {
        foreach {arg1 arg2} $subs {
            regsub -all -- $arg1 $text $arg2 text
        }
        return $text
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
        close $fp
    }

    proc help { hand idx args } {
        switch -- $args {
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
                putidx $idx "### \002+ripetopresolv <channel> <pattern>\002"
                putidx $idx "    Add a top domain or regexp pattern that you want to resolve for"
                putidx $idx "    further ripe checking. It's possible that domains like com, info, org"
                putidx $idx "    could be from a country that is banned in the top domain list."
                putidx $idx "    Example (match .com): .+ripetopresolv #channel com"
                putidx $idx "    Example (match everything): .+ripetopresolv #channel .*" 
                putidx $idx "    Example (match .a-f*): .+ripetopresolv #channel \[a-f\]*"
                putidx $idx "### \002-ripetopresolv <channel> <pattern>\002"
                putidx $idx "    Remove a top resolve domain or regexp pattern from the channel that"
                putidx $idx "    you no longer wish to resolve."
                putidx $idx "### \002+ripetopdom <channel> <topdomain>\002"
                putidx $idx "    Add a top domain for the channel that you wish to ban"
                putidx $idx "    Example: .+ripetopdom #channel ro"
                putidx $idx "### \002-ripetopdom <channel> <topdomain>\002"
                putidx $idx "    Remove a top domain from the channel that you no longer"
                putidx $idx "    wish to ban"
                putidx $idx "### \002ripebanr <banreason|bantopreson> \[text\]\002"
                putidx $idx "    Set custom ban reasons for 'banreason' and 'bantopreason'."
                putidx $idx "    To restore the default message run the above command without \[text\]"
                putidx $idx "    The \[text\] support substitutional keywords, current keywords are:"
                putidx $idx "    %domain% = Topdomain used in 'bantopreason'"
                putidx $idx "    %ripe% = Country code from the whois server, used in 'banreason'"
                putidx $idx "    %nick% = Nickname for the user being banned, used in both 'banreason' and 'bantopreason'"
                putidx $idx "    Example (topdomain reason): .ripebanr bantopreason Hello '%nick%, TLD '%domain%' is not allowed here"
                putidx $idx "    Example (standard reason): .ripebanr banreason Sorry '%ripe' not allowed in here"
                putidx $idx "    Example (restore default ban reason): .ripebanr banreason"
                putidx $idx "### \002ripesettings\002"
                putidx $idx "    List current channel settings"
                putidx $idx "### \002testripecheck <channel> <host>\002"
                putidx $idx "    Test your settings against a specific channel, don't"
                putidx $idx "    forget to enable debug console to see the output"
                putidx $idx "    from testripecheck, ie .console +d"
                putidx $idx "### \002help ripecheck\002"
                putidx $idx "    This help page you're currently viewing"
            }
            +ripetopresolv { 
                putidx $idx "Usage: \002+ripetopresolv <channel> <pattern>\002"
                putidx $idx "       Add a top domain or regexp pattern that you want to resolve for"
                putidx $idx "       further ripe checking. It's possible that domains like com, info, org"
                putidx $idx "       could be from a country that is banned in the top domain list."
                putidx $idx "       Example (match .com): .+ripetopresolv #channel com"
                putidx $idx "       Example (match everything): .+ripetopresolv #channel .*" 
                putidx $idx "       Example (match .a-f*): .+ripetopresolv #channel \[a-f\]*"
            }
            -ripetopresolv { 
                putidx $idx "Usage: \002-ripetopresolv <channel> <pattern>\002"
                putidx $idx "       Remove a top resolve domain or regexp pattern from the channel that"
                putidx $idx "       you no longer wish to resolve."
            }
            +ripetopdom {
                putidx $idx "Usage: \002+ripetopdom <channel> <topdomain>\002"
                putidx $idx "       Add a top domain for the channel that you wish to ban"
                putidx $idx "       Example: .+ripetopdom #channel ro"
            }
            -ripetopdom {
                putidx $idx "Usage: \002-ripetopdom <channel> <topdomain>\002"
                putidx $idx "       Remove a top domain from the channel that you no longer"
                putidx $idx "       wish to ban"
            }
            ripebanr {
                putidx $idx "Usage: \002ripebanr <banreason|bantopreson> \[text\]\002"
                putidx $idx "       Set custom ban reasons for 'banreason' and 'bantopreason'."
                putidx $idx "       To restore the default message run the above command without \[text\]"
                putidx $idx "       The \[text\] support substitutional keywords, current keywords are:"
                putidx $idx "       %domain% = Topdomain used in 'bantopreason'"
                putidx $idx "       %ripe% = Country code from the whois server, used in 'banreason'"
                putidx $idx "       %nick% = Nickname for the user being banned, used in both 'banreason' and 'bantopreason'"
                putidx $idx "       Example (topdomain reason): .ripebanr bantopreason Hello '%nick%, TLD '%domain%' is not allowed here"
                putidx $idx "       Example (standard reason): .ripebanr banreason Sorry '%ripe' not allowed in here"
                putidx $idx "       Example (restore default ban reason): .ripebanr banreason"
            }
            testripecheck {
                putidx $idx "Usage: \002testripecheck <channel> <host>\002"
            }
            default {*dcc:help $hand $idx [join $args]; return 0}
        }
    }
}
putlog "ripecheck v$::ripecheck::version by Ratler loaded"
