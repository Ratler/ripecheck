#
# ripecheck.tcl  Version: 2.3  Author: Stefan Wold <ratler@stderr.eu>
###
# Info:
# This script check unresolved ip addresses against a RIPE database
# and ban the user if the country match your configured top domains.
# Features:
# * Configuration through dcc console
# * Per channel settings
# * Can handle top domain banning for name based hosts
# * Custom bantime (global)
# * Support extra resolving for domains like info, com, net, org
#   to find hosts that actually have an ip from a country
#   you wish to ban.
###
# Require / Depends:
# tcllib 1.8
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
# +ripetopresolv <channel> <resolvdomain>
# Add a top domain that you want to resolve for further
# ripe checking. It's possible that domains like com, info,
# org could be from a country that is banned in the top
# domain list.
# Example: .+ripetopresolv #channel com
#
# -ripetopresolv <channel> <resolvdomain>
# Remove a top resolve domain from the channel that you no longer
# wish to resolve for further ripe checking.
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
# Copyright (C) 2006 - 2008  Stefan Wold <ratler@stderr.eu>
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

# --- Settings ---

# RIPE query timeout setting, default 5 seconds
set rtimeout 5

# Path to netmask file
set iplistfile "scripts/iplist.txt"

# Path to channel settings file
set ripechanfile "ripecheckchan.dat"

# ---- Only edit stuff below this line if you know what you are doing ----
set ver "2.3"

# Channel flags
setudef flag ripecheck
setudef flag ripecheck.topchk
setudef flag ripecheck.topban
setudef flag ripecheck.pubcmd
setudef int ripecheck.bantime

# Packages
package require ip

# Bindings
bind join - *!*@* _ripecheck_onjoin
bind dcc -|- testripecheck _testripecheck
bind dcc m|ov +ripetopdom _+ripetopdom
bind dcc m|ov -ripetopdom _-ripetopdom
bind dcc m|ov +ripetopresolv _+ripetopresolv
bind dcc m|ov -ripetopresolv _-ripetopresolv
bind dcc -|- ripesettings _ripesettings
bind dcc -|- help _ripe_help_dcc
bind pub -|- !ripecheck _pubripecheck

# Global variables
set maskarray [list]

# Parse ip list file
if {[file exists $iplistfile]} {
    set fid [open $iplistfile r]
    while { ![eof $fid] } {
        gets $fid line
        if {[regexp {^\#} $line]} {
            continue
        }
        regexp {^([0-9\.\/]+)[[:space:]]+([a-z\.]+)} $line dummy mask whoisdb
        lappend maskarray $mask
        set maskhash($mask) $whoisdb
    }
    close $fid
    putloglev d * "ripecheck: DEBUG - IP file loaded with [llength $maskarray] netmasks"
}

# Read channel settings - only at startup
if {[file exists $ripechanfile]} {
    set fchan [open $ripechanfile r]
    while { ![eof $fchan] } {
        gets $fchan line
        if {[regexp {^\#} $line]} {
            set chanarr([lindex [split $line :] 0]) [split [lindex [split $line :] 1] ,]
        } elseif {[regexp {^topresolv} $line]} {
            set topresolv([lindex [split $line :] 1]) [split [lindex [split $line :] 2] ,]
        }
    }
    close $fchan
    putloglev d * "ripecheck: DEBUG - Channel file loaded with settings for [array size chanarr] channel(s)"
    putloglev d * "ripecheck: DEBUG - Top resolv domains loaded for [array size topresolv] channel(s)"
}

# Functions
proc _ripecheck_onjoin { nick host handle channel } {
    global topresolv chanarr

    # Only run if channel is defined
    if {![channel get $channel ripecheck]} { return 0 }

    # Exclude ops, voice, friends
    if {[matchattr $handle fov|fov $channel]} {
        putloglev d * "ripecheck: $nick is on exempt list"
        return 0
    }

    # Check if channel has a domain list or complain about it and then abort
    if {![info exists chanarr($channel)]} {
        putlog "ripecheck: Ripecheck is enabled but $channel has no domain list!"
        return 0
    }

    # Get IP/Host part
    regexp ".+@(.+)" $host matches iphost

    # Top domain ban if enabled
    if {[channel get $channel ripecheck.topban]} {
        set htopdom [lindex [split $iphost "."] end]
        foreach domain $chanarr($channel) {
            if {![string compare $htopdom $domain]} {
                set bantime [channel get $channel ripecheck.bantime]
                putlog "ripecheck: Matched top domain '$domain' banning *!*.$domain for $bantime minute(s)"
                newchanban $channel "*!*@*.$domain" ripecheck "RIPE Country Check: Top domain .$domain is banned." $bantime
                # Break the loop since we found a match
                break
            }
        }
    }

    # Only run RIPE check on numeric IP unless ripecheck.topchk is enabled
    if {[regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $iphost]} {
        putloglev d * "ripecheck: DEBUG - Found numeric IP $iphost ... scanning"
        whois_connect $iphost $iphost 1 $nick $channel $host 0
    } elseif {[channel get $channel ripecheck.topchk]} {
        # Check if channel has a resolv domain list or complain about it and then abort
        if {![info exists topresolv($channel)]} {
            putlog "ripecheck: Ripecheck is enabled but $channel has no resolv domain list!"
            return 0
        }

        putloglev d * "ripecheck: DEBUG - Trying to resolve host ..."

        set htopdom [lindex [split $iphost "."] end]
        foreach domain $topresolv($channel) {
            putloglev d * "ripecheck: DEBUG - domain: $domain ip: $iphost"
            if {![string compare $htopdom $domain]} {
                putloglev d * "ripecheck: DEBUG - Matched resolve domain .$domain"
                dnslookup $iphost whois_connect $nick $channel $host 0
                # Break the loop since we found a match
                break
            }
        }
    }
}

proc ripecheck { ip host nick channel orghost ripe } {
    global chanarr

    #set ripe [get_html $ip]
    set bantime [channel get $channel ripecheck.bantime]
    foreach country $chanarr($channel) {
        if {![string compare $ripe $country]} {
            putlog "ripecheck: Matched country '$ripe' banning $nick!$orghost for $bantime minute(s)"
            newchanban $channel "*!*@$host" ripecheck "RIPE Country Check: Matched .$ripe" $bantime
            # Break the loop since we found a match
            break
        }
    }
}

proc _testripecheck { nick idx arg } {
    global topresolv

    if {[llength [split $arg]] != 2} {
        _ripe_help_dcc $nick $idx testripecheck; return 0
    }

    foreach {channel ip} $arg {break}
    set ip [string tolower $ip]

    if {[validchan $channel]} {
        if {[regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]} {
            whois_connect $ip "" ""  $nick $channel "" 1
        } else {
            putloglev d * "ripecheck: DEBIG - Resolving..."
            set htopdom [lindex [split $ip "."] end]
            foreach domain $topresolv($channel) {
                putloglev d * "ripecheck: DEBUG - channel: $channel domain: $domain ip: $ip top domain: $htopdom"
                if {![string compare $htopdom $domain]} {
                    putloglev d * "ripecheck: DEBUG - Matched resolve domain .$domain for $channel"
                    dnslookup $ip whois_connect $nick $channel "" 1
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
    global chanarr
    putloglev d * "ripecheck: DEBUG - Got country: $ripe"
    foreach country $chanarr($channel) {
        if {![string compare $ripe $country]} {
            putloglev d * "ripecheck: DEBUG - Matched '$ripe' for $ip on channel $channel."
            # Break the loop since we found a match
            break
        }
    }
}
proc _pubripecheck { nick host handle channel ip } {
    if {![channel get $channel ripecheck.pubcmd]} { return 0 }

    if {[regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]} {
        whois_connect $ip $ip "" $nick $channel "" 2
    } else {
        dnslookup $ip whois_connect $nick $channel "" 2
    }
}

proc whois_connect { ip host status nick channel orghost test } {
    global maskhash maskarray rtimeout

    set matchmask [::ip::longestPrefixMatch $ip $maskarray]
    set whoisdb [string tolower $maskhash($matchmask)]

    if { $whoisdb == "unallocated" } {
        putlog "ripecheck: Unallocated netmask, bailing out!"
        return -1
    }

    # Setup timeout
    after $rtimeout * 1000 set ::state "timeout"

    putloglev d * "ripecheck: DEBUG - Matching mask $matchmask using whois DB: $whoisdb"

    if {[catch {socket -async $whoisdb 43} sock]} {
        putlog "ripecheck: ERROR: Failed to connect to server $whoisdb!" ; return -1
    }
    fconfigure $sock -buffering line
    fileevent $sock writable [list whois_callback $ip $host $nick $channel $orghost $sock $whoisdb $test]
    vwait ::state
    if { $::state == "timeout" } {
        putlog "ripecheck: ERROR: Connection timeout against $whoisdb"; return -1
    }
}

proc whois_callback { ip host nick channel orghost sock whoisdb test } {
    global ::state

    if {[string equal {} [fconfigure $sock -error]]} {
        puts $sock $ip
        flush $sock

        set ::state "connected"
        while {![eof $sock]} {
            set row [gets $sock]
            if {[regexp -line -nocase {country:\s*([a-z]{2,4})} $row -> line]} {
                set line [string tolower $line]
                putloglev d * "ripecheck: DEBUG - $whoisdb answer: $line Test: $test"

                if { $test == 1 } {
                    testripecheck $ip $host $channel $line
                } elseif { $test == 2 } {
                    puthelp "PRIVMSG $channel :ripecheck: $host is located in .$line"
                } else {
                    ripecheck $ip $host $nick $channel $orghost $line
                }
                break
            }
        }
        close $sock
    } else {
        set ::state "timeout"
    }
}

# Add top resolv domain for channel and write settings to file
proc _+ripetopresolv { nick idx arg } {
    global chanarr topresolv

    if {[llength [split $arg]] != 2} {
        _ripe_help_dcc $nick $idx +ripetopresolv; return 0
    }

    foreach {channel topdom} $arg {break}

    set topdom [string tolower $topdom]

    if {[validchan $channel]} {
        # It's pointless to set a resolv domain if no domains have been added for banning on the
        # current channel.
        if {[info exists chanarr($channel)]} {
            # If data exist extract into a list
            if {[info exists topresolv($channel)]} {
                putloglev d * "ripecheck: DEBUG - topresolv exists"
                set dlist $topresolv($channel)
                # top domain doesn't exist so lets add it
                if {[lsearch -exact $dlist $topdom] == -1 } {
                    lappend dlist $topdom
                    set topresolv($channel) $dlist
                } else {
                    putdcc $idx "\002RIPECHECK\002: Resolve domain '$topdom' already exist on $channel"; return 0
                }
            } else {
                putloglev d * "ripecheck: DEBUG - topresolv doesn't exist"
                set dlist [list $topdom]
                set topresolv($channel) $dlist
            }
            # Write to the ripecheck channel file
            write_settings [array get chanarr] [array get topresolv]
            putdcc $idx "\002RIPECHECK\002: Top resolve domain '$topdom' successfully added to $channel."
        } else {
            putdcc $idx "\002RIPECHECK\002: You need to add a top domain for $channel before adding a resolve domain."
        }
    } else {
        putdcc $idx "\002RIPECHECK\002: Invalid channel: $channel"
    }
}

# Remove resolve domain from channel and write settings to file
proc _-ripetopresolv { nick idx arg } {
    global chanarr topresolv

    if {[llength [split $arg]] != 2} {
        _ripe_help_dcc $nick $idx -ripetopresolv; return 0
    }

    foreach {channel topdom} $arg {break}

    set topdom [string tolower $topdom]

    if {[validchan $channel]} {
        if {[info exists topresolv($channel)]} {
            putloglev d * "ripecheck: DEBUG - topresolv($channel) exists"
            set dlist $topresolv($channel)
            # resolve domain exist so lets remove it
            set dlist_index [lsearch -exact $dlist $topdom]
            if {$dlist_index != -1 } {
                set dlist [lreplace $dlist $dlist_index $dlist_index]
                # More magic, lets clear array if the list is empty
                if {[llength $dlist] > 0} {
                    set topresolv($channel) $dlist
                } else {
                    unset topresolv($channel)
                }
            } else {
                putdcc $idx "\002RIPECHECK\002: Resolve domain '$topdom' doesn't exist on $channel"; return 0
            }

        } else {
            putdcc $idx "\002RIPECHECK\002: Nothing to do, no settings found for $channel."
        }
        # Write to the ripecheck channel file
        write_settings [array get chanarr] [array get topresolv]
        putdcc $idx "\002RIPECHECK\002: Resolve domain '$topdom' successfully removed from $channel."

    } else {
        putdcc $idx "\002RIPECHECK\002: Invalid channel: $channel"
    }
}

# List channel and top resolv domains
proc _ripesettings { nick idx arg } {
    global chanarr topresolv

    if {[array size chanarr] > 0 && [array size topresolv] > 0} {
        putdcc $idx "\002RIPECHECK\002: ---------------- CURRENT SETTINGS ----------------"
        foreach channel [array names chanarr] {
            putdcc $idx "\002RIPECHECK\002: Channel: $channel   Banned domains: $chanarr($channel)   Resolve domains: $topresolv($channel)"
        }
    } else {
        putdcc $idx "\002RIPECHECK\002: No channel settings made yet."
    }
}

# Add top domain to channel and write settings to file
proc _+ripetopdom { nick idx arg } {
    global chanarr topresolv

    if {[llength [split $arg]] != 2} {
        _ripe_help_dcc $nick $idx +ripetopdom; return 0
    }

    foreach {channel topdom} $arg {break}

    set topdom [string tolower $topdom]

    if {[validchan $channel]} {
        # If data exist extract into a list
        if {[info exists chanarr($channel)]} {
            putloglev d * "ripecheck: DEBUG - chanarr exists"
            set dlist $chanarr($channel)
            # top domain doesn't exist so lets add it
            if {[lsearch -exact $dlist $topdom] == -1 } {
                lappend dlist $topdom
                set chanarr($channel) $dlist
            } else {
                putdcc $idx "\002RIPECHECK\002: Domain '$topdom' already exist on $channel"; return 0
            }
        } else {
            putloglev d * "ripecheck: DEBUG - chanarr doesn't exist"
            set dlist [list $topdom]
            set chanarr($channel) $dlist
        }
        # Write to the ripecheck channel file
        write_settings [array get chanarr] [array get topresolv]
        putdcc $idx "\002RIPECHECK\002: Top domain '$topdom' successfully added to $channel."
    } else {
        putdcc $idx "\002RIPECHECK\002: Invalid channel: $channel"
    }
}

# Remove top domain for channel and write settings to file
proc _-ripetopdom { nick idx arg } {
    global chanarr topresolv

    if {[llength [split $arg]] != 2} {
        _ripe_help_dcc $nick $idx -ripetopdom; return 0
    }

    foreach {channel topdom} $arg {break}

    set topdom [string tolower $topdom]

    if {[validchan $channel]} {
        if {[info exists chanarr($channel)]} {
            putloglev d * "ripecheck: DEBUG - chanarr($channel) exists"
            set dlist $chanarr($channel)
            # top domain doesn't exist so lets add it
            set dlist_index [lsearch -exact $dlist $topdom]
            if {$dlist_index != -1 } {
                set dlist [lreplace $dlist $dlist_index $dlist_index]
                # More magic, clear array if list is empty
                if {[llength $dlist] > 0} {
                    set chanarr($channel) $dlist
                } else {
                    unset chanarr($channel)
                }
            } else {
                putdcc $idx "\002RIPECHECK\002: Domain '$topdom' doesn't exist on $channel"; return 0
            }

        } else {
            putdcc $idx "\002RIPECHECK\002: Nothing to do, no settings found for $channel."
        }
        # Write to the ripecheck channel file
        write_settings [array get chanarr] [array get topresolv]
        putdcc $idx "\002RIPECHECK\002: Top domain '$topdom' successfully removed from $channel."

    } else {
        putdcc $idx "\002RIPECHECK\002: Invalid channel: $channel"
    }
}

proc write_settings { thisarray thatarray } {
    global ripechanfile

    array set data $thisarray
    array set tresolv $thatarray

    # Backup file in case something goes wrong
    if {[file exists $ripechanfile]} {
        # Don't backup a zero byte file
        if {[file size $ripechanfile] > 0} {
            file copy -force $ripechanfile $ripechanfile.bak
        }
    }
    set fp [open $ripechanfile w]

    foreach key [array names data] {
        puts $fp "$key:[join $data($key) ,]"
    }
    foreach key [array names tresolv] {
        puts $fp "topresolv:$key:[join $tresolv($key) ,]"
    }
    close $fp
}

proc _ripe_help_dcc { hand idx args } {
    global ver

    switch -- $args {
        ripecheck {
            putidx $idx "### \002ripecheck v$ver\002 by Ratler ###"; putidx $idx ""
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
            putidx $idx "### \002+ripetopresolv <channel> <resolvdomain>\002"
            putidx $idx "    Add a top domain that you want to resolve for further"
            putidx $idx "    ripe checking. It's possible that domains like com, info, org"
            putidx $idx "    could be from a country that is banned in the top domain list."
            putidx $idx "    Example: .+ripetopresolv #channel com"
            putidx $idx "### \002-ripetopresolv <channel> <resolvdomain>\002"
            putidx $idx "    Remove a top resolve domain from the channel that you no longer"
            putidx $idx "    wish to resolve for further ripe checking."
            putidx $idx "### \002+ripetopdom <channel> <topdomain>\002"
            putidx $idx "    Add a top domain for the channel that you wish to ban"
            putidx $idx "    Example: .+ripetopdom #channel ro"
            putidx $idx "### \002-ripetopdom <channel> <topdomain>\002"
            putidx $idx "    Remove a top domain from the channel that you no longer"
            putidx $idx "    wish to ban"
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
            putidx $idx "Usage: \002+ripetopresolv <channel> <resolvdomain>\002"
            putidx $idx "       Add a top domain that you want to resolve for further"
            putidx $idx "       ripe checking. It's possible that domains like com, info, org"
            putidx $idx "       could be from a country that is banned in the top domain list."
            putidx $idx "       Example: .+ripetopresolv #channel com"
        }
        -ripetopresolv { 
            putidx $idx "Usage: \002-ripetopresolv <channel> <resolvdomain>\002"
            putidx $idx "       Remove a top resolve domain from the channel that you no longer"
            putidx $idx "       wish to resolve for further ripe checking."
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
        testripecheck {
            putidx $idx "Usage: \002testripecheck <channel> <host>\002"
        }
        default {*dcc:help $hand $idx [join $args]; return 0}
    }
}

putlog "ripecheck v$ver by Ratler loaded"
