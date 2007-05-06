#
# ripecheck.tcl  Version: 0.7  Author: Stefan Wold <ratler@gmail.com>
###
# Info: 
# This script check unresolved ip addresses against a RIPE database
# and ban the user if the country match your configured topdomains.
###
# Usage:
# Simply load the script and change the topdomains you
# wish to ban. You can test ip addresses from dcc console by
# enabling debug output (.console +d) and running .testripecheck ip
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
###
# Tested:
# eggdrop v1.6.18 GNU/Linux with tcl 8.4, http 2.5 and tcllib 1.8
# eggdrop v1.6.17 GNU/Linux with tcl 8.4, http 2.5 and tcllib 1.8
###
# TODO:
# - Per channel settings
# - Change configuration through dcc console
# - Check if it possible to add code to handle lookup against LACNIC  
###
# ChangeLog:
# 0.7: New dependency added, tcllib.
#      Ripecheck will now try to guess which whois database
#      to use, it should now be a lot more accurate when banning.
#      Whois databases supported now are:
#      RIPE, APNIC, ARIN, AFRINIC, VERIO
# 0.6: New function to resolve some topdomains and then
#      do a ripecheck. Topdomains like .com .info might
#      match countries in your topdomain list.
#      It's also possible to change timeout for the RIPE
#      query, recommended setting is default 5 seconds.
#      Saving a few cpu cycles by breaking loops when a match
#      was found.
# 0.5: Added better error handling during the http query.
#      Added channel flags so it's possible to enable/disable
#      ripecheck per channel.
# 0.4: Changed to using http package instead of sockets.
#      Added configuration option for ban time 
# 0.2: First release (not public)
###
# LICENSE:
# Copyright (C) 2006, 2007  Stefan Wold <ratler@gmail.com>
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

# Space separated list of topdomains you want to ban, see example below
#set topdomains { "ro" "ma" "tr" }
set topdomains { }

# Space separated list of top domains to resolv to be further checked by RIPE.
# For example .com could resolv to an ip located in the countries you wish to
# have banned defined by topdomains.
#set topresolv { "com" "info" "net" }
set topresolv { }

# RIPE query timeout setting, default 5 seconds
set rtimeout 5

# Path to netmask file
set iplistfile "scripts/iplist.txt"

# ---- Only edit stuff below this line if you know what you are doing ----
set ver "0.7"

# Channel flags
setudef flag ripecheck
setudef flag ripecheck.topchk
setudef int ripecheck.bantime

# Packages
package require http 2.5
package require ip

# Bindings
bind join - *!*@* ripecheck_onjoin
bind dcc -|- testripecheck _testripecheck

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
	
	regexp {^([0-9\.\/]+)[[:space:]]+([a-z]+)} $line dummy mask whoisdb
	lappend maskarray $mask
	set maskhash($mask) $whoisdb
    }
    close $fid
    putloglev d * "ripecheck: DEBUG - IP file loaded with [llength $maskarray] netmasks"
}


# Functions
proc ripecheck_onjoin { nick host handle channel } {
    global topresolv
    
    # Only run if channel is defined
    if {![channel get $channel ripecheck]} { return 0 }
    
    # Exclude ops, voice, friends
    if {[matchattr $handle fov|fov $channel]} { 
	putloglev d * "ripecheck: $nick is on exempt list"
	return 0 
     }

    # Only run RIPE check on numeric IP unless ripecheck.topchk
    # is enabled
    regexp ".+@(.+)" $host matches iphost
    if {[regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $iphost]} {
	putloglev d * "ripecheck: DEBUG - Found numeric IP $iphost ... scanning"
	ripecheck $iphost $iphost 1 $nick $channel $host
    } elseif {[channel get $channel ripecheck.topchk]} {
	putloglev d * "ripecheck: DEBUG - Trying to resolve host ..."

	set htopdom [lindex [split $iphost "."] end]
	foreach domain $topresolv {
	    putloglev d * "ripecheck: DEBUG - domain: $domain ip: $iphost"
	    if {![string compare $htopdom $domain]} {
		putloglev d * "ripecheck: DEBUG - Matched resolve domain .$domain"
		dnslookup $iphost ripecheck $nick $channel $host
		# Break the loop since we found a match
		break
	    }
	}
    }
}

proc ripecheck { ip host status nick channel orghost } {
    global topdomains
    
    set ripe [get_html $ip]
    set bantime [channel get $channel ripecheck.bantime]
    foreach country $topdomains {
	if {![string compare $ripe $country]} {
	    putlog "ripecheck: Matched country '$ripe' banning $nick!$orghost for $bantime minute(s)"
	    newchanban $channel "*!*@$host" ripecheck "RIPE Country Check: Matched .$ripe" $bantime
	    # Break the loop since we found a match
	    break
	}
    }
}

proc _testripecheck { nick idx args } {
    global topresolv

    set ip [lindex [split $args] 0]

    if {[regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]} {
	testripecheck $ip $ip 1
    } else {
	putloglev d * "ripecheck: DEBIG - Resolving..."
	set htopdom [lindex [split $ip "."] end]
	foreach domain $topresolv {
	    putloglev d * "ripecheck: DEBUG - domain: $domain ip: $ip"
	    if {![string compare $htopdom $domain]} {
		putloglev d * "ripecheck: DEBUG - Matched resolv domain .$domain"
		dnslookup $ip testripecheck
		# Break the loop since we found a match
		break
	    }
	}
    }
}

proc testripecheck { ip host status } {
    global topdomains

    set ripe [get_html $ip]
    foreach country $topdomains {
	if {![string compare $ripe $country]} {
	    putloglev d * "ripecheck: DEBUG - Matched '$ripe' for $ip"
	    # Break the loop since we found a match
	    break
	}
    }
}

proc get_html { iphost } {
    global rtimeout
    global maskhash
    global maskarray
    
    set matchmask [::ip::longestPrefixMatch $iphost $maskarray]
    set whoisdb [string toupper $maskhash($matchmask)]

    putloglev d * "ripecheck: DEBUG - Matching mask $matchmask using whois DB: $whoisdb"

    set query "http://www.ripe.net/fcgi-bin/whois?form_type=simple&full_query_string=&searchtext=${iphost}&submit.x=0&submit.y=0&alt_database=$whoisdb"
    set useragent "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20040120 Firebird/0.7"
    set http [::http::config -useragent $useragent]
    catch {set http [::http::geturl $query -timeout [expr 1000 * $rtimeout]]} error
    
    if {[::http::status $http] == "timeout"} {
	putlog "ripecheck: Error - Connection timed out!"
	::http::cleanup $http
	return 0
    }
    if {[string match -nocase "*couldn't open socket*" $error]} {
	putlog "ripecheck: Error - Connection to ripe failed!"
	::http::cleanup $http
	return 0
    }

    set output [::http::data $http]
    ::http::cleanup $http
 
    if {[regexp -line -nocase {country:\s*([a-z]{2,4})} $output -> line]} {
	set line [string tolower $line]
	putloglev d * "ripecheck: DEBUG - $whoisdb answer: $line"
	return $line
    }
    return ""
}

putlog "ripecheck v$ver by Ratler loaded"
