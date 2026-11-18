# NS-2 Simulation for Emergency Communication and Alert System (ECAS)
# Course Mapping: CO3 (TCP Reno vs UDP CBR, congestion, DropTail queues),
#                 CO4 (Distance Vector rtproto DV + link failure rtmodel-at),
#                 CO5 (ports, flows, packet trace).
#
# Usage: ns emergency.tcl [low|normal|heavy]

set load "normal"
if {$argc >= 1} {
    set load [lindex $argv 0]
}

set ns [new Simulator]
$ns rtproto DV

$ns color 1 Blue
$ns color 2 Red

set tracefile [open "real_trace_${load}.tr" w]
$ns trace-all $tracefile

set cwndfile [open "cwnd_${load}.tr" w]

# Load parameters (Low / Normal / Heavy)
if {$load eq "low"} {
    set cbr_rate "250kb"
    set cbr_pkt 512
    set tcp_rate "200kb"
    set tcp_window 16
} elseif {$load eq "heavy"} {
    set cbr_rate "2.4Mb"
    set cbr_pkt 1024
    set tcp_rate "2.0Mb"
    set tcp_window 48
} else {
    set cbr_rate "900kb"
    set cbr_pkt 768
    set tcp_rate "800kb"
    set tcp_window 32
}

# Same 8-node topology & CO5 IPv4 subnet plan as ECAS application (backend/db.py):
#   n(0) ECC_HQ       -> 10.0.0.10/24  (mask 255.255.255.0, gw 10.0.0.1) [ECC Core Subnet 10.0.0.0/24]
#   n(1) TOWER_NORTH  -> 10.0.1.11/24  (mask 255.255.255.0, gw 10.0.1.1) [Relay Subnet 10.0.1.0/24]
#   n(2) TOWER_SOUTH  -> 10.0.1.12/24  (mask 255.255.255.0, gw 10.0.1.1) [Relay Subnet 10.0.1.0/24]
#   n(3) SUBSTATION_A -> 10.0.1.13/24  (mask 255.255.255.0, gw 10.0.1.1) [Relay Subnet 10.0.1.0/24]
#   n(4) POLICE       -> 10.0.2.21/24  (mask 255.255.255.0, gw 10.0.2.1) [Responder Subnet 10.0.2.0/24]
#   n(5) FIRE         -> 10.0.2.22/24  (mask 255.255.255.0, gw 10.0.2.1) [Responder Subnet 10.0.2.0/24]
#   n(6) AMBULANCE    -> 10.0.2.23/24  (mask 255.255.255.0, gw 10.0.2.1) [Responder Subnet 10.0.2.0/24]
#   n(7) HOSPITAL     -> 10.0.2.24/24  (mask 255.255.255.0, gw 10.0.2.1) [Responder Subnet 10.0.2.0/24]
for {set i 0} {$i < 8} {incr i} {
    set n($i) [$ns node]
}

# Same 12 links, delays, bandwidths, and distinct DropTail queue-limits
$ns duplex-link $n(0) $n(1) 2.0Mb 12ms DropTail
$ns queue-limit $n(0) $n(1) 20
$ns queue-limit $n(1) $n(0) 20

$ns duplex-link $n(0) $n(2) 1.5Mb 18ms DropTail
$ns queue-limit $n(0) $n(2) 15
$ns queue-limit $n(2) $n(0) 15

$ns duplex-link $n(1) $n(3) 1.5Mb 10ms DropTail
$ns queue-limit $n(1) $n(3) 15
$ns queue-limit $n(3) $n(1) 15

$ns duplex-link $n(2) $n(3) 1.2Mb 14ms DropTail
$ns queue-limit $n(2) $n(3) 15
$ns queue-limit $n(3) $n(2) 15

$ns duplex-link $n(1) $n(4) 2.0Mb 8ms DropTail
$ns queue-limit $n(1) $n(4) 20
$ns queue-limit $n(4) $n(1) 20

$ns duplex-link $n(3) $n(4) 1.2Mb 15ms DropTail
$ns queue-limit $n(3) $n(4) 15
$ns queue-limit $n(4) $n(3) 15

$ns duplex-link $n(1) $n(5) 1.5Mb 15ms DropTail
$ns queue-limit $n(1) $n(5) 15
$ns queue-limit $n(5) $n(1) 15

$ns duplex-link $n(3) $n(5) 1.5Mb 10ms DropTail
$ns queue-limit $n(3) $n(5) 15
$ns queue-limit $n(5) $n(3) 15

$ns duplex-link $n(2) $n(6) 1.2Mb 12ms DropTail
$ns queue-limit $n(2) $n(6) 15
$ns queue-limit $n(6) $n(2) 15

$ns duplex-link $n(3) $n(6) 1.2Mb 14ms DropTail
$ns queue-limit $n(3) $n(6) 15
$ns queue-limit $n(6) $n(3) 15

$ns duplex-link $n(2) $n(7) 1.5Mb 16ms DropTail
$ns queue-limit $n(2) $n(7) 15
$ns queue-limit $n(7) $n(2) 15

$ns duplex-link $n(3) $n(7) 2.0Mb 11ms DropTail
$ns queue-limit $n(3) $n(7) 20
$ns queue-limit $n(7) $n(3) 20

# Flow 1: Reliable TCP Reno (ECC_HQ -> POLICE)
set tcp0 [new Agent/TCP/Reno]
$tcp0 set fid_ 1
$tcp0 set window_ $tcp_window
$tcp0 set packetSize_ 1000
$ns attach-agent $n(0) $tcp0

set sink0 [new Agent/TCPSink]
$ns attach-agent $n(4) $sink0
$ns connect $tcp0 $sink0

set cbr_tcp [new Application/Traffic/CBR]
$cbr_tcp set packetSize_ 1000
$cbr_tcp set rate_ $tcp_rate
$cbr_tcp attach-agent $tcp0

# Flow 2: Connectionless UDP CBR (ECC_HQ -> AMBULANCE)
set udp1 [new Agent/UDP]
$udp1 set fid_ 2
$ns attach-agent $n(0) $udp1

set null1 [new Agent/Null]
$ns attach-agent $n(6) $null1
$ns connect $udp1 $null1

set cbr_udp [new Application/Traffic/CBR]
$cbr_udp set packetSize_ $cbr_pkt
$cbr_udp set rate_ $cbr_rate
$cbr_udp attach-agent $udp1

# Trace TCP congestion window cwnd_ every 0.1s
proc record_cwnd {tcp_agent out_file} {
    global ns
    set now [$ns now]
    set cwnd [$tcp_agent set cwnd_]
    puts $out_file "$now $cwnd"
    $ns at [expr $now + 0.1] "record_cwnd $tcp_agent $out_file"
}

$ns at 0.2 "record_cwnd $tcp0 $cwndfile"
$ns at 0.5 "$cbr_tcp start"
$ns at 0.5 "$cbr_udp start"

# Link failure & recovery (Distance Vector rtProtoDV reroutes around n0-n1 failure)
$ns rtmodel-at 3.0 down $n(0) $n(1)
$ns rtmodel-at 6.0 up $n(0) $n(1)

$ns at 9.5 "$cbr_tcp stop"
$ns at 9.5 "$cbr_udp stop"

proc finish {} {
    global ns tracefile cwndfile
    $ns flush-trace
    close $tracefile
    close $cwndfile
    exit 0
}

$ns at 10.0 "finish"
$ns run

