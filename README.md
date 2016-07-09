# onion-graph
A Tor Network relay connectivity scanner: can every relay connect to every other relay?

onion-graph build a circuit between each pair of relays, generating a log line for each circuit. It is a work in progress: it only does basic connectivity tests.

scripting-onion-graph.txt has some shell script and notes about how this can be graphed. (But dot really doesn't like large graphs with ~5000 nodes.)

# Known Issues

* network load - running these tests as fast as you can puts significant load on the Tor network
  * onion-graph waits for each circuit to be built before building the next one. On fast guards, this builds a circuit every 1-2 seconds.
* what if a relay is down? How can you tell the difference between down and firewalled?
  * sometimes the error is different, particularly if the relay has been dropped from the consensus
  * onion-scan can optionally choose only Stable relays to minimise downtime
* making ~7000 connections through a single relay might overload it, particularly if it's low-bandwidth, file-descriptor limited, or behind a NAT box
  * onion-scan only connects to Fast relays
* connection testing is directional - sometimes relay A can initiate a connection to relay B, but relay B can't initiate a connection to relay A. But once they're connected, they can both exchange cells.
  * onion-graph records the order of each connection. Running multiple tests on different days with different connection orders should eventually reveal one-way connectivity issues. But this can be hidden by existing connections on popular relays.
* timing information can be used to analyse relay load or open circuits
  * onion-graph adds noise, rounds times, and sorts to destroy connection ordering in the log
* what if the run is interrupted?
  * onion-graph has no resume functionality
* what if the network condition is transient?
  * onion-graph has no retry functionality

# Related Work

detect_partitions.py in https://github.com/TheTorProject/bwscanner/

Write and run a clique reachability test
https://trac.torproject.org/projects/tor/ticket/19068

The current Tor bandwidth authority code
https://gitweb.torproject.org/torflow.git/

onion-graph is based on custom_path_selection.py from stem master >1.4.1 (git 373d56f8), which is under the LGPL 3.
