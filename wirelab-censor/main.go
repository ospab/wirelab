// wl-censor: a censor model for the wirelab wire zone.
//
// Two ways to run it:
//
//   - as the lab's router (Linux, inside the wire container): the kernel does
//     not forward, frames are read from both interfaces with AF_PACKET, judged
//     by the active preset and written out the other side; netem on the egress
//     qdiscs still applies below;
//   - over a capture file (-replay, any OS): every packet is judged as if it
//     had passed through, and the decisions are reported.
//
// Every decision names the rule that made it and the rule's source, so a
// blocked connection traces back to a documented censor behaviour rather
// than to something this program made up.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
)

func main() {
	ifc := flag.String("client-if", "", "router: interface facing the client network")
	ifs := flag.String("server-if", "", "router: interface facing the server network")
	preset := flag.String("preset", "/out/censor-preset.json", "preset file; the router rereads it when it changes, absent means pass-through")
	logPath := flag.String("log", "/out/censor.jsonl", "decision log (router), or where -replay also writes decisions (default: none)")
	clientNet := flag.String("client-net", "10.77.1.0/24", "addresses on the client side")
	serverNet := flag.String("server-net", "10.77.2.0/24", "addresses on the server side")
	replay := flag.String("replay", "", "judge the packets of this pcap or pcapng file and report")
	flag.Parse()

	_, cnet, err := net.ParseCIDR(*clientNet)
	fail(err)
	_, snet, err := net.ParseCIDR(*serverNet)
	fail(err)

	if *replay != "" {
		out := ""
		if isSet("log") {
			out = *logPath
		}
		fail(runReplay(*replay, *preset, out, cnet, snet, os.Stdout))
		return
	}
	if *ifc == "" || *ifs == "" {
		fail(fmt.Errorf("router mode needs -client-if and -server-if; to judge a capture file use -replay"))
	}
	fail(route(*ifc, *ifs, *preset, *logPath, cnet, snet))
}

func isSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "wl-censor:", err)
		os.Exit(1)
	}
}
