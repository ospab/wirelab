//go:build ndpi && linux && cgo

package main

// The censor's protocol recognition, from nDPI (https://github.com/ntop/nDPI,
// LGPL-3.0). Pinned to 5.0: from 6.0 on, its TLS, QUIC and DNS dissectors
// are under ntop's dual licence and need a commercial agreement for
// for-profit use. Built in a container (containers/censor-build) and linked
// statically; the sources and that build file are what LGPL section 4 asks
// for to relink.

/*
#cgo LDFLAGS: -lndpi -lm
#include <stdlib.h>
#include <string.h>
#include <ndpi/ndpi_api.h>

static struct ndpi_detection_module_struct *wl_init(void) {
	struct ndpi_detection_module_struct *m = ndpi_init_detection_module(NULL);
	if (m == NULL) return NULL;
	if (ndpi_finalize_initialization(m) != 0) {
		ndpi_exit_detection_module(m);
		return NULL;
	}
	return m;
}

static struct ndpi_flow_struct *wl_flow_new(void) {
	struct ndpi_flow_struct *f = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
	if (f != NULL) memset(f, 0, SIZEOF_FLOW_STRUCT);
	return f;
}

typedef struct {
	unsigned short master, app;
	int state;
	unsigned int quic_version;
	char host[80];
	char ja4[37];
} wl_facts;

static int wl_is(unsigned short id, const wl_facts *o) {
	return o->master == id || o->app == id;
}

static void wl_process(struct ndpi_detection_module_struct *m, struct ndpi_flow_struct *f,
                       const unsigned char *pkt, unsigned short len, unsigned long long ms,
                       int dir, wl_facts *o) {
	struct ndpi_flow_input_info in;
	in.in_pkt_dir = (unsigned char)dir;
	in.seen_flow_beginning = 1;
	ndpi_protocol p = ndpi_detection_process_packet(m, f, pkt, len, ms, &in);
	o->master = p.proto.master_protocol;
	o->app = p.proto.app_protocol;
	o->state = p.state;
	memcpy(o->host, f->host_server_name, sizeof(o->host));
	o->host[sizeof(o->host) - 1] = 0;
	o->ja4[0] = 0;
	o->quic_version = 0;
	// protos is a union: tls_quic means something only for these.
	if (wl_is(NDPI_PROTOCOL_TLS, o) || wl_is(NDPI_PROTOCOL_QUIC, o) || wl_is(NDPI_PROTOCOL_DTLS, o)) {
		memcpy(o->ja4, f->protos.tls_quic.ja4_client, sizeof(o->ja4));
		o->ja4[sizeof(o->ja4) - 1] = 0;
		o->quic_version = f->protos.tls_quic.quic_version;
	}
}

static const char *wl_name(struct ndpi_detection_module_struct *m, unsigned short id) {
	return ndpi_get_proto_name(m, id);
}
*/
import "C"

import (
	"strings"
	"time"
	"unsafe"
)

type ndpiClassifier struct {
	mod   *C.struct_ndpi_detection_module_struct
	flows map[FlowKey]*C.struct_ndpi_flow_struct
}

func defaultClassifier() Classifier {
	m := C.wl_init()
	if m == nil {
		// Without nDPI the censor still runs, on first bytes; its start line
		// names the classifier, so this does not pass unnoticed.
		return newBuiltinClassifier()
	}
	return &ndpiClassifier{mod: m, flows: map[FlowKey]*C.struct_ndpi_flow_struct{}}
}

func (n *ndpiClassifier) Name() string { return "nDPI " + C.GoString(C.ndpi_revision()) }
func (n *ndpiClassifier) Caps() Caps   { return Caps{QUICSNI: true, JA4: true, DNS: true} }

func (n *ndpiClassifier) Forget(k FlowKey) {
	if f, ok := n.flows[k]; ok {
		C.ndpi_free_flow(f)
		delete(n.flows, k)
	}
}

// Names the rules use for nDPI's protocol ids.
var ndpiNames = map[string]string{
	"TLS": "TLS", "QUIC": "QUIC", "SSH": "SSH", "RDP": "RDP", "WireGuard": "WireGuard",
	"OpenVPN": "OpenVPN", "DNS": "DNS", "DTLS": "DTLS", "HTTP": "HTTP", "Unknown": "Unknown",
}

func (n *ndpiClassifier) Observe(p Packet, now time.Time) Facts {
	f := n.flows[p.Key]
	if f == nil {
		f = C.wl_flow_new()
		if f == nil {
			return Facts{}
		}
		n.flows[p.Key] = f
	}
	var o C.wl_facts
	dir := 0
	if p.Dir == dirS2C {
		dir = 1
	}
	C.wl_process(n.mod, f, (*C.uchar)(unsafe.Pointer(&p.Raw[0])), C.ushort(len(p.Raw)), C.ulonglong(now.UnixMilli()), C.int(dir), &o)
	facts := Facts{
		Host:        strings.ToLower(C.GoString(&o.host[0])),
		JA4:         C.GoString(&o.ja4[0]),
		QUICVersion: uint32(o.quic_version),
		// MONITORING and CLASSIFIED: nDPI will not change its mind.
		Done: o.state >= 2,
	}
	// The application protocol (e.g. a site over TLS) sits on a master
	// (TLS); the rules want the carrier.
	for _, id := range []C.ushort{o.master, o.app} {
		if id == 0 {
			continue
		}
		if name, ok := ndpiNames[C.GoString(C.wl_name(n.mod, id))]; ok {
			facts.Proto = name
			break
		}
	}
	if facts.Proto == "" && facts.Done {
		facts.Proto = "Unknown"
	}
	return facts
}
