package winsys

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modDnsapi                       = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsGetCacheDataTable        = modDnsapi.NewProc("DnsGetCacheDataTable")
	dnsQueryNoWireQuery             = uint32(0x10) // answer from the local cache only, never send a packet
	dnsTypeA                 uint16 = 1
	dnsTypeAAAA              uint16 = 28
)

// DNS_CACHE_ENTRY as returned by the (undocumented but long-stable)
// DnsGetCacheDataTable export of dnsapi.dll.
type dnsCacheEntry struct {
	next       *dnsCacheEntry
	name       *uint16
	rtype      uint16
	dataLength uint16
	flags      uint32
}

// DNSCacheRecord is one name the machine resolved recently, with the
// addresses still held in the resolver cache.
type DNSCacheRecord struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips,omitempty"`
}

// DNSCache reads the Windows resolver cache. Everything comes from local
// memory: lookups are issued with DNS_QUERY_NO_WIRE_QUERY so that inspecting
// the cache never generates network traffic.
func DNSCache() []DNSCacheRecord {
	if procDnsGetCacheDataTable.Find() != nil {
		return nil
	}
	var head *dnsCacheEntry
	r, _, _ := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head)))
	if r == 0 || head == nil {
		return nil
	}

	index := make(map[string]int)
	var out []DNSCacheRecord
	for e, guard := head, 0; e != nil && guard < 20000; e, guard = e.next, guard+1 {
		if e.name == nil || (e.rtype != dnsTypeA && e.rtype != dnsTypeAAAA) {
			continue
		}
		name := windows.UTF16PtrToString(e.name)
		if name == "" {
			continue
		}
		i, ok := index[name]
		if !ok {
			i = len(out)
			index[name] = i
			out = append(out, DNSCacheRecord{Name: name})
		}
		for _, ip := range cachedAddresses(name, e.rtype) {
			if !contains(out[i].IPs, ip) {
				out[i].IPs = append(out[i].IPs, ip)
			}
		}
	}
	return out
}

func cachedAddresses(name string, qtype uint16) []string {
	var rec *windows.DNSRecord
	if err := windows.DnsQuery(name, qtype, dnsQueryNoWireQuery, nil, &rec, nil); err != nil || rec == nil {
		return nil
	}
	defer windows.DnsRecordListFree(rec, 1)

	var ips []string
	for r, guard := rec, 0; r != nil && guard < 256; r, guard = r.Next, guard+1 {
		switch r.Type {
		case dnsTypeA:
			ips = append(ips, net.IP(r.Data[:4]).String())
		case dnsTypeAAAA:
			ips = append(ips, net.IP(r.Data[:16]).String())
		}
	}
	return ips
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
