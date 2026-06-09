// geoip-gen builds the small synthetic MaxMind databases the GeoIP integration
// suite (33-ebpf-geoip-scenarios) needs to run without a real GeoLite2 license.
//
// Three files are written to the parent fixtures directory:
//   - GeoLite2-City.mmdb     country.iso_code per network (what the agent reads)
//   - GeoLite2-ASN.mmdb      autonomous_system_number / _organization per network
//   - GeoLite2-Country.mmdb  the suite's skip-guard sentinel (also a valid DB)
//
// The mappings are chosen so the suite's assertions actually fire:
//   - 10.200.0.0/24 -> KP   the netns source range (EBPF_NS_IP=10.200.0.2); makes
//                           the firewall geo-deny-kp rule match local test traffic.
//   - 192.168.56.0/24 -> CU the 2-VM attacker range; geo-deny-cu under 2-VM lane.
//   - 8.8.8.8/32 -> US      the /api/v1/geoip/lookup?ip=8.8.8.8 assertion (== "US").
//   - 1.0.1.0/24 -> CN      a ratelimit country tier sanity range.
//
// Build/run: `go run .` from this directory (regenerates the *.mmdb fixtures).
package main

import (
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

type geo struct {
	cidr    string
	country string // ISO 3166-1 alpha-2
	asn     uint32
	asnOrg  string
}

// One row per network. Kept tiny on purpose — these are test fixtures.
var rows = []geo{
	{"10.200.0.0/24", "KP", 65001, "ebpfsentinel-test-kp"},
	{"192.168.56.0/24", "CU", 65002, "ebpfsentinel-test-cu"},
	{"1.0.1.0/24", "CN", 4134, "Chinanet"},
	{"8.8.8.0/24", "US", 15169, "Google LLC"},
}

func cityRecord(country string) mmdbtype.Map {
	return mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String(country),
			"names":    mmdbtype.Map{"en": mmdbtype.String(country)},
		},
		"registered_country": mmdbtype.Map{
			"iso_code": mmdbtype.String(country),
			"names":    mmdbtype.Map{"en": mmdbtype.String(country)},
		},
	}
}

func countryRecord(country string) mmdbtype.Map {
	return mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String(country),
			"names":    mmdbtype.Map{"en": mmdbtype.String(country)},
		},
	}
}

func asnRecord(asn uint32, org string) mmdbtype.Map {
	return mmdbtype.Map{
		"autonomous_system_number":       mmdbtype.Uint32(asn),
		"autonomous_system_organization": mmdbtype.String(org),
	}
}

func mustInsert(w *mmdbwriter.Tree, cidr string, rec mmdbtype.DataType) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("parse %s: %v", cidr, err)
	}
	if err := w.Insert(network, rec); err != nil {
		log.Fatalf("insert %s: %v", cidr, err)
	}
}

func build(dbType string, fill func(*mmdbwriter.Tree)) *mmdbwriter.Tree {
	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            dbType,
		RecordSize:              28,
		IncludeReservedNetworks: true, // 10.0.0.0/8 + 192.168.0.0/16 are reserved
	})
	if err != nil {
		log.Fatalf("new %s: %v", dbType, err)
	}
	fill(w)
	return w
}

func write(w *mmdbwriter.Tree, path string) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
	log.Printf("wrote %s", path)
}

func main() {
	outDir, err := filepath.Abs("..")
	if err != nil {
		log.Fatal(err)
	}

	city := build("GeoLite2-City", func(w *mmdbwriter.Tree) {
		for _, r := range rows {
			mustInsert(w, r.cidr, cityRecord(r.country))
		}
	})
	write(city, filepath.Join(outDir, "GeoLite2-City.mmdb"))

	asn := build("GeoLite2-ASN", func(w *mmdbwriter.Tree) {
		for _, r := range rows {
			mustInsert(w, r.cidr, asnRecord(r.asn, r.asnOrg))
		}
	})
	write(asn, filepath.Join(outDir, "GeoLite2-ASN.mmdb"))

	country := build("GeoLite2-Country", func(w *mmdbwriter.Tree) {
		for _, r := range rows {
			mustInsert(w, r.cidr, countryRecord(r.country))
		}
	})
	write(country, filepath.Join(outDir, "GeoLite2-Country.mmdb"))
}
