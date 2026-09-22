package policy

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// ListsDir holds the static lists of a generation next to its profiles, one <name>.txt per list,
// one value per line. The leading dot keeps it out of the profile scan.
const ListsDir = ".lists"

// staticSet is a static list as a condition looks values up in it: strings as they are, or, for
// an address list (type: cidr), prefixes by length, the way the mirror keeps a dynamic one.
type staticSet struct {
	values map[string]struct{}
	nets   map[netip.Prefix]struct{}
	lens   [2][129]int
}

func (s *staticSet) contains(value string) bool {
	_, ok := s.values[value]

	return ok
}

func (s *staticSet) containsAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	fam := 0

	if !ip.Is4() {
		fam = 1
	}

	for bits := ip.BitLen(); bits >= 0; bits-- {
		if s.lens[fam][bits] == 0 {
			continue
		}

		if _, ok := s.nets[netip.PrefixFrom(ip, bits).Masked()]; ok {
			return true
		}
	}

	return false
}

// readStatic reads a list body. An address list takes an address (a /32 or /128) or a prefix per
// line; a line that is neither fails the load, as the controller keeps only valid entries.
func readStatic(path string, addr bool) (*staticSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	s := &staticSet{values: map[string]struct{}{}, nets: map[netip.Prefix]struct{}{}}
	lines := bufio.NewScanner(bytes.NewReader(raw))
	lines.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for n := 1; lines.Scan(); n++ {
		v := strings.TrimSpace(lines.Text())

		if v == "" {
			continue
		}

		if !addr {
			s.values[v] = struct{}{}

			continue
		}

		p, err := netip.ParsePrefix(v)
		if err != nil {
			a, aerr := netip.ParseAddr(v)
			if aerr != nil {
				return nil, fmt.Errorf("line %d: %q is neither an address nor a prefix", n, v)
			}

			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}

		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()

		if _, had := s.nets[p]; !had {
			s.nets[p] = struct{}{}
			s.lens[family(p)][p.Bits()]++
		}
	}

	if err := lines.Err(); err != nil {
		return nil, err
	}

	return s, nil
}

func family(p netip.Prefix) int {
	if p.Addr().Is4() {
		return 0
	}

	return 1
}

// loadStatic reads the static lists the conditions of the profiles look values up in. A list that
// is named by a condition and missing on disk fails the load: the generation came without its
// data.
func loadStatic(dir string, profiles map[string]*Profile) error {
	sets := map[string]*staticSet{}

	for _, name := range Names(profiles) {
		p := profiles[name]

		for _, cname := range sortedKeys(p.Conditions) {
			c := p.Conditions[cname]

			for i := range c.Clauses {
				cl := &c.Clauses[i]

				if !cl.Static {
					continue
				}

				key := cl.Dataset

				if cl.Addr {
					key += "\x00cidr"
				}

				set, ok := sets[key]

				if !ok {
					var err error

					set, err = readStatic(filepath.Join(dir, ListsDir, cl.Dataset+".txt"), cl.Addr)
					if err != nil {
						return fmt.Errorf("%s: condition %s: static list %q: %w", name, cname, cl.Dataset, err)
					}

					sets[key] = set
				}

				cl.static = set
			}
		}
	}

	return nil
}
