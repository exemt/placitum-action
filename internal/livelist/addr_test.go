package livelist

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"
)

/* Redis в памяти: пакеты и объекты под ключами, как их кладёт keeper. */
type fakeBlobs struct {
	objs map[string][]byte
	fail bool
}

func (b *fakeBlobs) Object(_ context.Context, key string) ([]byte, error) {
	if b.fail {
		return nil, errors.New("redis down")
	}

	return b.objs[key], nil
}

func (b *fakeBlobs) Objects(_ context.Context, keys []string) ([][]byte, error) {
	if b.fail {
		return nil, errors.New("redis down")
	}

	out := make([][]byte, len(keys))
	for i, k := range keys {
		out[i] = b.objs[k]
	}

	return out, nil
}

var testKey = Key{'k', 'e', 'y', '-', 'o', 'f', '-', 't', 'h', 'e', '-', 'e', 'p', 'o', 'c', 'h'}

func addrMirror() (*Mirror, *set, *fakeBlobs) {
	st := &set{name: "bans", comp: newComposition(), ready: true, epoch: 7, seq: 10, key: testKey, typ: typeCIDR}
	blobs := &fakeBlobs{objs: map[string][]byte{}}
	m := &Mirror{log: slog.Default(), blobs: blobs, sets: map[string]*set{"bans": st}}

	return m, st, blobs
}

func cidr(op uint8, value string, exp int64) packRecord {
	p, err := netip.ParsePrefix(value)
	if err != nil {
		a := netip.MustParseAddr(value).Unmap()
		p = netip.PrefixFrom(a, a.BitLen())
	}

	return packRecord{op: op, prefix: netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked(), exp: exp}
}

// stage кладёт пакет seq с записями в Redis и считает хеш, как keeper: XOR
// по материалу над текущим составом st.
func stage(st *set, blobs *fakeBlobs, seq uint64, recs ...packRecord) {
	hash := st.comp.hash
	seen := map[string]bool{}

	for k := range st.comp.nets {
		seen[string(prefixMaterial(k))] = true
	}

	for k := range st.comp.entries {
		seen[k] = true
	}

	for _, r := range recs {
		mat := string(r.material(st.typ))

		if r.op == recAdd && !seen[mat] {
			hash ^= SipHashBytes(st.key, []byte(mat))
			seen[mat] = true
		}

		if r.op == recRemove && seen[mat] {
			hash ^= SipHashBytes(st.key, []byte(mat))
			delete(seen, mat)
		}
	}

	blobs.objs[diffKey(st.name, seq)] = pack(packHead{
		kind: kindPackage, typ: st.typ, epoch: st.epoch, seq: seq, hash: hash, key: st.key,
	}, recs)
}

/*
 * Префикс со сроком -- такая же запись, как адрес: накрывает свои адреса,
 * пока срок не вышел, и снимается пакетом remove. Одиночный адрес -- префикс
 * полной длины; поиск пробует только те длины, которые в наборе есть.
 */
func TestPrefixWithTTLCoversAddresses(t *testing.T) {
	m, st, blobs := addrMirror()
	later := time.Now().Add(time.Hour).UnixMilli()

	stage(st, blobs, 11,
		cidr(recAdd, "203.0.113.0/24", later),
		cidr(recAdd, "198.51.100.7", later),
		cidr(recAdd, "2001:db8::/32", later),
	)

	m.onFrame(st, frame{V: Version, Epoch: hexOf(7), Seq: 11, Op: opDiff, Package: diffKey("bans", 11)})

	if st.seq != 11 {
		t.Fatalf("package must be applied: seq %d", st.seq)
	}

	for _, ip := range []string{"203.0.113.9", "203.0.113.255", "198.51.100.7", "2001:db8:1::5"} {
		if ok, ready := m.ContainsAddr("bans", netip.MustParseAddr(ip)); !ok || !ready {
			t.Fatalf("%s must be covered: ok=%v ready=%v", ip, ok, ready)
		}
	}

	for _, ip := range []string{"203.0.114.1", "198.51.100.8", "2001:db9::1"} {
		if ok, _ := m.ContainsAddr("bans", netip.MustParseAddr(ip)); ok {
			t.Fatalf("%s must not be covered", ip)
		}
	}

	if st.comp.lens[0][24] != 1 || st.comp.lens[0][32] != 1 || st.comp.lens[1][32] != 1 {
		t.Fatalf("length counters: %v %v", st.comp.lens[0][20:33], st.comp.lens[1][32])
	}

	/* Contains принимает и адрес, и префикс */
	if ok, _ := m.Contains("bans", "203.0.113.77"); !ok {
		t.Fatal("Contains by address")
	}

	if ok, _ := m.Contains("bans", "203.0.113.0/24"); !ok {
		t.Fatal("Contains by prefix")
	}

	stage(st, blobs, 12, cidr(recRemove, "203.0.113.0/24", 0))
	m.onFrame(st, frame{V: Version, Epoch: hexOf(7), Seq: 12, Op: opDiff})

	if ok, _ := m.ContainsAddr("bans", netip.MustParseAddr("203.0.113.9")); ok {
		t.Fatal("removed prefix must not cover")
	}

	if st.comp.lens[0][24] != 0 {
		t.Fatalf("length counter must drop with the prefix: %d", st.comp.lens[0][24])
	}

	want := SipHashBytes(testKey, prefixMaterial(netip.MustParsePrefix("198.51.100.7/32"))) ^
		SipHashBytes(testKey, prefixMaterial(netip.MustParsePrefix("2001:db8::/32")))

	if st.comp.hash != want {
		t.Fatal("hash must follow the composition")
	}
}

/* Истёкший префикс не накрывает никого до пакета keeper, но остаётся в составе ради хеша. */
func TestExpiredPrefixIsAMiss(t *testing.T) {
	m, st, blobs := addrMirror()

	stage(st, blobs, 11, cidr(recAdd, "10.0.0.0/8", time.Now().Add(-time.Second).UnixMilli()))
	m.onFrame(st, frame{V: Version, Epoch: hexOf(7), Seq: 11, Op: opDiff})

	if ok, ready := m.ContainsAddr("bans", netip.MustParseAddr("10.1.2.3")); ok || !ready {
		t.Fatalf("expired prefix: ok=%v ready=%v", ok, ready)
	}

	if _, present := st.comp.nets[netip.MustParsePrefix("10.0.0.0/8")]; !present {
		t.Fatal("expired entry must stay until keeper removes it")
	}
}

/*
 * Отставание: тик с seq дальше своего -- пакеты между ними читаются из Redis
 * одним махом и применяются по порядку; пакет, которого уже нет, -- снапшот
 * (здесь keeper не отвечает, поэтому набор остаётся на своём seq).
 */
func TestCatchUpReadsMissingPackages(t *testing.T) {
	m, st, blobs := addrMirror()
	later := time.Now().Add(time.Hour).UnixMilli()

	stage(st, blobs, 11, cidr(recAdd, "10.0.0.1", later))
	st.comp.apply(st.key, typeCIDR, cidr(recAdd, "10.0.0.1", later)) // как будто применили
	st.seq = 11

	stage(st, blobs, 12, cidr(recAdd, "10.0.0.2", later))
	st.comp.apply(st.key, typeCIDR, cidr(recAdd, "10.0.0.2", later))
	stage(st, blobs, 13, cidr(recAdd, "10.0.0.3", later))
	st.comp.apply(st.key, typeCIDR, cidr(recAdd, "10.0.0.3", later))

	/* откатываем зеркало на 11 -- пакеты 12 и 13 лежат в Redis */
	st.comp = newComposition()
	st.comp.apply(st.key, typeCIDR, cidr(recAdd, "10.0.0.1", later))

	m.onFrame(st, frame{V: Version, Epoch: hexOf(7), Seq: 13, Op: opTick, Hash: hexOf(headHash(blobs.objs[diffKey("bans", 13)]))})

	if st.seq != 13 {
		t.Fatalf("catch-up must reach the tick: seq %d", st.seq)
	}

	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if ok, _ := m.ContainsAddr("bans", netip.MustParseAddr(ip)); !ok {
			t.Fatalf("%s must be in the set after catch-up", ip)
		}
	}

	/* пакет 14 отсутствует: снапшот не отвечает (nc nil -> запрос падает), seq стоит */
	m.nc = nil
	func() {
		defer func() { _ = recover() }()
		m.onFrame(st, frame{V: Version, Epoch: hexOf(7), Seq: 14, Op: opTick})
	}()

	if st.seq != 13 {
		t.Fatalf("missing package must not advance the set: seq %d", st.seq)
	}
}

/* Чужая эпоха в заголовке пакета -- пакет не применяется. */
func TestForeignPackageIsRefused(t *testing.T) {
	m, st, blobs := addrMirror()
	later := time.Now().Add(time.Hour).UnixMilli()

	stage(st, blobs, 11, cidr(recAdd, "10.0.0.1", later))
	st.epoch = 8 // зеркало в другой эпохе, чем пакет

	m.nc = nil
	func() {
		defer func() { _ = recover() }()
		m.onFrame(st, frame{V: Version, Epoch: hexOf(8), Seq: 11, Op: opDiff})
	}()

	if st.seq != 10 || st.comp.size() != 0 {
		t.Fatalf("package of another epoch must be refused: seq %d size %d", st.seq, st.comp.size())
	}
}

func headHash(data []byte) uint64 {
	head, _, _ := unpack(data)

	return head.hash
}
