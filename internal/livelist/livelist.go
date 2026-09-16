package livelist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

const Version = 3

const (
	subjectPrefix  = "waf.sets."
	opResync       = "resync"
	opDiff         = "diff"
	opTick         = "tick"
	opSnapshot     = "snapshot"
	requestTimeout = 5 * time.Second
	objectTimeout  = 30 * time.Second
	resyncEvery    = 2 * time.Second

	silenceAfter    = 6 * time.Second
	queueDepth      = 1024
	packagesPerRead = 256
)

type Blobs interface {
	Object(ctx context.Context, key string) ([]byte, error)
	Objects(ctx context.Context, keys []string) ([][]byte, error)
}

type RedisBlobs struct {
	client *redis.Client
}

func OpenBlobs(url string) (*RedisBlobs, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	opt.DialTimeout = requestTimeout
	opt.ReadTimeout = objectTimeout
	opt.WriteTimeout = requestTimeout

	return &RedisBlobs{client: redis.NewClient(opt)}, nil
}

func (b *RedisBlobs) Object(ctx context.Context, key string) ([]byte, error) {
	data, err := b.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}

	return data, err
}

func (b *RedisBlobs) Objects(ctx context.Context, keys []string) ([][]byte, error) {
	vals, err := b.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	out := make([][]byte, len(vals))

	for i, v := range vals {
		if s, ok := v.(string); ok {
			out[i] = []byte(s)
		}
	}

	return out, nil
}

func (b *RedisBlobs) Close() error { return b.client.Close() }

func diffKey(name string, seq uint64) string {
	return "waf:diff:" + name + ":" + strconv.FormatUint(seq, 10)
}

type frame struct {
	V       int    `json:"v"`
	Set     string `json:"set"`
	Epoch   string `json:"epoch"`
	Seq     uint64 `json:"seq"`
	Op      string `json:"op"`
	Hash    string `json:"hash"`
	Key     string `json:"key"`
	Package string `json:"package"`
	Object  string `json:"object"`
	Count   int    `json:"count"`
}

type record struct {
	exp    int64
	reason string
}

type Entry struct {
	Reason  string
	Expires int64
}

type composition struct {
	entries map[string]record
	nets    map[netip.Prefix]int64
	lens    [2][129]int
	hash    uint64
}

func newComposition() *composition {
	return &composition{entries: map[string]record{}, nets: map[netip.Prefix]int64{}}
}

func family(p netip.Prefix) int {
	if p.Addr().Is4() {
		return 0
	}

	return 1
}

func (c *composition) apply(key Key, typ uint8, r packRecord) {
	if typ == typeCIDR {
		p := r.prefix
		_, had := c.nets[p]

		switch {
		case r.op == recAdd:
			if !had {
				c.hash ^= SipHashBytes(key, prefixMaterial(p))
				c.lens[family(p)][p.Bits()]++
			}

			c.nets[p] = r.exp

		case had:
			c.hash ^= SipHashBytes(key, prefixMaterial(p))
			c.lens[family(p)][p.Bits()]--
			delete(c.nets, p)
		}

		return
	}

	_, had := c.entries[r.value]

	switch {
	case r.op == recAdd:
		if !had {
			c.hash ^= SipHash(key, r.value)
		}

		c.entries[r.value] = record{exp: r.exp, reason: r.reason}

	case had:
		c.hash ^= SipHash(key, r.value)
		delete(c.entries, r.value)
	}
}

func (c *composition) containsAddr(ip netip.Addr, now int64) bool {
	ip = ip.Unmap()
	fam := 0
	if !ip.Is4() {
		fam = 1
	}

	for bits := ip.BitLen(); bits >= 0; bits-- {
		if c.lens[fam][bits] == 0 {
			continue
		}

		p := netip.PrefixFrom(ip, bits).Masked()
		if exp, ok := c.nets[p]; ok && alive(exp, now) {
			return true
		}
	}

	return false
}

func (c *composition) size() int { return len(c.entries) + len(c.nets) }

func alive(exp int64, now int64) bool {
	return exp == 0 || exp > now
}

type set struct {
	name string

	mu    sync.RWMutex
	ready bool
	epoch uint64
	seq   uint64
	key   Key
	typ   uint8
	comp  *composition

	lastSeen time.Time
	silent   bool

	in      chan frame
	syncing bool
	refused string
	snapBad bool
}

type Mirror struct {
	nc    *nats.Conn
	blobs Blobs
	log   *slog.Logger
	from  string

	mu   sync.Mutex
	sets map[string]*set
	subs []*nats.Subscription
	done chan struct{}
	once sync.Once
}

func New(nc *nats.Conn, blobs Blobs, log *slog.Logger) *Mirror {
	host, _ := os.Hostname()

	m := &Mirror{
		nc:    nc,
		blobs: blobs,
		log:   log,
		from:  host,
		sets:  map[string]*set{},
		done:  make(chan struct{}),
	}

	go m.resync()

	return m
}

func (m *Mirror) Ensure(name string) {
	if name == "" {
		return
	}

	m.mu.Lock()

	if _, ok := m.sets[name]; ok {
		m.mu.Unlock()

		return
	}

	st := &set{name: name, comp: newComposition(), in: make(chan frame, queueDepth), lastSeen: time.Now()}
	m.sets[name] = st

	sub, err := m.nc.Subscribe(subjectPrefix+name, func(msg *nats.Msg) {
		var f frame
		if err := json.Unmarshal(msg.Data, &f); err != nil {
			m.log.Warn("list frame is not json", "set", name)

			return
		}

		select {
		case st.in <- f:
		default:
		}
	})
	if err == nil {
		m.subs = append(m.subs, sub)
	}

	m.mu.Unlock()

	if err != nil {
		m.log.Error("list subscribe failed", "set", name, "error", err.Error())

		return
	}

	go m.run(st)

	m.log.Info("list mirror on", "set", name)
}

func (m *Mirror) lookup(name string) *set {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.sets[name]
}

func (m *Mirror) Contains(name, value string) (ok, ready bool) {
	st := m.lookup(name)

	if st == nil || value == "" {
		return false, false
	}

	st.mu.RLock()
	defer st.mu.RUnlock()

	if !st.ready {
		return false, false
	}

	now := time.Now().UnixMilli()

	if st.typ == typeCIDR {
		if a, err := netip.ParseAddr(value); err == nil {
			return st.comp.containsAddr(a, now), true
		}

		if p, err := netip.ParsePrefix(value); err == nil {
			exp, ok := st.comp.nets[netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()]

			return ok && alive(exp, now), true
		}

		return false, true
	}

	rec, ok := st.comp.entries[value]

	return ok && alive(rec.exp, now), true
}

func (m *Mirror) Lookup(name, value string) (Entry, bool, bool) {
	st := m.lookup(name)

	if st == nil || value == "" {
		return Entry{}, false, false
	}

	st.mu.RLock()
	defer st.mu.RUnlock()

	if !st.ready {
		return Entry{}, false, false
	}

	rec, ok := st.comp.entries[value]
	if !ok || !alive(rec.exp, time.Now().UnixMilli()) {
		return Entry{}, false, true
	}

	return Entry{Reason: rec.reason, Expires: rec.exp}, true, true
}

func (m *Mirror) ContainsAddr(name string, ip netip.Addr) (ok, ready bool) {
	st := m.lookup(name)

	if st == nil || !ip.IsValid() {
		return false, false
	}

	st.mu.RLock()
	defer st.mu.RUnlock()

	if !st.ready {
		return false, false
	}

	return st.comp.containsAddr(ip, time.Now().UnixMilli()), true
}

type Stats struct {
	Name    string
	Ready   bool
	Epoch   string
	Seq     uint64
	Hash    string
	Entries int
}

func (m *Mirror) Stats() []Stats {
	m.mu.Lock()
	sets := make([]*set, 0, len(m.sets))
	for _, st := range m.sets {
		sets = append(sets, st)
	}
	m.mu.Unlock()

	out := make([]Stats, 0, len(sets))

	for _, st := range sets {
		st.mu.RLock()
		out = append(out, Stats{
			Name:    st.name,
			Ready:   st.ready,
			Epoch:   hexOf(st.epoch),
			Seq:     st.seq,
			Hash:    hexOf(st.comp.hash),
			Entries: st.comp.size(),
		})
		st.mu.RUnlock()
	}

	return out
}

func (m *Mirror) Close() {
	m.once.Do(func() { close(m.done) })

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, sub := range m.subs {
		_ = sub.Unsubscribe()
	}

	m.subs = nil
}

func (m *Mirror) run(st *set) {
	m.snapshot(st)

	for {
		select {
		case <-m.done:
			return
		case f := <-st.in:
			m.onFrame(st, f)
		}
	}
}

func (m *Mirror) onFrame(st *set, f frame) {
	if f.V != Version {
		m.log.Warn("unsupported dataset message version", "set", st.name, "v", f.V)

		return
	}

	st.mu.Lock()
	ready, myEpoch, mySeq := st.ready, st.epoch, st.seq
	if f.Op != opResync {
		st.lastSeen = time.Now()
		st.silent = false
	}
	st.mu.Unlock()

	if !ready {
		m.snapshot(st)

		return
	}

	if f.Op == opResync {
		return
	}

	epoch, err := strconv.ParseUint(f.Epoch, 16, 64)
	if err != nil {
		return
	}

	if epoch != myEpoch {
		m.log.Info("new epoch", "set", st.name, "epoch", f.Epoch)
		st.snapBad = false
		m.snapshot(st)

		return
	}

	switch {
	case f.Seq < mySeq:
	case f.Seq == mySeq:
		if f.Op == opTick || f.Op == opDiff {
			m.verify(st, f.Hash, f.Op)
		}
	default:
		m.catchUp(st, f.Seq, f.Hash)
	}
}

func (m *Mirror) catchUp(st *set, upto uint64, hash string) {
	if m.blobs == nil {
		m.log.Error("packages cannot be read: no internal redis", "set", st.name)

		return
	}

	for {
		st.mu.RLock()
		mySeq := st.seq
		st.mu.RUnlock()

		if mySeq >= upto {
			break
		}

		n := upto - mySeq
		if n > packagesPerRead {
			n = packagesPerRead
		}

		keys := make([]string, n)
		for i := range keys {
			keys[i] = diffKey(st.name, mySeq+1+uint64(i))
		}

		ctx, cancel := context.WithTimeout(context.Background(), objectTimeout)
		objs, err := m.blobs.Objects(ctx, keys)
		cancel()

		if err != nil {
			m.log.Warn("packages unavailable", "set", st.name, "from", mySeq+1, "error", err.Error())

			return
		}

		for i, data := range objs {
			if data == nil {
				m.log.Info("package gone, taking a snapshot", "set", st.name, "seq", mySeq+1+uint64(i))
				m.snapshot(st)

				return
			}

			if !m.applyPackage(st, data, mySeq+1+uint64(i)) {
				return
			}
		}
	}

	m.verify(st, hash, "catch-up")
}

func (m *Mirror) applyPackage(st *set, data []byte, want uint64) bool {
	head, recs, err := unpack(data)
	if err != nil {
		m.log.Warn("package is malformed", "set", st.name, "seq", want, "error", err.Error())
		m.snapshot(st)

		return false
	}

	st.mu.Lock()

	if head.kind != kindPackage || head.epoch != st.epoch || head.seq != want || head.typ != st.typ {
		st.mu.Unlock()
		m.log.Warn("package does not match the set", "set", st.name, "seq", want,
			"kind", head.kind, "epoch", hexOf(head.epoch), "got_seq", head.seq)
		m.snapshot(st)

		return false
	}

	for _, r := range recs {
		st.comp.apply(st.key, head.typ, r)
	}

	st.seq = head.seq
	st.mu.Unlock()

	return m.verify(st, hexOf(head.hash), "package")
}

func (m *Mirror) verify(st *set, want, where string) bool {
	st.mu.RLock()
	got := st.comp.hash
	seq := st.seq
	st.mu.RUnlock()

	if want == "" || hexOf(got) == want {
		return true
	}

	if st.snapBad {
		m.log.Debug("still diverged after a bad snapshot", "set", st.name, "at", where, "seq", seq)

		return false
	}

	m.log.Warn("diverged", "set", st.name, "at", where, "seq", seq, "want", want, "got", hexOf(got))
	m.snapshot(st)

	return false
}

func (m *Mirror) snapshot(st *set) {
	if st.syncing {
		return
	}

	st.syncing = true
	defer func() { st.syncing = false }()

	if st.snapBad {
		return
	}

	body, _ := json.Marshal(map[string]any{"from": m.from})

	msg, err := m.nc.Request(subjectPrefix+st.name+".snapshot", body, requestTimeout)
	if err != nil {
		m.log.Warn("snapshot request failed", "set", st.name, "error", err.Error())

		return
	}

	var ref frame
	if err := json.Unmarshal(msg.Data, &ref); err != nil || ref.Op != opSnapshot || ref.Object == "" {
		op := ref.Op
		if op == "" {
			op = "bad reply"
		}

		if st.refused == op {
			m.log.Debug("snapshot refused", "set", st.name, "reply", op)
		} else {
			m.log.Warn("snapshot refused", "set", st.name, "reply", op)
			st.refused = op
		}

		return
	}

	st.refused = ""

	if m.blobs == nil {
		m.log.Error("snapshot object cannot be read: no internal redis", "set", st.name, "object", ref.Object)

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), objectTimeout)
	data, err := m.blobs.Object(ctx, ref.Object)
	cancel()

	if err != nil {
		m.log.Warn("snapshot object unavailable", "set", st.name, "object", ref.Object, "error", err.Error())

		return
	}

	if data == nil {
		m.log.Warn("snapshot object already gone", "set", st.name, "object", ref.Object)

		return
	}

	head, recs, err := unpack(data)
	if err != nil || head.kind != kindSnapshot {
		m.log.Warn("snapshot object is malformed", "set", st.name, "object", ref.Object, "error", errText(err))

		return
	}

	comp := newComposition()

	for _, r := range recs {
		comp.apply(head.key, head.typ, r)
	}

	bad := comp.hash != head.hash

	st.mu.Lock()
	st.epoch, st.key, st.seq, st.typ, st.comp = head.epoch, head.key, head.seq, head.typ, comp
	st.ready = true
	st.snapBad = bad
	st.mu.Unlock()

	if bad {
		m.log.Error("snapshot hash mismatch: mirror cannot reproduce keeper's set, "+
			"further divergence is logged, not resynced",
			"set", st.name, "seq", head.seq, "want", hexOf(head.hash), "got", hexOf(comp.hash))
	}

	m.log.Info("snapshot applied", "set", st.name, "entries", comp.size(), "bytes", len(data),
		"epoch", hexOf(head.epoch), "seq", head.seq)
}

func (m *Mirror) resync() {
	tick := time.NewTicker(resyncEvery)
	defer tick.Stop()

	for {
		select {
		case <-m.done:
			return
		case <-tick.C:
		}

		m.mu.Lock()
		sets := make([]*set, 0, len(m.sets))
		for _, st := range m.sets {
			sets = append(sets, st)
		}
		m.mu.Unlock()

		now := time.Now()

		for _, st := range sets {
			st.mu.Lock()
			ready := st.ready
			quiet := !st.silent && now.Sub(st.lastSeen) > silenceAfter
			if ready && quiet {
				st.silent = true
			}
			last := st.lastSeen
			st.mu.Unlock()

			if !ready {
				select {
				case st.in <- frame{V: Version, Op: opResync}:
				default:
				}

				continue
			}

			if quiet {
				m.log.Warn("keeper silent", "set", st.name, "since", last.Format(time.RFC3339))
			}
		}
	}
}

func hexOf(v uint64) string {
	return fmt.Sprintf("%016x", v)
}

func errText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
