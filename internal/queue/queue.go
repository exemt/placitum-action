/*
 * Admission control.
 *
 * Сообщение забираем с шины сразу: клиент NATS не очередь, pending — только
 * то, что уже в полёте к нам. Дальше решаем сами: прокисший бюджет выкидываем
 * из своего буфера (IP_DEADLINE_EXCEEDED), чтобы слот занял свежий запрос.
 * Полная очередь живых — drop (IP_QUEUE_LIMIT) или wait до места / дедлайна.
 * Молчание для модуля неотличимо от перегрузки.
 */

package queue

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/exemt/placitum-action/internal/protocol"
	"github.com/exemt/placitum-shared/flow"
)

const (
	ReasonQueueLimit       = "ACTION_QUEUE_LIMIT"
	ReasonDeadlineExceeded = "ACTION_DEADLINE_EXCEEDED"

	FullDrop = "drop"
	FullWait = "wait"
)

type Task struct {
	Req   *protocol.Request
	Reply string

	enqueued time.Time
}

type Handler func(t *Task, budget time.Duration, shed string)

type Pool struct {
	mu     sync.Mutex
	cond   *sync.Cond
	q      []*Task
	depth  int
	closed bool
	stop   chan struct{}

	handler Handler
	full    string

	reserve   time.Duration
	minBudget time.Duration

	wg sync.WaitGroup

	Accepted atomic.Int64
	Shed     atomic.Int64
	Expired  atomic.Int64

	io *flow.Counter
}

func New(workers, depth, reserveMS, minBudgetMS int, full string, h Handler) *Pool {
	if full == "" {
		full = FullDrop
	}

	if depth < 1 {
		depth = 1
	}

	p := &Pool{
		q:         make([]*Task, 0, depth),
		depth:     depth,
		stop:      make(chan struct{}),
		handler:   h,
		full:      full,
		reserve:   time.Duration(reserveMS) * time.Millisecond,
		minBudget: time.Duration(minBudgetMS) * time.Millisecond,
		io:        flow.New(),
	}
	p.cond = sync.NewCond(&p.mu)

	p.wg.Add(workers + 1)

	go p.sweep()

	for range workers {
		go p.work()
	}

	return p
}

func (p *Pool) Submit(t *Task) {
	t.enqueued = time.Now()

	if p.waitLeft(t) < p.minBudget {
		p.expire(t, p.waitLeft(t))
		return
	}

	p.replyDead(p.collectExpired())

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		p.expire(t, 0)
		return
	}

	if len(p.q) < p.depth {
		p.enqueueLocked(t)
		p.mu.Unlock()
		return
	}

	if p.full == FullWait {
		p.submitWaitLocked(t)
		return
	}

	p.mu.Unlock()
	p.shedLimit(t)
}

func (p *Pool) submitWaitLocked(t *Task) {
	left := p.waitLeft(t)
	if left < p.minBudget {
		p.mu.Unlock()
		p.expire(t, left)
		return
	}

	timedOut := false
	timer := time.AfterFunc(left, func() {
		p.mu.Lock()
		timedOut = true
		p.cond.Broadcast()
		p.mu.Unlock()
	})

	for len(p.q) >= p.depth && !timedOut && !p.closed {
		if dead := p.takeExpiredLocked(); len(dead) > 0 {
			p.mu.Unlock()
			p.replyDead(dead)
			p.mu.Lock()
			continue
		}

		p.cond.Wait()
	}

	timer.Stop()

	if p.closed {
		p.mu.Unlock()
		p.expire(t, 0)
		return
	}

	if len(p.q) < p.depth {
		p.enqueueLocked(t)
		p.mu.Unlock()
		return
	}

	p.mu.Unlock()
	p.expire(t, 0)
}

func (p *Pool) enqueueLocked(t *Task) {
	p.q = append(p.q, t)
	p.Accepted.Add(1)
	p.cond.Signal()
}

func (p *Pool) waitLeft(t *Task) time.Duration {
	return p.leftAt(t, time.Now())
}

func (p *Pool) leftAt(t *Task, now time.Time) time.Duration {
	deadline := time.Duration(t.Req.DeadlineMS) * time.Millisecond
	return deadline - now.Sub(t.enqueued) - p.reserve
}

func (p *Pool) collectExpired() []*Task {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.takeExpiredLocked()
}

func (p *Pool) takeExpiredLocked() []*Task {
	if len(p.q) == 0 {
		return nil
	}

	now := time.Now()
	var dead []*Task
	kept := p.q[:0]

	for _, t := range p.q {
		if p.leftAt(t, now) < p.minBudget {
			dead = append(dead, t)
			continue
		}

		kept = append(kept, t)
	}

	p.q = kept

	if len(dead) > 0 {
		p.cond.Broadcast()
	}

	return dead
}

func (p *Pool) Queued() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.q)
}

func (p *Pool) IO() flow.Flow {
	return p.io.Snapshot()
}

func (p *Pool) Close() {
	close(p.stop)
	p.mu.Lock()
	p.closed = true
	p.cond.Broadcast()
	p.mu.Unlock()
	p.wg.Wait()
}

func (p *Pool) sweep() {
	defer p.wg.Done()

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-p.stop:
			return
		case <-tick.C:
			p.replyDead(p.collectExpired())
		}
	}
}

func (p *Pool) work() {
	defer p.wg.Done()

	for {
		t, dead, ok := p.pop()
		p.replyDead(dead)

		if !ok {
			return
		}

		if t == nil {
			continue
		}

		budget, shed := p.budget(t)
		start := time.Now()
		p.handler(t, budget, shed)
		p.io.Add(0, 0, shed != "", time.Since(start))
	}
}

func (p *Pool) pop() (t *Task, dead []*Task, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for {
		dead = p.takeExpiredLocked()

		if len(p.q) > 0 {
			t = p.q[0]
			p.q = p.q[1:]
			p.cond.Broadcast()
			return t, dead, true
		}

		if p.closed {
			return nil, dead, false
		}

		if len(dead) > 0 {
			return nil, dead, true
		}

		p.cond.Wait()
	}
}

func (p *Pool) budget(t *Task) (time.Duration, string) {
	left := p.waitLeft(t)
	if left < p.minBudget {
		p.Expired.Add(1)
		return left, ReasonDeadlineExceeded
	}

	return left, ""
}

func (p *Pool) replyDead(dead []*Task) {
	for _, t := range dead {
		p.expire(t, 0)
	}
}

func (p *Pool) expire(t *Task, left time.Duration) {
	p.Expired.Add(1)
	start := time.Now()
	p.handler(t, left, ReasonDeadlineExceeded)
	p.io.Add(0, 0, true, time.Since(start))
}

func (p *Pool) shedLimit(t *Task) {
	p.Shed.Add(1)
	start := time.Now()
	p.handler(t, 0, ReasonQueueLimit)
	p.io.Add(0, 0, true, time.Since(start))
}
