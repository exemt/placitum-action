package queue

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/exemt/placitum-action/internal/protocol"
)

func TestSubmitDrop(t *testing.T) {
	var sheds atomic.Int64
	block := make(chan struct{})
	started := make(chan struct{})

	p := New(1, 1, 0, 0, FullDrop, func(task *Task, _ time.Duration, shed string) {
		if shed != "" {
			if shed != ReasonQueueLimit {
				t.Errorf("shed = %s", shed)
			}
			sheds.Add(1)
			return
		}

		select {
		case <-started:
		default:
			close(started)
		}

		<-block
	})
	defer func() {
		close(block)
		p.Close()
	}()

	req := &protocol.Request{DeadlineMS: 5000}
	p.Submit(&Task{Req: req})
	<-started
	p.Submit(&Task{Req: req})
	p.Submit(&Task{Req: req})

	if sheds.Load() != 1 {
		t.Fatalf("sheds = %d, want 1", sheds.Load())
	}

	if p.Shed.Load() != 1 {
		t.Fatalf("pool.Shed = %d, want 1", p.Shed.Load())
	}
}

func TestSubmitWaitDeadline(t *testing.T) {
	var expired atomic.Int64
	block := make(chan struct{})
	started := make(chan struct{})

	p := New(1, 1, 0, 1, FullWait, func(task *Task, _ time.Duration, shed string) {
		if shed == ReasonDeadlineExceeded {
			expired.Add(1)
			return
		}

		if shed != "" {
			t.Errorf("unexpected shed %s", shed)
			return
		}

		select {
		case <-started:
		default:
			close(started)
		}

		<-block
	})
	defer func() {
		close(block)
		p.Close()
	}()

	p.Submit(&Task{Req: &protocol.Request{DeadlineMS: 5000}})
	<-started
	p.Submit(&Task{Req: &protocol.Request{DeadlineMS: 5000}})

	waited := make(chan struct{})
	go func() {
		p.Submit(&Task{Req: &protocol.Request{DeadlineMS: 20}})
		close(waited)
	}()

	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("wait did not return")
	}

	if expired.Load() < 1 {
		t.Fatalf("expired = %d, want >= 1", expired.Load())
	}
}

func TestSubmitEvictsStale(t *testing.T) {
	var expired, sheds, ok atomic.Int64
	block := make(chan struct{})
	started := make(chan struct{})

	p := New(1, 1, 0, 1, FullDrop, func(task *Task, _ time.Duration, shed string) {
		switch shed {
		case ReasonDeadlineExceeded:
			expired.Add(1)
			return
		case ReasonQueueLimit:
			sheds.Add(1)
			return
		case "":
			ok.Add(1)
		}

		select {
		case <-started:
		default:
			close(started)
		}

		<-block
	})
	defer func() {
		close(block)
		p.Close()
	}()

	p.Submit(&Task{Req: &protocol.Request{DeadlineMS: 5000}})
	<-started
	p.Submit(&Task{Req: &protocol.Request{DeadlineMS: 1}})
	time.Sleep(15 * time.Millisecond)
	p.Submit(&Task{Req: &protocol.Request{DeadlineMS: 5000}})

	if sheds.Load() != 0 {
		t.Fatalf("sheds = %d, want 0: stale should be evicted, not drop the new one", sheds.Load())
	}

	if expired.Load() < 1 {
		t.Fatalf("expired = %d, want >= 1", expired.Load())
	}

	if p.Queued() != 1 {
		t.Fatalf("queued = %d, want 1", p.Queued())
	}
}

func TestSubmitAlreadyStale(t *testing.T) {
	var expired atomic.Int64

	p := New(1, 2, 0, 1, FullDrop, func(task *Task, _ time.Duration, shed string) {
		if shed == ReasonDeadlineExceeded {
			expired.Add(1)
		}
	})
	defer p.Close()

	p.Submit(&Task{Req: &protocol.Request{DeadlineMS: 0}})

	if expired.Load() != 1 {
		t.Fatalf("expired = %d, want 1", expired.Load())
	}

	if p.Queued() != 0 {
		t.Fatalf("queued = %d, want 0", p.Queued())
	}
}
