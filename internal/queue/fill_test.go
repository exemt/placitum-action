package queue

import (
	"sync"
	"testing"
	"time"

	"github.com/exemt/placitum-action/internal/protocol"
)

// Заполнение снимается при постановке: сколько мест было занято до запроса.
// Полная очередь -- ровно 100, и сброшенный запрос уходит обработчику с ним.
func TestFillAtAdmission(t *testing.T) {
	var (
		mu   sync.Mutex
		shed []*Task
	)

	p := New(0, 4, 0, 0, FullDrop, func(t *Task, _ time.Duration, reason string) {
		if reason == ReasonQueueLimit {
			mu.Lock()
			shed = append(shed, t)
			mu.Unlock()
		}
	})
	defer p.Close()

	var fills []int

	for range 4 {
		task := &Task{Req: &protocol.Request{DeadlineMS: 60000}}
		p.Submit(task)
		fills = append(fills, task.Fill)
	}

	want := []int{0, 25, 50, 75}

	for i := range want {
		if fills[i] != want[i] {
			t.Fatalf("fills = %v, want %v", fills, want)
		}
	}

	over := &Task{Req: &protocol.Request{DeadlineMS: 60000}}
	p.Submit(over)

	mu.Lock()
	defer mu.Unlock()

	if len(shed) != 1 || shed[0] != over || over.Fill != 100 {
		t.Fatalf("shed %d tasks, fill %d; want the fifth one with 100", len(shed), over.Fill)
	}
}
