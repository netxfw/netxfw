package logengine

import (
	"sync"

	"github.com/netxfw/netxfw/pkg/sdk"
	"github.com/nxadm/tail"
)

// Tailer watches files and streams lines.
type Tailer struct {
	logger       sdk.Logger
	Events       chan LogEvent
	wg           sync.WaitGroup
	tails        []*tail.Tail
	watchedFiles map[string]bool
	mu           sync.Mutex
	checkpoint   *CheckpointManager
}

// NewTailer creates a new Tailer.
func NewTailer(checkpoint *CheckpointManager, logger sdk.Logger) *Tailer {
	return &Tailer{
		logger:       logger,
		Events:       make(chan LogEvent, 10000), // Buffered channel
		watchedFiles: make(map[string]bool),
		checkpoint:   checkpoint,
	}
}

// Watch starts tailing the specified files.
// files: map[filename]tail_position
func (t *Tailer) Watch(files map[string]string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for file, mode := range files {
		if t.watchedFiles[file] {
			continue
		}
		t.watchedFiles[file] = true
		t.wg.Add(1)
		go t.tailFile(file, mode)
	}
}

func (t *Tailer) tailFile(filename string, mode string) {
	defer t.wg.Done()

	// Determine start position using CheckpointManager and mode
	location := t.checkpoint.GetOffset(filename, mode)

	config := tail.Config{
		Location:  location,
		Follow:    true,
		ReOpen:    true, // Handle log rotation
		MustExist: false,
		Poll:      true, // Fallback if inotify fails
		Logger:    tail.DiscardingLogger,
	}

	tailer, err := tail.TailFile(filename, config)
	if err != nil {
		t.logger.Errorf("❌ Failed to tail file %s: %v", filename, err)
		return
	}

	t.tails = append(t.tails, tailer)

	go func() {
		for line := range tailer.Lines {
			if line.Err != nil {
				t.logger.Warnf("Error reading %s: %v", filename, line.Err)
				continue
			}
			t.Events <- LogEvent{
				Line:      line.Text,
				Source:    filename,
				Timestamp: line.Time,
			}

			if pos, err := tailer.Tell(); err == nil {
				t.checkpoint.UpdateOffset(filename, pos)
			}
		}
		t.wg.Done()
	}()
}

// Stop stops all tailers.
func (t *Tailer) Stop() {
	for _, tailer := range t.tails {
		_ = tailer.Stop()
	}
	t.wg.Wait()
	close(t.Events)
}
