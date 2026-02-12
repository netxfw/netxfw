package logengine

import (
	"log"
	"sync"

	"github.com/nxadm/tail"
)

// Tailer watches files and streams lines.
type Tailer struct {
	Events       chan LogEvent
	wg           sync.WaitGroup
	tails        []*tail.Tail
	watchedFiles map[string]bool
	mu           sync.Mutex
	checkpoint   *CheckpointManager
}

// NewTailer creates a new Tailer.
func NewTailer(checkpoint *CheckpointManager) *Tailer {
	return &Tailer{
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
		log.Printf("❌ Failed to tail file %s: %v", filename, err)
		return
	}

	t.tails = append(t.tails, tailer)

	for line := range tailer.Lines {
		if line.Err != nil {
			log.Printf("Error reading %s: %v", filename, line.Err)
			continue
		}
		t.Events <- LogEvent{
			Line:      line.Text,
			Source:    filename,
			Timestamp: line.Time,
		}

		// Update checkpoint if needed (even if mode is not "offset", we might want to switch to "offset" later)
		// But strictly speaking, we only need to save if we care about "offset" mode recovery.
		// For simplicity, we always update in memory, and CheckpointManager decides if it saves to disk.
		if pos, err := tailer.Tell(); err == nil {
			t.checkpoint.UpdateOffset(filename, pos)
		}
	}
}

// Stop stops all tailers.
func (t *Tailer) Stop() {
	for _, tailer := range t.tails {
		tailer.Stop()
	}
	t.wg.Wait()
	close(t.Events)
}
