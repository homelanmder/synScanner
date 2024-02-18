package output

import (
	"bytes"
	"sync"
)

// fileWriter is a concurrent file based output writer.
type bufferWriter struct {
	buffer *bytes.Buffer
	mu     sync.Mutex
}

// NewFileOutputWriter creates a new buffered writer for a file
func newBufferOutputWriter(buffer *bytes.Buffer) *bufferWriter {

	return &bufferWriter{buffer: buffer}
}

// WriteString writes an output to the underlying file
func (w *bufferWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.buffer.Write(data); err != nil {
		return 0, err
	}
	if _, err := w.buffer.Write([]byte("\n")); err != nil {
		return 0, err
	}
	return len(data) + 1, nil
}

// Close closes the underlying writer flushing everything to disk
func (w *bufferWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	//nolint:errcheck // we don't care whether sync failed or succeeded.
	return w.Close()
}
