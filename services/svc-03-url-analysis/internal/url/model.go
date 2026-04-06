package url

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	defaultPoolSize    = 3
	inferenceTimeout   = 5 * time.Second
	neutralScore       = 50
	neutralProbability = 0.5
	spawnReadyTimeout  = 10 * time.Second
	maxReplaceRetries  = 3
)

type inferRequest struct {
	URL string `json:"url"`
}

type inferResponse struct {
	Score       int     `json:"score"`
	Probability float64 `json:"probability"`
	Label       string  `json:"label"`
	Error       string  `json:"error,omitempty"`
}

// workerProcess wraps a live Python subprocess with its stdin/stdout pipes.
type workerProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

func (p *workerProcess) kill() {
	_ = p.stdin.Close()
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
}

// LogFunc is an optional callback for error logging within the model pool.
// If nil, errors are silently discarded.
type LogFunc func(msg string, err error)

// URLModel maintains a pool of pre-spawned Python inference subprocesses.
// Each subprocess runs inference_script.py and communicates via JSON over
// stdin/stdout (one request/response pair per line).
//
// Concurrency model: each workerProcess handles one request at a time.
// The pool channel acts as a counting semaphore — acquiring a process removes
// it from the pool; returning it (or its replacement) puts it back.
//
// Shutdown: closing the done channel unblocks any goroutines waiting in
// acquire(), preventing the Close-vs-Predict race where a drained pool
// would block callers for the full inference timeout.
type URLModel struct {
	scriptPath string
	pool       chan *workerProcess
	done       chan struct{}
	logFn      LogFunc
	mu         sync.Mutex
	closed     bool
}

// NewURLModel creates a URLModel with poolSize pre-spawned Python processes.
// scriptPath must point to inference_script.py.
// poolSize <= 0 defaults to defaultPoolSize (3).
// logFn is an optional error logger; pass nil to discard errors.
//
// Each worker must send a "READY" line on stdout before being placed in the
// pool. If any worker fails to start or signal readiness, all previously
// spawned workers are cleaned up and an error is returned.
func NewURLModel(scriptPath string, poolSize int, logFn LogFunc) (*URLModel, error) {
	if poolSize <= 0 {
		poolSize = defaultPoolSize
	}
	m := &URLModel{
		scriptPath: scriptPath,
		pool:       make(chan *workerProcess, poolSize),
		done:       make(chan struct{}),
		logFn:      logFn,
	}
	for i := 0; i < poolSize; i++ {
		p, err := m.spawn()
		if err != nil {
			m.Close()
			return nil, fmt.Errorf("url model: spawn worker %d: %w", i, err)
		}
		m.pool <- p
	}
	return m, nil
}

func (m *URLModel) logError(msg string, err error) {
	if m.logFn != nil {
		m.logFn(msg, err)
	}
}

// spawn starts a Python subprocess and waits for its "READY" stdout signal.
// Returns an error if the process fails to start or does not become ready
// within spawnReadyTimeout.
func (m *URLModel) spawn() (*workerProcess, error) {
	cmd := exec.Command("python3", m.scriptPath)
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdoutPipe.Close()
		return nil, fmt.Errorf("start: %w", err)
	}

	reader := bufio.NewReader(stdoutPipe)

	// Wait for the worker to signal readiness via a "READY" line on stdout.
	readyCh := make(chan error, 1)
	go func() {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			readyCh <- fmt.Errorf("read ready signal: %w", readErr)
			return
		}
		if strings.TrimSpace(line) != "READY" {
			readyCh <- fmt.Errorf("unexpected ready line: %s", strings.TrimSpace(line))
			return
		}
		readyCh <- nil
	}()

	select {
	case readyErr := <-readyCh:
		if readyErr != nil {
			_ = stdin.Close()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, fmt.Errorf("worker readiness: %w", readyErr)
		}
	case <-time.After(spawnReadyTimeout):
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("worker readiness: timeout after %s", spawnReadyTimeout)
	}

	return &workerProcess{
		cmd:    cmd,
		stdin:  stdin,
		stdout: reader,
	}, nil
}

// acquire waits for an available worker, model shutdown, or ctx cancellation.
func (m *URLModel) acquire(ctx context.Context) (*workerProcess, bool) {
	select {
	case p := <-m.pool:
		return p, true
	case <-m.done:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}

// release returns p to the pool, or kills it if the model is closed.
func (m *URLModel) release(p *workerProcess) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		p.kill()
		return
	}
	m.pool <- p
}

// replaceAsync spawns a fresh worker and puts it in the pool.
// Retries up to maxReplaceRetries times with exponential backoff.
func (m *URLModel) replaceAsync() {
	go func() {
		var lastErr error
		for attempt := 0; attempt < maxReplaceRetries; attempt++ {
			if attempt > 0 {
				backoff := time.Duration(1<<uint(attempt-1)) * 500 * time.Millisecond
				time.Sleep(backoff)
			}

			m.mu.Lock()
			closed := m.closed
			m.mu.Unlock()
			if closed {
				return
			}

			p, err := m.spawn()
			if err != nil {
				lastErr = err
				continue
			}

			m.mu.Lock()
			if m.closed {
				m.mu.Unlock()
				p.kill()
				return
			}
			m.pool <- p
			m.mu.Unlock()
			return
		}
		m.logError("url model: failed to replace crashed worker after retries", lastErr)
	}()
}

// Predict sends a raw URL to a Python subprocess which performs feature
// extraction and inference, returning (score, probability).
//
// The provided context controls the overall deadline. If ctx has no deadline,
// a default 5-second timeout is applied. On timeout or subprocess crash,
// returns (50, 0.5, nil) — the neutral "unknown risk" score defined in
// DECISIONS.MD. The pipeline is never hard-failed.
// Calling Predict on a closed URLModel returns neutral immediately.
func (m *URLModel) Predict(ctx context.Context, rawURL string) (score int, probability float64, err error) {
	// Fast path: if the model is already closed, return neutral without blocking.
	select {
	case <-m.done:
		return neutralScore, neutralProbability, nil
	default:
	}

	// Apply default timeout if the caller's context has none.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, inferenceTimeout)
		defer cancel()
	}

	p, ok := m.acquire(ctx)
	if !ok {
		// Pool fully occupied, closed, or ctx cancelled — return neutral.
		return neutralScore, neutralProbability, nil
	}

	req := inferRequest{URL: rawURL}
	reqBytes, marshalErr := json.Marshal(req)
	if marshalErr != nil {
		m.logError("url model: marshal features", marshalErr)
		m.release(p)
		return neutralScore, neutralProbability, nil
	}
	reqBytes = append(reqBytes, '\n')

	if _, writeErr := p.stdin.Write(reqBytes); writeErr != nil {
		m.logError("url model: write to worker stdin", writeErr)
		p.kill()
		m.replaceAsync()
		return neutralScore, neutralProbability, nil
	}

	type readResult struct {
		line string
		err  error
	}
	ch := make(chan readResult, 1) // buffered so the goroutine never blocks
	go func() {
		line, readErr := p.stdout.ReadString('\n')
		ch <- readResult{line: line, err: readErr}
	}()

	select {
	case result := <-ch:
		if result.err != nil {
			m.logError("url model: read from worker stdout", result.err)
			p.kill()
			m.replaceAsync()
			return neutralScore, neutralProbability, nil
		}
		var resp inferResponse
		if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(result.line)), &resp); jsonErr != nil {
			m.logError("url model: unmarshal response", jsonErr)
			p.kill()
			m.replaceAsync()
			return neutralScore, neutralProbability, nil
		}
		if resp.Error != "" {
			m.logError("url model: inference error from worker", fmt.Errorf("%s", resp.Error))
			m.release(p)
			return neutralScore, neutralProbability, nil
		}
		m.release(p)
		return resp.Score, resp.Probability, nil

	case <-m.done:
		// Model shutting down — kill the held worker and return immediately.
		p.kill()
		return neutralScore, neutralProbability, nil

	case <-ctx.Done():
		m.logError("url model: inference timeout", ctx.Err())
		p.kill()
		m.replaceAsync()
		return neutralScore, neutralProbability, nil
	}
}

// Close terminates all pooled Python processes. It is safe to call multiple
// times. Processes held by in-flight Predict calls are cleaned up by release()
// when those calls complete (it checks m.closed under the mutex).
//
// Closing the done channel unblocks any goroutines waiting in acquire().
// The drain runs under m.mu so that a concurrent replaceAsync() goroutine
// cannot sneak a freshly-spawned process into the pool after the drain finishes
// but before m.closed is visible.
func (m *URLModel) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	close(m.done)
	for {
		select {
		case p := <-m.pool:
			p.kill()
		default:
			return
		}
	}
}
