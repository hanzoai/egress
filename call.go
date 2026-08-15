package egress

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/ai/model"
	"github.com/zap-proto/zip/middleware"
)

// Call is one request to spend a credential upstream.
//
// Notice what is absent. There is no org, no user and no upstream URL. The
// first two come from the verified token, because a caller that could name a
// tenant could spend another tenant's key. The third comes from this host's
// configuration, because a caller that could name an upstream could have the
// credential delivered to it.
type Call struct {
	// Provider is the dialect, spelled as hanzoai/ai spells it: "OpenAI",
	// "OpenRouter", "Claude", "Fireworks", "DigitalOcean". It selects both the
	// wire format and the credential, so a key enrolled for one vendor cannot
	// be spent against another.
	Provider string `json:"provider"`
	// Label picks between several credentials of the same provider. Empty means
	// "default".
	Label string `json:"label"`
	// Model is the upstream model name.
	Model string `json:"model"`

	// Question is the turn to answer; Prompt is the system prompt; History is
	// what came before, oldest first.
	Question string `json:"question"`
	Prompt   string `json:"prompt"`
	History  []Turn `json:"history"`

	// Lang is the caller's language, used for provider-side error text.
	Lang string `json:"lang"`

	// The dialect's sampling knobs. They belong to the caller because the
	// caller holds the provider record they were configured on; egress holds
	// custody and nothing else.
	Temperature      float32 `json:"temperature"`
	TopP             float32 `json:"topP"`
	TopK             int     `json:"topK"`
	FrequencyPenalty float32 `json:"frequencyPenalty"`
	PresencePenalty  float32 `json:"presencePenalty"`
	Thinking         bool    `json:"thinking"`
}

// Turn is one earlier message.
type Turn struct {
	Author string `json:"author"`
	Text   string `json:"text"`
}

// Meter is the record of one spend: what it cost and whose credential paid.
// It is the last frame of a call's stream and the line written to the log.
type Meter struct {
	Provider   string  `json:"provider"`
	Model      string  `json:"model"`
	Scope      string  `json:"scope"`
	Prompt     int     `json:"prompt"`
	Completion int     `json:"completion"`
	Total      int     `json:"total"`
	CacheRead  int     `json:"cacheRead"`
	CacheWrite int     `json:"cacheWrite"`
	Price      float64 `json:"price"`
	Currency   string  `json:"currency"`
	Millis     int64   `json:"millis"`
}

// ErrUnknownProvider is what a provider hanzoai/ai has no dialect for gets.
var ErrUnknownProvider = errors.New("egress: unknown provider")

// spend resolves the credential for this principal, makes the upstream call and
// streams the answer to w as it arrives. The credential exists only inside this
// function; it is not returned, not logged, and scrubbed out of anything that
// is.
func (s *Server) spend(ctx context.Context, p Principal, in *Call, w *frames) (Meter, error) {
	provider, ok := slug(in.Provider)
	if !ok {
		return Meter{}, ErrUnknownProvider
	}
	label := in.Label
	if label == "" {
		label = "default"
	}
	if !segment(label) {
		return Meter{}, fmt.Errorf("egress: label %q is not a name", in.Label)
	}

	key, scope, err := s.custody.resolve(ctx, p, provider, label)
	if err != nil {
		return Meter{}, err
	}

	breaker := s.breaker(provider)
	if !breaker.Allow() {
		return Meter{}, fmt.Errorf("egress: %s is not answering", in.Provider)
	}

	dialect, err := model.GetModelProvider(
		in.Provider, in.Model, "", key, "",
		in.Temperature, in.TopP, in.TopK, in.FrequencyPenalty, in.PresencePenalty,
		s.cfg.URLs[provider], "", "", 0, 0, "USD", in.Thinking,
	)
	if err != nil {
		breaker.Report(err, 0)
		return Meter{}, scrub(err, key)
	}
	if dialect == nil {
		breaker.Report(nil, 0)
		return Meter{}, ErrUnknownProvider
	}

	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Deadline)
	defer cancel()
	result, err := run(ctx, func() (*model.ModelResult, error) {
		return dialect.QueryText(in.Question, w, turns(in.History), in.Prompt, nil, nil, language(in.Lang))
	})
	breaker.Report(err, 0)
	if err != nil {
		// The dialect may still be running: it took no context and cannot be
		// stopped, only left. Sealing the stream is what keeps its output from
		// arriving after the refusal that replaced it.
		w.seal()
		return Meter{}, scrub(err, key)
	}

	return Meter{
		Provider:   in.Provider,
		Model:      in.Model,
		Scope:      scope,
		Prompt:     result.PromptTokenCount,
		Completion: result.ResponseTokenCount,
		Total:      result.TotalTokenCount,
		CacheRead:  result.CacheReadTokenCount,
		CacheWrite: result.CacheWriteTokenCount,
		Price:      result.TotalPrice,
		Currency:   result.Currency,
		Millis:     time.Since(started).Milliseconds(),
	}, nil
}

// run bounds a dialect call by ctx. The dialects take no context of their own,
// so the deadline is enforced here: the call keeps running in its goroutine
// until the vendor client gives up, but this process stops waiting on it and
// the caller gets an answer.
func run(ctx context.Context, call func() (*model.ModelResult, error)) (*model.ModelResult, error) {
	type answer struct {
		result *model.ModelResult
		err    error
	}
	done := make(chan answer, 1)
	go func() {
		// The dialect runs in a goroutine of its own, and a panic in a
		// goroutine is the whole process unless it is caught where it happens.
		// Caught, a vendor client that falls over is one refused call.
		defer func() {
			if p := recover(); p != nil {
				done <- answer{nil, fmt.Errorf("egress: upstream call failed: %v", p)}
			}
		}()
		result, err := call()
		done <- answer{result, err}
	}()
	select {
	case a := <-done:
		if a.err != nil {
			return nil, a.err
		}
		if a.result == nil {
			return nil, errors.New("egress: upstream returned nothing")
		}
		return a.result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// breaker returns the circuit for one provider, opened when that provider
// starts failing so a vendor outage stops costing every caller a full deadline.
func (s *Server) breaker(provider string) *middleware.Breaker {
	s.circuits.mu.Lock()
	defer s.circuits.mu.Unlock()
	b, ok := s.circuits.by[provider]
	if !ok {
		b = middleware.NewBreaker(middleware.BreakerConfig{})
		s.circuits.by[provider] = b
	}
	return b
}

// circuits holds one breaker per provider.
type circuits struct {
	mu sync.Mutex
	by map[string]*middleware.Breaker
}

// turns converts the caller's history into what the dialects read.
func turns(history []Turn) []*model.RawMessage {
	out := make([]*model.RawMessage, 0, len(history))
	for _, t := range history {
		out = append(out, &model.RawMessage{Author: t.Author, Text: t.Text})
	}
	return out
}

// language falls back to English, which is what the dialects translate their
// own errors into when they are given nothing.
func language(lang string) string {
	if lang == "" {
		return "en"
	}
	return lang
}

// scrub removes the credential from an error. Providers echo parts of a
// rejected key back in their error bodies, and an error is the one value on
// this path that travels to a caller and into a log.
func scrub(err error, key string) error {
	if err == nil || key == "" {
		return err
	}
	text := err.Error()
	if !strings.Contains(text, key) {
		return err
	}
	return errors.New(strings.ReplaceAll(text, key, "[redacted]"))
}

// frames carries provider output to the caller as it arrives. It satisfies what
// a dialect streams into — bytes, plus the flush that puts them on the wire
// before the answer is finished; hanzoai/ai's providers require both and check
// for the second before doing anything else.
//
// It is also the only thing writing to the response, which is what makes the
// deadline safe. A dialect takes no context, so a call that runs past its
// deadline is abandoned rather than stopped, and its goroutine is still writing
// when this process has already moved on to say so. Sealed, those writes stop
// here instead of interleaving with the frame that reports the timeout.
type frames struct {
	mu     sync.Mutex
	to     *bufio.Writer
	sealed bool
}

// errAbandoned is what a dialect writing past its deadline gets. It is an error
// rather than a silent discard so the dialect stops rather than streaming on
// into nothing.
var errAbandoned = errors.New("egress: call abandoned")

func (f *frames) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sealed {
		return 0, errAbandoned
	}
	return f.to.Write(b)
}

// Flush pushes what is buffered. A failure here is not swallowed: bufio keeps
// it and returns it from the next Write, which is how a caller that hung up
// stops the upstream call.
func (f *frames) Flush() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.sealed {
		_ = f.to.Flush()
	}
}

// seal closes the stream to the dialect. What comes after is this process's own
// last word.
func (f *frames) seal() {
	f.mu.Lock()
	f.sealed = true
	f.mu.Unlock()
}

// emit writes one server-sent event of our own — the meter, or the refusal —
// and puts it on the wire. It writes through the seal, because by then the only
// writer left is this one.
func (f *frames) emit(event string, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, _ = f.to.WriteString("event: " + event + "\ndata: ")
	_, _ = f.to.Write(body)
	_, _ = f.to.WriteString("\n\n")
	_ = f.to.Flush()
}
