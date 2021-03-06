package httpio

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

var (
	ErrInvalidURLHost        = errors.New("invalid url host")
	ErrInvalidURLScheme      = errors.New("invalid url scheme")
	ErrReadFailed            = errors.New("read failed")
	ErrReadFromSource        = errors.New("read from source")
	ErrRangeReadNotSupported = errors.New("range reads not supported")
	ErrRangeReadNotSatisfied = errors.New("range not satisfied")
)

const ReadSizeLimit = 32768

type Options struct {
	client *http.Client
	url    string
}

type Option func(*Options)

type ReadCloser struct {
	options *Options

	cancel context.CancelFunc
}

type ReadAtCloser struct {
	options       *Options
	contentLength int64

	cancel context.CancelFunc
}

func NewReadAtCloser(opts ...Option) (r *ReadAtCloser, err error) {
	o := new(Options)
	for _, opt := range opts {
		opt(o)
	}

	o.ensureClient()

	if err := o.validateUrl(); err != nil {
		return nil, err
	}

	contentLength, err := o.headURL()
	if err != nil {
		return nil, err
	}

	return &ReadAtCloser{
		contentLength: contentLength,
		options:       o,
	}, nil
}

func WithClient(c *http.Client) Option {
	return func(o *Options) {
		o.client = c
	}
}

func WithURL(url string) Option {
	return func(o *Options) {
		o.url = url
	}
}

func (o *Options) ensureClient() {
	if o.client == nil {
		o.client = new(http.Client)
	}
}

func (o *Options) validateUrl() error {
	u, err := url.Parse(o.url)
	if err != nil {
		return err
	}

	if u.Scheme == "" {
		return ErrInvalidURLScheme
	}

	if u.Hostname() == "" {
		return ErrInvalidURLHost
	}

	return nil
}

func (o *Options) headURL() (int64, error) {
	head, err := o.client.Head(o.url)
	if err != nil {
		return 0, err
	}

	if head.Header.Get("accept-ranges") != "bytes" {
		return 0, ErrRangeReadNotSupported
	}

	return head.ContentLength, nil
}

func (o *Options) HashURL() (hash.Hash, error) {
	res, err := o.client.Get(o.url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	return Sha256SumReader(res.Body)
}

func (r *ReadAtCloser) HashURL() (hash.Hash, error) {
	return r.options.HashURL()
}

func (r *ReadAtCloser) Length() int64 {
	return r.contentLength
}

// ReadAt satisfies the io.ReaderAt interface. It requires that
func (r *ReadAtCloser) ReadAt(b []byte, start int64) (n int, err error) {
	end := start + int64(len(b))
	if r.contentLength < end {
		return 0, ErrReadFromSource
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.options.url, nil)
	if err != nil {
		return 0, err
	}

	requestRange := fmt.Sprintf("bytes=%d-%d", start, end)
	req.Header.Add("Range", requestRange)

	res, err := r.options.client.Do(req)
	if err != nil {
		return 0, err
	}

	if res.StatusCode != http.StatusPartialContent {
		return 0, ErrRangeReadNotSatisfied
	}

	bt := make([]byte, len(b))
	bt, err = ioutil.ReadAll(res.Body)

	copy(b, bt)

	l := int64(len(b))
	if l > res.ContentLength {
		l = res.ContentLength
	}
	return int(l), nil
}

// Close cancels the client context and closes any idle connections.
func (r *ReadAtCloser) Close() error {
	// Ensure a cancellable context has been created else r.cancel will be nil.
	if r.cancel != nil {
		r.cancel()
	}

	r.options.client.CloseIdleConnections()
	return nil
}

func (r *ReadCloser) HashURL() (hash.Hash, error) {
	return r.options.HashURL()
}

func (r *ReadCloser) Read(p []byte) (n int, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.options.url, nil)
	if err != nil {
		return 0, err
	}

	res, err := r.options.client.Do(req)
	if err != nil {
		return 0, err
	}

	if res.StatusCode != http.StatusOK {
		return 0, ErrReadFailed
	}

	bt := make([]byte, len(p))
	bt, err = ioutil.ReadAll(res.Body)

	copy(p, bt)

	l := int64(len(p))
	if l > res.ContentLength {
		l = res.ContentLength
	}
	return int(l), nil
}

// Close cancels the client context and closes any idle connections.
func (r *ReadCloser) Close() error {
	// Ensure a cancellable context has been created else r.cancel will be nil.
	if r.cancel != nil {
		r.cancel()
	}

	r.options.client.CloseIdleConnections()
	return nil
}

// Sha256SumReader reads from r until and calculates the sha256 sum, until r is exhausted.
func Sha256SumReader(r io.Reader) (hash.Hash, error) {
	shaSum := sha256.New()

	buf := make([]byte, ReadSizeLimit)
	if _, err := io.CopyBuffer(shaSum, r, buf); err != nil {
		return nil, err
	}

	return shaSum, nil
}
