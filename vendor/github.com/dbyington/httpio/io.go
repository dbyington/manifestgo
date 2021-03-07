package httpio

import (
	"context"
	"crypto/md5"
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

	ErrHeaderEtag          = errors.New("etag header differs")
	ErrHeaderContentLength = errors.New("content length differs")
	headerErrs             = map[string]error{
		"Etag":           ErrHeaderEtag,
		"Content-Length": ErrHeaderContentLength,
	}
)

const ReadSizeLimit = 32768

type Options struct {
	client        *http.Client
	url           string
	expectHeaders map[string]string
}

type Option func(*Options)

type ReadCloser struct {
	options *Options

	cancel context.CancelFunc
}

type ReadAtCloser struct {
	options       *Options
	contentLength int64
	etag          string

	cancel context.CancelFunc
}

func NewReadAtCloser(opts ...Option) (r *ReadAtCloser, err error) {
	o := &Options{expectHeaders: make(map[string]string)}
	for _, opt := range opts {
		opt(o)
	}

	o.ensureClient()

	if err := o.validateUrl(); err != nil {
		return nil, err
	}

	contentLength, etag, err := o.headURL(o.expectHeaders)
	if err != nil {
		return nil, err
	}

	return &ReadAtCloser{
		contentLength: contentLength,
		etag:          etag,
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

func WithExpectHeaders(e map[string]string) Option {
	return func(o *Options) {
		o.expectHeaders = e
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

func (o *Options) headURL(expectHeaders map[string]string) (int64, string, error) {
	head, err := o.client.Head(o.url)
	if err != nil {
		return 0, "", err
	}

	if head.Header.Get("accept-ranges") != "bytes" {
		return 0, "", ErrRangeReadNotSupported
	}

	for k, v := range expectHeaders {
		if sent := head.Header.Get(k); sent != v {
			return 0, "", headerErrs[k]
		}
	}

	return head.ContentLength, head.Header.Get("Etag"), nil
}

func (o *Options) HashURL(hashSize uint) (hash.Hash, error) {
	res, err := o.client.Get(o.url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	switch hashSize {
	case sha256.Size:
		return Sha256SumReader(res.Body)
	default:
		return md5SumReader(res.Body)
	}
}

func (r *ReadAtCloser) HashURL(size uint) (hash.Hash, error) {
	return r.options.HashURL(size)
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

func (r *ReadCloser) HashURL(size uint) (hash.Hash, error) {
	return r.options.HashURL(size)
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

// md5SumReader reads from r until and calculates the md5 sum, until r is exhausted.
func md5SumReader(r io.Reader) (hash.Hash, error) {
	md5sum := md5.New()
	buf := make([]byte, ReadSizeLimit)
	if _, err := io.CopyBuffer(md5sum, r, buf); err != nil {
		return nil, err
	}

	return md5sum, nil
}
