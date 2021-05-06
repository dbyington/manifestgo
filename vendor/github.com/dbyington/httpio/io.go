package httpio

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Possible errors
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

// MaxConcurrentReaders limits the number of concurrent reads.
const MaxConcurrentReaders = 5

// RequestError fulfills the error type for reporting more specific errors with http requests.
type RequestError struct {
	StatusCode string
	Url        string
}

// Error returns the string of a RequestError.
func (r RequestError) Error() string {
	return fmt.Sprintf("Error requesting %s, received code: %s", r.Url, r.StatusCode)
}

// ReadSizeLimit is the maximum size buffer chunk to operate on.
const ReadSizeLimit = 32768

// Options contains the parts to create and use a ReadCloser or ReadAtCloser
type Options struct {
	client               *http.Client
	hashChunkSize        int64
	expectHeaders        map[string]string
	maxConcurrentReaders int64
	url                  string
}

// Option is a func type used to pass options to the New* funcs.
type Option func(*Options)

// ReadCloser contains the required parts to implement a io.ReadCloser on a URL.
type ReadCloser struct {
	options *Options

	cancel context.CancelFunc
}

type readClient interface {
	do(req *http.Request) (*http.Response, error)
}

type readAtCloseRead struct {
	client    readClient
	ctx       context.Context
	cancelCTX context.CancelFunc
	id        string
}

func (r *ReadAtCloser) newReader() *readAtCloseRead {
	ctx, cancel := context.WithCancel(r.ctx)
	reader := &readAtCloseRead{
		client:    r,
		ctx:       ctx,
		cancelCTX: cancel,
		id:        randomString(),
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.readers[reader.id] = reader

	return reader
}

func (r *readAtCloseRead) cancel() {
	r.cancelCTX()
}

// ReadAtCloser contains the required options and metadata to implement io.ReadAtCloser on a URL.
// Use the Options to configure the ReadAtCloser with an http.Client, URL, and any additional http.Header values that should be sent with the request.
type ReadAtCloser struct {
	options       *Options
	contentLength int64
	etag          string

	ctx               context.Context
	cancel            context.CancelFunc
	readerWG          *sync.WaitGroup
	concurrentReaders chan struct{}
	mutex             *sync.Mutex
	readers           map[string]*readAtCloseRead
}

func (r *ReadAtCloser) do(req *http.Request) (*http.Response, error) {
	r.concurrentReaders <- struct{}{}
	res, err := r.options.client.Do(req)
	<-r.concurrentReaders
	return res, err
}

func (r *ReadAtCloser) finishReader(id string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	reader, ok := r.readers[id]
	if !ok {
		return
	}

	reader.cancel()
	delete(r.readers, id)
}

// NewReadAtCloser validates the options provided and returns a new a *ReadAtCloser after validating the URL. The URL validation includes basic scheme and hostnane checks.
func NewReadAtCloser(opts ...Option) (r *ReadAtCloser, err error) {
	o := &Options{expectHeaders: make(map[string]string)}
	for _, opt := range opts {
		opt(o)
	}

	o.ensureClient()

	if err := o.validateUrl(); err != nil {
		return nil, err
	}

	maxReaders := o.maxConcurrentReaders
	if maxReaders == 0 {
		maxReaders = MaxConcurrentReaders
	}

	contentLength, etag, err := o.headURL(o.expectHeaders)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &ReadAtCloser{
		contentLength:     contentLength,
		etag:              etag,
		options:           o,
		ctx:               ctx,
		cancel:            cancel,
		mutex:             &sync.Mutex{},
		concurrentReaders: make(chan struct{}, maxReaders),
		readerWG:          &sync.WaitGroup{},
		readers:           make(map[string]*readAtCloseRead),
	}, nil
}

// WithClient is an Option func which allows the user to supply their own instance of an http.Client. If not supplied a new generic http.Client is created.
func WithClient(c *http.Client) Option {
	return func(o *Options) {
		o.client = c
	}
}

// WithURL (REQUIRED) is an Option func used to supply the full url string; scheme, host, and path, to be read.
func WithURL(url string) Option {
	return func(o *Options) {
		o.url = url
	}
}

// WithMaxConcurrentReaders is an Option to set the maximum number of concurrent go funcs performing Reads in any Reader. If not supplied the default MaxConcurrentReaders is used.
func WithMaxConcurrentReaders(r int64) Option {
	return func(o *Options) {
		o.maxConcurrentReaders = r
	}
}

// WithExpectHeaders is an Option func used to specify any expected response headers from the server.
func WithExpectHeaders(e map[string]string) Option {
	return func(o *Options) {
		o.expectHeaders = e
	}
}

// WithHashChunkSize is an Option func to specify the size to chunk content at when hashing the content.
func WithHashChunkSize(s int64) Option {
	return func(o *Options) {
		o.hashChunkSize = s
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

	// This is really annoying, but we have to strip the quotes around the string.
	etag := strings.Trim(head.Header.Get("Etag"), "\"")
	return head.ContentLength, etag, nil
}

func (o *Options) hashURL(hashSize uint) (hash.Hash, error) {
	res, err := o.client.Get(o.url)
	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode > 399 {
		return nil, RequestError{StatusCode: res.Status, Url: o.url}
	}

	defer res.Body.Close()

	switch hashSize {
	case sha256.Size:
		return sha256SumReader(res.Body)
	default:
		return md5SumReader(res.Body)
	}
}

// HashURL takes the hash scheme as a uint (either sha256.Size or md5.Size) and the chunk size, and returns the hashed URL body in the supplied scheme as a slice of hash.Hash.
// When the chunk size is less than the length of the content, the URL will be read with multiple, concurrent range reads to create the slice of hash.Hash.
// Specifying a chunkSize <= 0 is translated to "do not chunk" and the entire content will be hashed as one chunk.
// The size and capacity of the returned slice of hash.Hash is equal to the number of chunks calculated based on the content length divided by the chunkSize, or 1 if chunkSize is equal to, or less than 0.
func (r *ReadAtCloser) HashURL(scheme uint) ([]hash.Hash, error) {
	r.mutex.Lock()
	cl := r.contentLength
	chunkSize := r.options.hashChunkSize
	r.mutex.Unlock()

	if chunkSize <= 0 {
		chunkSize = cl
	}
	var chunks int64

	// If chunkSize is greater than the content length reset it to the available length and set number of chunks to 1.
	// Otherwise we need to divide the length by the number of chunks and round up. The final chunkSize will be the sum of the remainder.
	if chunkSize > cl {
		chunkSize = cl
		chunks = 1
	} else {
		chunks = int64(math.Ceil(float64(cl) / float64(chunkSize)))
	}

	var hasher func(reader io.Reader) (hash.Hash, error)

	switch scheme {
	case sha256.Size:
		hasher = sha256SumReader
	default:
		hasher = md5SumReader
	}

	hashes := make([]hash.Hash, chunks, chunks)
	hashErrs := make([]error, chunks)
	wg := sync.WaitGroup{}

	for i := int64(0); i < chunks; i++ {
		wg.Add(1)
		go func(w *sync.WaitGroup, idx int64, size int64, rac *ReadAtCloser) {
			defer w.Done()
			b := make([]byte, size)
			if _, err := rac.ReadAt(b, size*idx); err != nil {
				hashErrs[idx] = err
				if err != io.ErrUnexpectedEOF {
					return
				}
			}

			reader := bytes.NewReader(b[:])
			h, err := hasher(reader)
			if err != nil {
				hashErrs[idx] = err
				return
			}

			hashes[idx] = h
		}(&wg, i, chunkSize, r)
	}

	wg.Wait()
	if err := checkErrSlice(hashErrs); err != nil {
		return hashes, err
	}
	return hashes, nil
}

func checkErrSlice(es []error) (err error) {
	for _, e := range es {
		if e != nil {
			if err == nil {
				err = fmt.Errorf("%s: %s", err, e)
				continue
			}
			err = e
		}
	}
	return nil
}

// Length returns the reported ContentLength of the URL body.
func (r *ReadAtCloser) Length() int64 {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.contentLength
}

// Etag returns the last read Etag from the URL being operated on by the configured ReadAtCloser.
func (r *ReadAtCloser) Etag() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.etag
}

// ReadAt satisfies the io.ReaderAt interface. It requires the ReadAtCloser be previously configured.
func (r *ReadAtCloser) ReadAt(b []byte, start int64) (n int, err error) {
	end := start + int64(len(b))

	r.readerWG.Add(1)
	defer r.readerWG.Done()

	reader := r.newReader()
	defer r.finishReader(reader.id)
	req, err := http.NewRequestWithContext(reader.ctx, http.MethodGet, r.options.url, nil)
	if err != nil {
		return 0, err
	}

	requestRange := fmt.Sprintf("bytes=%d-%d", start, end)
	req.Header.Add("Range", requestRange)

	res, err := reader.client.do(req)
	if err != nil {
		return 0, err
	}

	if res.StatusCode != http.StatusPartialContent {
		return 0, ErrRangeReadNotSatisfied
	}

	bt := make([]byte, len(b))
	bt, err = ioutil.ReadAll(res.Body)

	copy(b, bt)

	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.contentLength < end {
		return int(res.ContentLength - start), io.ErrUnexpectedEOF
	}

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

	r.readerWG.Wait()
	return nil
}

// HashURL takes the hash scheme size (sha256.Size or md5.Size) and returns the hashed URL body in the supplied scheme as a hash.Hash interface.
func (r *ReadCloser) HashURL(size uint) (hash.Hash, error) {
	return r.options.hashURL(size)
}

// Read fulfills the io.Reader interface. The ReadCloser must be previously configured. The body of the configured URL is read into p, up to len(p). If the length of p is greater than the ContentLength of the body the length returned will be ContentLength.
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

// sha256SumReader reads from r until and calculates the sha256 sum, until r is exhausted.
func sha256SumReader(r io.Reader) (hash.Hash, error) {
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

func randomString() string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	s := make([]rune, rand.Intn(25)+25)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}
