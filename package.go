package manifestgo

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"hash"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/dbyington/httpio"
	"github.com/sirupsen/logrus"

	xar "github.com/dbyington/manifestgo/goxar"
)

const ReadSizeLimit = 32768

type Bundle struct {
	Version  string `xml:"CFBundleVersion,attr"`
	ID       string `xml:"id,attr"`
	SubTitle string `xml:"path,attr"`
}

type PkgRef struct {
	Version string `xml:"version,attr" json:"version"`
	Bundle  Bundle `xml:"bundle-version>bundle"`
}

type Package struct {
	PkgRef PkgRef `xml:"pkg-ref"`
	Title  string `xml:"title"`
	Hashes []hash.Hash
	URL    string
	Size   int64

	// Resource info
	ContentLength int64
	Etag          string
}

func (p *Package) GetBundleIdentifier() string {
	return p.PkgRef.Bundle.ID
}
func (p *Package) GetBundleVersion() string {
	return p.PkgRef.Bundle.Version
}
func (p *Package) GetKind() string {
	return "software"
}
func (p *Package) GetSubtitle() string {
	return p.PkgRef.Bundle.SubTitle
}
func (p *Package) GetTitle() string {
	if p.Title == "" {
		if p.GetSubtitle() != "" {
			p.Title = strings.TrimRight(p.GetSubtitle(), ".APPapp")
		} else {
			sub := strings.Split(p.GetBundleIdentifier(), ".")
			p.Title = strings.Title(sub[len(sub)-1])
		}
	}
	return p.Title
}

func (p *Package) BuildManifest() (*Manifest, error) {
	return BuildPackageManifest(p)
}

func (p *Package) AsJSON(indent int) ([]byte, error) {
	if indent >= 0 {
		ind := strings.Repeat(" ", indent)
		return json.MarshalIndent(p, "", ind)
	}

	return json.Marshal(p)
}

func ReadPkgUrl(client *http.Client, url string, hashSize uint, hashChunkSize int64, expect map[string]string) (*Package, error) {
	r, err := httpio.NewReadAtCloser(httpio.WithClient(client), httpio.WithURL(url), httpio.WithExpectHeaders(expect))
	if err != nil {
		return nil, err
	}

	// Hasing the file could take a while so we're going to farm that out immediately and inspect the error later.
	var (
		hashes  []hash.Hash
		hashErr error
	)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	logrus.Infof("hashing with a hash chunk size of: %d", hashChunkSize)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		hashes, hashErr = r.HashURL(hashSize, hashChunkSize)
	}(wg)

	p := &Package{
		Size: r.Length(),
		URL:  url,
		Etag: r.Etag(),
	}

	x, err := xar.NewReader(r, r.Length())
	if err != nil {
		return nil, err
	}

	if err = p.fill(x); err != nil {
		return nil, err
	}

	wg.Wait()
	if hashErr != nil {
		return nil, hashErr
	}
	logrus.Infof("got %d hash chunks", len(hashes))
	p.Hashes = append(p.Hashes, hashes...)

	return p, nil
}

func ReadPkgFile(name string) (*Package, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	fstat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	br := bufio.NewReader(f)
	shaSum, err := Sha256SumReader(br)
	if err != nil {
		return nil, err
	}

	p := &Package{
		Hashes: []hash.Hash{shaSum},
		Size:   fstat.Size(),
	}

	r, err := xar.NewReader(f, fstat.Size())
	if err != nil {
		return nil, err
	}

	if err := p.fill(r); err != nil {
		return nil, err
	}

	return p, nil
}

func Sha256SumReader(r io.Reader) (hash.Hash, error) {
	shaSum := sha256.New()

	buf := make([]byte, ReadSizeLimit)
	if _, err := io.CopyBuffer(shaSum, r, buf); err != nil {
		return nil, err
	}

	return shaSum, nil
}

func (p *Package) fill(r *xar.Reader) error {
	for _, f := range r.File {
		// The reader should have only collected the Distribution file but just in case...
		if f.Name != "Distribution" {
			continue
		}

		distReader, err := f.Open()
		if err != nil {
			return err
		}

		b := make([]byte, f.Size)
		_, err = io.ReadFull(distReader, b)
		if err != nil {
			return err
		}

		if err := xml.Unmarshal(b, &p); err != nil {
			return err
		}

	}
	return nil
}
