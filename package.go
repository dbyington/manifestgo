package manifestgo

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"hash"
	"io"
	"os"
	"strings"
	"sync"

	xar "github.com/dbyington/manifestgo/goxar"
)

const ReadSizeLimit = 32768

type sourceFile string

const (
	sourcePackageInfo  sourceFile = "PackageInfo"
	sourceDistribution sourceFile = "Distribution"
)

type Bundle struct {
	ID      string `xml:"id,attr"`
	Path    string `xml:"path,attr"`
	Version string `xml:"CFBundleVersion,attr"`
}

type Line struct {
	Choice string `xml:"choice,attr"`
}

type Choice struct {
	ID          string   `xml:"id,attr"`
	Title       string   `xml:"title,attr"`
	Description string   `xml:"description,attr"`
	PkgRef      []PkgRef `xml:"pkg-ref"`
}

type PkgInfo struct {
	Identifier string   `xml:"identifier,attr"`
	Version    string   `xml:"version,attr"`
	Bundle     []Bundle `xml:"bundle"`
}
type PkgRef struct {
	Bundle            []Bundle `xml:"bundle-version>bundle"`
	ID                string   `xml:"id,attr"`
	PackageIdentifier string   `xml:"packageIdentifier,attr"`
	Version           string   `xml:"version,attr"`
	Package           string
}

type Package struct {
	Choice  Choice   `xml:"choice"`
	PkgInfo PkgInfo  `xml:"pkg-info"`
	PkgRef  []PkgRef `xml:"pkg-ref"`
	Title   string   `xml:"title"`
	Hashes  []hash.Hash
	URL     string
	Size    int64

	id string

	// Resource info
	ContentLength int64
	Etag          string

	hashChunkSize int64
	hashType      uint
	reader        PackageReader
	source        sourceFile
}

type PackageReader interface {
	HashURL(uint) ([]hash.Hash, error)
	Length() int64
	Etag() string
	URL() string
	ReadAt(p []byte, off int64) (n int, err error)
}

func NewPackage(pr PackageReader, hashTypeSize uint, hashChunkSize int64) *Package {
	return &Package{
		reader:        pr,
		hashChunkSize: hashChunkSize,
		hashType:      hashTypeSize,
	}
}

func (p *Package) GetBundleIdentifier() string {
	if p == nil {
		return ""
	}
	if p.source == sourcePackageInfo {
		return p.PkgInfo.Identifier
	}

	id := p.getPrimaryPkgRefBundle().ID

	if id == "" {
		id = p.getPrimaryPkgRef().ID
	}

	return id
}

func (p *Package) getPrimaryPkgRef() PkgRef {
	if p == nil {
		return PkgRef{}
	}

	if len(p.Choice.PkgRef) > 0 && p.Choice.ID != "" {
		for _, cPkg := range p.PkgRef {
			if cPkg.ID == p.Choice.ID {
				if cPkg.Version != "" || len(cPkg.Bundle) != 0 {
					return cPkg
				}
			}
		}
	}

	if len(p.PkgRef) == 0 {
		return PkgRef{}
	}

	return p.PkgRef[0]
}

func (p *Package) getPrimaryPkgRefBundle() Bundle {
	if p == nil {
		return Bundle{}
	}

	pkgRef := p.getPrimaryPkgRef()

	if len(pkgRef.Bundle) == 0 {
		return Bundle{}
	}

	for _, b := range pkgRef.Bundle {
		if strings.EqualFold(b.ID, pkgRef.ID) {
			return b
		}
	}

	return pkgRef.Bundle[0]
}

func (p *Package) GetVersion() string {
	if p == nil {
		return ""
	}

	if p.source == sourcePackageInfo {
		return p.PkgInfo.Version
	}

	v := p.getPrimaryPkgRef().Version

	if v == "" {
		v = p.getPrimaryPkgRefBundle().Version
	}

	return v
}

func (p *Package) GetKind() string {
	if p == nil {
		return ""
	}
	return "software"
}

func (p *Package) GetPath() string {
	if p == nil {
		return ""
	}
	return p.getPrimaryPkgRefBundle().Path
}

func (p *Package) GetTitle() string {
	if p == nil {
		return ""
	}

	if p.source == sourcePackageInfo {
		primaryPkgID := p.PkgInfo.Identifier
		if strings.HasSuffix(primaryPkgID, "pkg") {
			pkgID := strings.Split(p.PkgInfo.Identifier, ".")
			primaryPkgID = strings.Join(pkgID[:len(pkgID)-1], ".")
		}

		for _, bundle := range p.PkgInfo.Bundle {
			if bundle.ID == primaryPkgID {
				b := strings.SplitAfter(bundle.Path, "/")
				t := strings.Split(b[len(b)-1], ".")
				return t[0]
			}
		}
	}

	if p.Title != "" {
		return p.Title
	}

	// TODO: Can this be used if the Title is not available or is obviously not what should be used?
	// pkgID := strings.Split(p.GetBundleIdentifier(), ".")
	// primaryPkgID := strings.Join(pkgID[:len(pkgID)-1], ".")
	// for _, b := range p.getPrimaryPkgRef().Bundle {
	//     if b.ID == primaryPkgID {
	//         fmt.Printf("Got Bundle: %+v\n", b)
	//     }
	// }

	if p.GetPath() != "" {
		path := strings.Split(p.GetPath(), "/")
		t := strings.Split(path[len(path)-1], ".")
		p.Title = t[0]
	} else {
		sub := strings.Split(p.GetBundleIdentifier(), ".")
		p.Title = strings.Title(sub[len(sub)-1])
	}

	return p.Title
}

func (p *Package) GetHashStrings() []string {
	s := make([]string, len(p.Hashes))
	for i, h := range p.Hashes {
		s[i] = hex.EncodeToString(h.Sum(nil))
	}

	return s
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

func (p *Package) ReadFromURL() error {
	urlHasher := p.reader.HashURL
	if urlHasher == nil {
		return errors.New("no hasher")
	}

	// Hasing the file could take a while so we're going to farm that out immediately and inspect the error later.
	var (
		hashes  []hash.Hash
		hashErr error
	)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		hashes, hashErr = p.reader.HashURL(p.hashType)
	}(wg)

	size := p.reader.Length()
	if p.hashChunkSize < size {
		size = p.hashChunkSize
	}

	p.Size = size
	p.URL = p.reader.URL()
	p.Etag = p.reader.Etag()

	x, err := xar.NewReader(p.reader, p.reader.Length())
	if err != nil {
		return err
	}

	if err = p.fill(x); err != nil {
		return err
	}

	wg.Wait()
	if hashErr != nil {
		return hashErr
	}
	p.Hashes = append(p.Hashes, hashes...)

	return nil
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
		distReader, err := f.Open()
		if err != nil {
			return err
		}

		b := make([]byte, f.Size)
		_, err = io.ReadFull(distReader, b)
		if err != nil {
			return err
		}

		// Because this could come from one of two sources, which have slightly different layouts we unmarshal into different interfaces depending on the file.
		switch sourceFile(f.Name) {
		case sourceDistribution:
			if err := xml.Unmarshal(b, &p); err != nil {
				return err
			}
		case sourcePackageInfo:
			var pi PkgInfo
			if err := xml.Unmarshal(b, &pi); err != nil {
				return err
			}
			p.PkgInfo = pi
		}
		p.source = sourceFile(f.Name)
	}

	return nil
}
