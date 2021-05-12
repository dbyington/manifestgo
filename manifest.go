package manifestgo

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/groob/plist"
)

// Manifest handles the manifest for install application command
type Manifest struct {
	ManifestItems []*Item `plist:"items" json:"manifestItems"`
}

// Item represents an item
type Item struct {
	Assets   []*Asset  `plist:"assets" json:"assets"`
	Metadata *Metadata `plist:"metadata" json:"metadata"`
}

// Asset represents an asset
type Asset struct {
	Kind       string   `plist:"kind" json:"kind"`
	MD5Size    int64    `plist:"md5-size,omitempty" json:"md5_size,omitempty"`
	MD5s       []string `plist:"md5s,omitempty" json:"md5_hash_strings,omitempty"`
	SHA256Size int64    `plist:"sha256-size,omitempty" json:"sha256_size,omitempty"`
	SHA256s    []string `plist:"sha256s,omitempty" json:"sha256_hash_strings,omitempty"`
	URL        string   `plist:"url" json:"url"`
}

// Metadata stores the command meta-data
type Metadata struct {
	BundleIdentifier string `plist:"bundle-identifier" json:"bundle_identifier"`
	BundleVersion    string `plist:"bundle-version" json:"bundle_version"`
	Kind             string `plist:"kind" json:"kind"`
	Title            string `plist:"title" json:"title"`
}

func (m *Manifest) AsJSON(indent int) ([]byte, error) {
	if indent > 0 {
		ind := strings.Repeat(" ", indent)
		return json.MarshalIndent(m, "", ind)
	}

	return json.Marshal(m)
}

func (m *Manifest) AsPlist(indent int) ([]byte, error) {
	if indent > 0 {
		ind := strings.Repeat(" ", indent)
		return plist.MarshalIndent(m, ind)
	}

	return plist.Marshal(m)
}

func (m *Manifest) AsEncodedPlistString(indent int) (string, error) {
	b, err := m.AsPlist(indent)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func BuildPackageManifest(p *Package) (*Manifest, error) {
	a := &Asset{
		Kind: "software-package",
		URL:  p.URL,
	}

	if len(p.Hashes) == 0 {
		return nil, errors.New("unable to create asset: no hashes available")
	}

	for _, h := range p.Hashes {
		if h == nil {
			return nil, errors.New("hash not ready")
		}
		switch p.hashType {
		case md5.Size:
			a.MD5Size = p.Size
			a.MD5s = append(a.MD5s, hex.EncodeToString(h.Sum(nil)))
		case sha256.Size:
			a.SHA256Size = p.Size
			a.SHA256s = append(a.SHA256s, hex.EncodeToString(h.Sum(nil)))
		default:
			fmt.Printf("unsupported hash size: %d, expected %d or %d\n", h.Size(), md5.Size, sha256.Size)
			continue
		}
	}

	metadata := &Metadata{
		BundleIdentifier: p.GetBundleIdentifier(),
		BundleVersion:    p.GetVersion(),
		Kind:             p.GetKind(),
		Title:            p.GetTitle(),
	}

	m := &Manifest{
		ManifestItems: []*Item{
			{
				Assets:   []*Asset{a},
				Metadata: metadata,
			},
		},
	}

	return m, nil
}
