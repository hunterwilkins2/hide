package main

import (
	"net/url"

	"github.com/apple/pkl-go/pkl"
	glob "github.com/ryanuber/go-glob"
)

func startPklReader(manager *secretsManager) error {
	client, err := pkl.NewExternalReaderClient(
		pkl.WithExternalClientResourceReader(hideReader{manager: manager}),
	)
	if err != nil {
		return err
	}

	return client.Run()
}

type hideReader struct {
	manager *secretsManager
}

var _ pkl.ResourceReader = &hideReader{}

func (r hideReader) Scheme() string {
	return "hide"
}

func (r hideReader) HasHierarchicalUris() bool {
	return false
}

func (r hideReader) IsGlobbable() bool {
	return true
}

func (r hideReader) ListElements(uri url.URL) ([]pkl.PathElement, error) {
	matches := []pkl.PathElement{}
	for key, _ := range r.manager.List() {
		if glob.Glob(uri.Opaque, key) {
			matches = append(matches, pkl.NewPathElement(key, false))
		}
	}
	return matches, nil
}

func (r hideReader) Read(uri url.URL) ([]byte, error) {
	if !r.manager.HasKey(uri.Opaque) {
		return nil, nil
	}
	return []byte(r.manager.Get(uri.Opaque)), nil
}
