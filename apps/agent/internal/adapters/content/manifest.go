package content

type Manifest struct {
	Version string          `json:"version"`
	Entries []ManifestEntry `json:"entries"`
}

type ManifestEntry struct {
	Ref     string `json:"ref"`
	Kind    string `json:"kind"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	File    string `json:"file"`
}
