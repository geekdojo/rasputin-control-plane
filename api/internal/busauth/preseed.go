package busauth

import (
	"encoding/json"
	"fmt"
)

// ParsePreseed decodes a matched-set preseed file: the JSON array of
// {hash,nodeId,label} that rasputin-provision writes to the controlplane's seed
// media, and that the api preloads into the token store at boot.
//
// It is parse-only, and pure so it can be fuzzed (geekdojo-brain#106): the
// entries it returns are validated by Store.PreloadHashes, which owns the rules
// about node binding. An entry naming no node is legal here and means an
// unbound token (see geekdojo-brain#423).
func ParsePreseed(data []byte) ([]PreseedToken, error) {
	var toks []PreseedToken
	if err := json.Unmarshal(data, &toks); err != nil {
		return nil, fmt.Errorf("parse preseed: %w", err)
	}
	return toks, nil
}
