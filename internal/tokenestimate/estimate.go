package tokenestimate

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/pkoukk/tiktoken-go"
)

const EncodingName = "o200k_base"

// o200kBaseVocab is the BPE vocabulary for the o200k_base encoding, embedded
// into the binary at build time. tiktoken-go's default loader downloads this
// from openaipublic.blob.core.windows.net on first use — a host that is
// unreachable from this deployment, which made the first agent run after every
// process start hang for minutes. Embedding the vocabulary removes that network
// dependency entirely: no blob host at runtime, no CDN/Go-module fetch at
// Docker build time.
//
//go:embed assets/o200k_base.tiktoken
var o200kBaseVocab []byte

// embeddedBpeLoader satisfies tiktoken.BpeLoader by serving the embedded
// o200k_base ranks instead of fetching over the network. This package only
// ever asks for o200k_base, so the requested file argument is ignored.
type embeddedBpeLoader struct{}

func (embeddedBpeLoader) LoadTiktokenBpe(_ string) (map[string]int, error) {
	ranks := make(map[string]int, 200000)
	for _, line := range strings.Split(string(o200kBaseVocab), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		token, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, fmt.Errorf("decode token %q: %w", parts[0], err)
		}
		rank, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("parse rank %q: %w", parts[1], err)
		}
		ranks[string(token)] = rank
	}
	if len(ranks) == 0 {
		return nil, fmt.Errorf("embedded o200k_base vocabulary is empty")
	}
	return ranks, nil
}

// The tokenizer is built once, lazily, from the embedded vocabulary. This is
// pure CPU (parse ~200k ranks, build the map) — no network, no I/O, ~100ms,
// and it cannot hang. There is deliberately no heuristic fallback: token
// counts are always exact. A load failure here is only possible if the
// embedded asset is corrupt, which the package tests catch at build time, so
// it is treated as a fatal programmer error.
var (
	tokenizer     *tiktoken.Tiktoken
	tokenizerOnce sync.Once
)

func getTokenizer() *tiktoken.Tiktoken {
	tokenizerOnce.Do(func() {
		tiktoken.SetBpeLoader(embeddedBpeLoader{})
		tok, err := tiktoken.GetEncoding(EncodingName)
		if err != nil {
			panic(fmt.Sprintf("tokenestimate: embedded %s tokenizer failed to load: %v", EncodingName, err))
		}
		tokenizer = tok
	})
	return tokenizer
}

func EstimateText(text string) int64 {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0
	}
	return int64(len(getTokenizer().Encode(trimmed, nil, nil)))
}
