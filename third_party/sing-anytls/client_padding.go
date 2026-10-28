package anytls

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"math/big"

	"github.com/anytls/sing-anytls/padding"
)

const (
	privateAuthPaddingMin = 32
	privateAuthPaddingMax = 256
)

// authenticationPaddingLength keeps the standard authentication layout and honors custom server schemes.
func authenticationPaddingLength(factory *padding.PaddingFactory, enhanced bool) (int, error) {
	return selectAuthenticationPadding(factory, enhanced, rand.Reader)
}

func selectAuthenticationPadding(factory *padding.PaddingFactory, enhanced bool, random io.Reader) (int, error) {
	if enhanced && bytes.Equal(factory.RawScheme, padding.DefaultPaddingScheme) {
		width := big.NewInt(privateAuthPaddingMax - privateAuthPaddingMin + 1)
		value, err := rand.Int(random, width)
		if err != nil {
			return 0, fmt.Errorf("generate authentication padding: %w", err)
		}
		return privateAuthPaddingMin + int(value.Int64()), nil
	}
	var size int
	if sizes := factory.GenerateRecordPayloadSizes(0); len(sizes) > 0 {
		size = sizes[0]
	}
	if size < 0 || size > math.MaxUint16 {
		return 0, fmt.Errorf("authentication padding length %d exceeds uint16 range", size)
	}
	return size, nil
}
