package pagination

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"gorm.io/gorm"
)

type Pagination struct {
	Token string `form:"token"`
	Size  int    `form:"size" binding:"omitempty,min=1,max=100"`
}

type Items[T any] struct {
	Items []T    `json:"items"`
	Next  string `json:"next,omitempty"`
}

type Identifiable interface {
	PrimaryKey() uint
}

func CursorPaginate[T Identifiable](query *gorm.DB, pg Pagination) (*Items[T], error) {
	if pg.Token != "" {
		id, err := DecodeCursor(pg.Token)
		if err != nil {
			return nil, fmt.Errorf("无效的游标: %w", err)
		}
		query = query.Where("_id > ?", id)
	}
	if pg.Size <= 0 {
		pg.Size = 20
	}

	var items []T
	if err := query.Order("_id ASC").Limit(pg.Size).Find(&items).Error; err != nil {
		return nil, err
	}

	var next string
	if len(items) == pg.Size {
		next = EncodeCursor(items[len(items)-1].PrimaryKey())
	}
	return &Items[T]{Items: items, Next: next}, nil
}

// Mapping converts Items[T] to Items[U] by applying conv to each item.
func Mapping[T any, U any](page *Items[T], conv func(*T) U) *Items[U] {
	out := make([]U, 0, len(page.Items))
	for i := range page.Items {
		out = append(out, conv(&page.Items[i]))
	}
	return &Items[U]{Items: out, Next: page.Next}
}

var cursorKey [32]byte

func init() {
	if _, err := rand.Read(cursorKey[:]); err != nil {
		panic(fmt.Sprintf("failed to generate cursor key: %v", err))
	}
}

func EncodeCursor(id uint) string {
	buf := binary.AppendUvarint(nil, uint64(id))
	mac := hmac.New(sha256.New, cursorKey[:])
	mac.Write(buf)
	sig := mac.Sum(nil)[:8]
	return base64.RawURLEncoding.EncodeToString(append(buf, sig...))
}

func DecodeCursor(s string) (uint, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, fmt.Errorf("malformed cursor")
	}

	if len(raw) < 2 {
		return 0, fmt.Errorf("malformed cursor")
	}

	id, n := binary.Uvarint(raw)
	if n <= 0 || n+8 > len(raw) {
		return 0, fmt.Errorf("malformed cursor")
	}

	varintBytes := raw[:n]
	sigBytes := raw[n:]
	if len(sigBytes) != 8 {
		return 0, fmt.Errorf("malformed cursor")
	}

	mac := hmac.New(sha256.New, cursorKey[:])
	mac.Write(varintBytes)
	expected := mac.Sum(nil)[:8]

	if !hmac.Equal(expected, sigBytes) {
		return 0, fmt.Errorf("invalid cursor")
	}

	return uint(id), nil
}
