package binding

import (
	"encoding/json"
	"strings"
)

// NewDelimitedType 生成一个以指定分隔符切分/拼接的 []string 类型的序列化/反序列化辅助。
// 返回 marshal / unmarshal / unmarshalText 三个函数，可直接用于自定义类型的接口实现。
func NewDelimitedType(sep string) (
	marshalFn func(values []string) ([]byte, error),
	unmarshalFn func(data []byte) ([]string, error),
	unmarshalTextFn func(text []byte) []string,
) {
	split := func(raw string) []string {
		if sep == " " {
			return strings.Fields(raw)
		}
		parts := strings.Split(raw, sep)
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				result = append(result, t)
			}
		}
		return result
	}

	marshalFn = func(values []string) ([]byte, error) {
		return json.Marshal(strings.Join(values, sep))
	}

	unmarshalFn = func(data []byte) ([]string, error) {
		var raw string
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
		return split(raw), nil
	}

	unmarshalTextFn = func(text []byte) []string {
		return split(string(text))
	}

	return marshalFn,
		unmarshalFn,
		unmarshalTextFn
}

// SpaceDelimited 空格分隔的字符串列表（OAuth2 标准的 scope / prompt 等）
// JSON/form 传输格式为空格分隔的字符串，Go 侧为 []string
type SpaceDelimited []string

var (
	spaceMarshal, spaceUnmarshal, spaceUnmarshalText = NewDelimitedType(" ")
)

func (s SpaceDelimited) MarshalJSON() ([]byte, error) {
	return spaceMarshal(s)
}

func (s *SpaceDelimited) UnmarshalJSON(data []byte) error {
	v, err := spaceUnmarshal(data)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

func (s *SpaceDelimited) UnmarshalText(text []byte) error {
	*s = spaceUnmarshalText(text)
	return nil
}

func (s SpaceDelimited) String() string {
	return strings.Join(s, " ")
}

func (s SpaceDelimited) Contains(v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

// CommaDelimited 逗号分隔的字符串列表
type CommaDelimited []string

var (
	commaMarshal, commaUnmarshal, commaUnmarshalText = NewDelimitedType(",")
)

func (c CommaDelimited) MarshalJSON() ([]byte, error) {
	return commaMarshal(c)
}

func (c *CommaDelimited) UnmarshalJSON(data []byte) error {
	v, err := commaUnmarshal(data)
	if err != nil {
		return err
	}
	*c = v
	return nil
}

func (c *CommaDelimited) UnmarshalText(text []byte) error {
	*c = commaUnmarshalText(text)
	return nil
}

func (c CommaDelimited) String() string {
	return strings.Join(c, ",")
}

func (c CommaDelimited) Contains(v string) bool {
	for _, item := range c {
		if item == v {
			return true
		}
	}
	return false
}
