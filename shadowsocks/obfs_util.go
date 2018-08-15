package shadowsocks

import (
    "fmt"
)

const (
    LBufSize        = 4108
    MaxNBuf         = 2048
)

var (
    ObfsLeakyBuf        = NewLeakyBuf(MaxNBuf, LBufSize)
)

// session info for each connection
type ConnSession struct {
    Cipher                      *Cipher
    ObfsHeaderSent              bool
    ObfsHeaderRecved            bool
}

func Printn(format string, content... interface{}) (n int, err error) {
    return fmt.Printf(format + "\n", content...)
}
