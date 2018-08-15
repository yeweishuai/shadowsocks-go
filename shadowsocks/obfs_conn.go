package shadowsocks

import (
	"io"
	"net"
)

// session info for each connection
type ObfsSessionInfo struct {
    ObfsHeaderSent              bool
    ObfsHeaderRecved            bool
}

type ObfsConn struct {
                        *Conn
        ObfsInfo        *ObfsSessionInfo
}

func ObfsNewConn(c net.Conn) *ObfsConn {
    return &ObfsConn {
            Conn :  NewConn(c, nil),
            ObfsInfo : &ObfsSessionInfo {
                    ObfsHeaderSent:false,
                    ObfsHeaderRecved:false,
            },
    }
}

func (c *ObfsConn) Deobfs(b []byte) (n int, err error) {
    return
}

// first time, read size varies as obfs
// So actual return size may exceed expect slice array size
func (c *ObfsConn) Read(b []byte) (n int, err error) {
        if c.Cipher == nil {
            return c.Deobfs(b)
        }


	if c.dec == nil {
		iv := make([]byte, c.info.ivLen)
		if _, err = io.ReadFull(c.Conn, iv); err != nil {
			return
		}
		if err = c.initDecrypt(iv); err != nil {
			return
		}
		if len(c.iv) == 0 {
			c.iv = iv
		}
	}

	cipherData := c.readBuf
	if len(b) > len(cipherData) {
		cipherData = make([]byte, len(b))
	} else {
		cipherData = cipherData[:len(b)]
	}

	n, err = c.Conn.Read(cipherData)
	if n > 0 {
		c.decrypt(b[0:n], cipherData[0:n])
	}
	return
}

func (c *ObfsConn) Write(b []byte) (n int, err error) {
	var iv []byte
	if c.enc == nil {
		iv, err = c.initEncrypt()
		if err != nil {
			return
		}
	}

	cipherData := c.writeBuf
	dataSize := len(b) + len(iv)
	if dataSize > len(cipherData) {
		cipherData = make([]byte, dataSize)
	} else {
		cipherData = cipherData[:dataSize]
	}

	if iv != nil {
		// Put initialization vector in buffer, do a single write to send both
		// iv and data.
		copy(cipherData, iv)
	}

	c.encrypt(cipherData[len(iv):], b)
	n, err = c.Conn.Write(cipherData)
	return
}
