package shadowsocks

import (
//    "io"
    "fmt"
    "net"
)

// session info for each connection
type ObfsSessionInfo struct {
    ObfsHeaderSent              bool
    ObfsHeaderRecved            bool
}

type ObfsConn struct {
                        net.Conn
                        *Cipher
        readBuf         []byte
        writeBuf        []byte
        ObfsInfo        *ObfsSessionInfo
}

func (oc *ObfsConn) Close() (err error) {
    ObfsLeakyBuf.Put(oc.readBuf)
    ObfsLeakyBuf.Put(oc.writeBuf)
    oc.Conn.Close()
    Printn("close obfs connection")
    return
}

func ObfsNewConn(c net.Conn) *ObfsConn {
    return &ObfsConn {
            Conn :  c,
            Cipher: nil,
            readBuf: ObfsLeakyBuf.Get(),
            writeBuf: ObfsLeakyBuf.Get(),
            ObfsInfo : &ObfsSessionInfo {
                    ObfsHeaderSent:false,
                    ObfsHeaderRecved:false,
            },
    }
}

func (oc *ObfsConn) GetIv() (iv []byte) {
    iv = make([]byte, len(oc.iv))
    copy(iv, oc.iv)
    return
}

func (oc *ObfsConn) GetIvLen() (ivlen int) {
    ivlen = oc.info.ivLen
    return ivlen
}

func (oc *ObfsConn) GetKey() (key []byte) {
    key = make([]byte, len(oc.key))
    copy(key, oc.key)
    return
}

// Upon connection accepting, read content exists obfs headers.
func (oc *ObfsConn) Read(b []byte) (n int, err error) {
    // first read obfs content upon connection
    if !oc.ObfsInfo.ObfsHeaderRecved {
        n, err = oc.Conn.Read(b)
        oc.ObfsInfo.ObfsHeaderRecved = true
        return n, err
    }
    if oc.Cipher == nil || oc.Cipher.dec == nil {
        err = fmt.Errorf("oc cipher[%p] nullptr or decryptor not init!", oc.Cipher)
        return 0, err
    }
    cipherData := oc.readBuf
    if len(b) > len(cipherData) {
        cipherData = make([]byte, len(b))
    } else {
        cipherData = cipherData[:len(b)]
    }

    n, err = oc.Conn.Read(cipherData)
    if n > 0 {
        oc.decrypt(b[:n], cipherData[:n])
    }
    return
}

func (oc *ObfsConn) Write(b []byte) (n int, err error) {
    var iv []byte
    if oc.Cipher == nil {
        err = fmt.Errorf("oc.Cipher[%p] nullptr!", oc.Cipher)
        return
    }
    if oc.enc == nil {
        Printn("try init encryptor")
        iv, err = oc.initEncrypt()
        if err != nil {
            err = fmt.Errorf("try write->init encrypt error:%s", err.Error())
            return
        }
    }

    cipherData := oc.writeBuf
    dataSize := len(b) + len(iv)
    Printn("try write to client, iv len %d, data size %d",
            len(iv), dataSize)

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
    oc.encrypt(cipherData[len(iv):], b)

    if !oc.ObfsInfo.ObfsHeaderSent {
        obfsData := make([]byte, ObfsResHeaderLen + dataSize)
        copy(obfsData, ObfsResponseHeader)
        copy(obfsData[ObfsResHeaderLen:], cipherData[:dataSize])
        cipherData = obfsData
        oc.ObfsInfo.ObfsHeaderSent = true
        Printn("obfs response header:\n%s", cipherData[:ObfsResHeaderLen])
    }
    n, err = oc.Conn.Write(cipherData)
    return n, err
}

func (oc *ObfsConn) FakeResponse() {
    oc.Conn.Write(FakeHttpResponse)
}

func (oc *ObfsConn) InitDecrypt(iv []byte) (err error) {
    if oc.dec != nil {
        Printn("decrypt already init!")
        return nil
    }
    if oc.Cipher == nil {
        err = fmt.Errorf("cipher[%p] nullptr!", oc.Cipher)
        return
    }
    ivlen := len(iv)
    if ivlen != oc.info.ivLen {
        err = fmt.Errorf("param ivlen[%d] while expect[%d]",
                ivlen, oc.info.ivLen)
        return err
    }
    if err = oc.initDecrypt(iv); err != nil {
        return err
    }
    if len(oc.iv) == 0 {
        oc.iv = iv
    }

    return
}

func (oc *ObfsConn) DecryptByte(dst, src []byte) (err error) {
    if oc.Cipher == nil || oc.dec == nil {
        err = fmt.Errorf("cipher[%p] or decryptor is nil!",
                oc.Cipher)
        return
    }
    if len(dst) < len(src) {
        dst = make([]byte, len(src))
    }
    oc.decrypt(dst, src)
    return
}
