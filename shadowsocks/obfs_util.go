package shadowsocks

import (
    "fmt"
    "encoding/hex"
    "strings"
)

const (
    LBufSize        = 4108
    MaxNBuf         = 2048

    ObfsHiddenIn    = "Cookie"
    ObfsColonSeperator = ":"
    ObfsKeyValueSeperator = "="
    ObfsItemSeperator = ";"
    ObfsPassKey = "cid"

    OnFailHttpResponse = "HTTP/1.1 302 Found\r\n" +
            "Location: http://cn.bing.com/\r\n" +
            "Server: Microsoft-IIS/10.0\r\n" +
            "Content-Length: 0\r\n" +
            "\r\n" +
            "<html><body>Redirecting...</body></html>"

    ObfsHttpResponse = "HTTP/1.1 200 OK\r\n" +
            "Connection: keep-alive\r\n" +
            "Content-Encoding: gzip\r\n" +
            "Content-Type: text/html\r\n" +
            "Server: nginx\r\n" +
            "Vary: Accept-Encoding\r\n" +
            "\r\n"
)

var (
    ObfsLeakyBuf        = NewLeakyBuf(MaxNBuf, LBufSize)
    FakeHttpResponse    = []byte(OnFailHttpResponse)
    ObfsResponseHeader  = []byte(ObfsHttpResponse)
    ObfsResHeaderLen    = len(ObfsResponseHeader)
)

func Printn(format string, content... interface{}) (n int, err error) {
    return fmt.Printf(format + "\n", content...)
}

// parse obfs header
type ObfsHeader struct {
    Pass            string
    RandHead        []byte
    // more to extend
}

func ParseObfsHeader(header *string) (obfs *ObfsHeader, err error) {
    if header == nil {
        err = fmt.Errorf("obfs heder[%p] nullptr", header)
        Printn("%s", err.Error())
        return nil, err
    }
    str_arr := strings.Split(*header, "\r\n")
    arr_len := len(str_arr)
    min_len := 2
    if arr_len < min_len {
        err = fmt.Errorf("obfs fields len[%d] while min len[%d]", arr_len, min_len)
        Printn("%s", err.Error())
        return nil, err
    }

    // compatible with ssr
    byte_str := ""
    for idx, chars := range strings.Split(str_arr[0], "%") {
        if idx == 0 {
            // skip "GET /"
            continue
        }
        if len(chars) < 2 {
            byte_str += "0" + chars
            break
        } else if len(chars) > 2 {
            byte_str += chars[:2]
            break
        } else {
            byte_str += chars
        }
    }

    pass := ""
    for _, obfs_line := range str_arr {
        obfs_line = strings.TrimSpace(obfs_line)
        // find line like "Cookie: cid=892idj"
        if !strings.HasPrefix(obfs_line, ObfsHiddenIn) {
            continue
        }
        fields_arr := strings.Split(obfs_line, ObfsColonSeperator)
        farr_len := len(fields_arr)
        expect_len := 2
        if farr_len != expect_len {
            err = fmt.Errorf("fields len[%d] while expect [%d]", farr_len, expect_len)
            Printn("%s", err.Error())
            return nil, err
        }
        fields_str := fields_arr[1]
        key_val_str_arr := strings.Split(fields_str, ObfsItemSeperator)
        for _, key_val_str := range key_val_str_arr {
            key_val_str = strings.TrimSpace(key_val_str)
            split_arr := strings.Split(key_val_str, ObfsKeyValueSeperator)
            split_len := len(split_arr)
            expect_len := 2
            if split_len != expect_len {
                err = fmt.Errorf("key value string[%s] split size[%d] error! obfs header:%s",
                        key_val_str, *header)
                Printn("%s", err.Error())
                return nil, err
            }
            key := strings.TrimSpace(split_arr[0])
            val := strings.TrimSpace(split_arr[1])
            if key == ObfsPassKey {
                pass = val
            }
        }
    }
    if pass == "" {
        err = fmt.Errorf("no pass from obfs header")
        Printn("%s", err.Error())
        return nil, err
    }

    rand_head, err := hex.DecodeString(byte_str)
    if err != nil {
        err = fmt.Errorf("decode hex[%s] error:%s",
                byte_str, err.Error())
        return nil, err
    }
    obfs = &ObfsHeader {
        Pass: pass,
        RandHead: rand_head,
    }

    return
}

func GetSlice(source []byte, slen int, start, end int) (new_arr []byte, err error) {
    if start > slen || end > slen {
        err = fmt.Errorf("start[%d] or end[%d] index outofbound source length[%d]",
                start, end, slen)
        return nil, err
    }
    new_arr = source[start:end]
    return
}

