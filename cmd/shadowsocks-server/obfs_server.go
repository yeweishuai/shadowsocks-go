package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip address start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	lenIPv4   = net.IPv4len + 2 // ipv4 + 2port
	lenIPv6   = net.IPv6len + 2 // ipv6 + 2port
	lenDmBase = 2               // 1addrLen + 2port, plus addrLen
	// lenHmacSha1 = 10
)

var debug ss.DebugLog
var sanitizeIps bool
var udp bool
var managerAddr string

// for obfs
var G_listener                  *net.Listener
var G_listen_port               int
var G_pass_cipher_map           map[string]*ss.Cipher

func init() {
    G_pass_cipher_map = make(map[string]*ss.Cipher)
}

func getRequest(conn *ss.Conn) (host string, err error) {
	ss.SetReadTimeout(conn)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 255(max length address) + 2(port) + 10(hmac-sha1)
	buf := make([]byte, 269)
	// read till we get possible domain length field
	if _, err = io.ReadFull(conn, buf[:idType+1]); err != nil {
		return
	}

	var reqStart, reqEnd int
	addrType := buf[idType]
	switch addrType & ss.AddrMask {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+lenIPv4
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+lenIPv6
	case typeDm:
		if _, err = io.ReadFull(conn, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, idDm0+int(buf[idDmLen])+lenDmBase
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&ss.AddrMask)
		return
	}

	if _, err = io.ReadFull(conn, buf[reqStart:reqEnd]); err != nil {
		return
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch addrType & ss.AddrMask {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
	}
	// parse port
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}

const logCntDelta = 100

var connCnt int
var nextLogConnCnt = logCntDelta

func sanitizeAddr(addr net.Addr) string {
	if sanitizeIps {
		return "x.x.x.x:zzzz"
	} else {
		return addr.String()
	}
}

func handleConnection(conn *ss.Conn, port string) {
	var host string

	connCnt++ // this maybe not accurate, but should be enough
	if connCnt-nextLogConnCnt >= 0 {
		// XXX There's no xadd in the atomic package, so it's difficult to log
		// the message only once with low cost. Also note nextLogConnCnt maybe
		// added twice for current peak connection number level.
		log.Printf("Number of client connections reaches %d\n", nextLogConnCnt)
		nextLogConnCnt += logCntDelta
	}

	// function arguments are always evaluated, so surround debug statement
	// with if statement
	if debug {
		debug.Printf("new client %s->%s\n", sanitizeAddr(conn.RemoteAddr()), conn.LocalAddr())
	}
	closed := false
	defer func() {
		if debug {
			debug.Printf("closed pipe %s<->%s\n", sanitizeAddr(conn.RemoteAddr()), host)
		}
		connCnt--
		if !closed {
			conn.Close()
		}
	}()

	host, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request", sanitizeAddr(conn.RemoteAddr()), conn.LocalAddr(), err)
		closed = true
		return
	}
	// ensure the host does not contain some illegal characters, NUL may panic on Win32
	if strings.ContainsRune(host, 0x00) {
		log.Println("invalid domain name.")
		closed = true
		return
	}
	debug.Println("connecting", host)
	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			log.Println("dial error:", err)
		} else {
			log.Println("error connecting to:", host, err)
		}
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()
	if debug {
		debug.Printf("piping %s<->%s", sanitizeAddr(conn.RemoteAddr()), host)
	}
	go func() {
		ss.PipeThenClose(conn, remote, func(Traffic int) {
			passwdManager.addTraffic(port, Traffic)
		})
	}()

	ss.PipeThenClose(remote, conn, func(Traffic int) {
		passwdManager.addTraffic(port, Traffic)
	})

	closed = true
	return
}

type PortListener struct {
	password string
	listener net.Listener
}

type UDPListener struct {
	password string
	listener *net.UDPConn
}

type PasswdManager struct {
	sync.Mutex
	portListener map[string]*PortListener
	udpListener  map[string]*UDPListener
	trafficStats map[string]int64
}

func (pm *PasswdManager) add(port, password string, listener net.Listener) {
	pm.Lock()
	pm.portListener[port] = &PortListener{password, listener}
	pm.trafficStats[port] = 0
	pm.Unlock()
}

func (pm *PasswdManager) addUDP(port, password string, listener *net.UDPConn) {
	pm.Lock()
	pm.udpListener[port] = &UDPListener{password, listener}
	pm.Unlock()
}

func (pm *PasswdManager) get(port string) (pl *PortListener, ok bool) {
	pm.Lock()
	pl, ok = pm.portListener[port]
	pm.Unlock()
	return
}

func (pm *PasswdManager) getUDP(port string) (pl *UDPListener, ok bool) {
	pm.Lock()
	pl, ok = pm.udpListener[port]
	pm.Unlock()
	return
}

func (pm *PasswdManager) del(port string) {
	pl, ok := pm.get(port)
	if !ok {
		return
	}
	if udp {
		upl, ok := pm.getUDP(port)
		if !ok {
			return
		}
		upl.listener.Close()
	}
	pl.listener.Close()
	pm.Lock()
	delete(pm.portListener, port)
	delete(pm.trafficStats, port)
	if udp {
		delete(pm.udpListener, port)
	}
	pm.Unlock()
}

func (pm *PasswdManager) addTraffic(port string, n int) {
	pm.Lock()
	pm.trafficStats[port] = pm.trafficStats[port] + int64(n)
	pm.Unlock()
	return
}

func (pm *PasswdManager) getTrafficStats() map[string]int64 {
	pm.Lock()
	copy := make(map[string]int64)
	for k, v := range pm.trafficStats {
		copy[k] = v
	}
	pm.Unlock()
	return copy
}

// Update port password would first close a port and restart listening on that
// port. A different approach would be directly change the password used by
// that port, but that requires **sharing** password between the port listener
// and password manager.
func (pm *PasswdManager) updatePortPasswd(port, password string) {
	pl, ok := pm.get(port)
	if !ok {
		log.Printf("new port %s added\n", port)
	} else {
		if pl.password == password {
			return
		}
		log.Printf("closing port %s to update password\n", port)
		pl.listener.Close()
	}
	// run will add the new port listener to passwdManager.
	// So there maybe concurrent access to passwdManager and we need lock to protect it.
	go run(port, password)
	if udp {
		pl, ok := pm.getUDP(port)
		if !ok {
			log.Printf("new udp port %s added\n", port)
		} else {
			if pl.password == password {
				return
			}
			log.Printf("closing udp port %s to update password\n", port)
			pl.listener.Close()
		}
		go runUDP(port, password)
	}
}

var passwdManager = PasswdManager{
	portListener: map[string]*PortListener{},
	udpListener:  map[string]*UDPListener{},
	trafficStats: map[string]int64{},
}

func updatePasswd() {
	log.Println("updating password")
	newconfig, err := ss.ParseConfig(configFile)
	if err != nil {
		log.Printf("error parsing config file %s to update password: %v\n", configFile, err)
		return
	}
	oldconfig := config
	config = newconfig

	if err = unifyPortPassword(config); err != nil {
		return
	}
	for port, passwd := range config.PortPassword {
		passwdManager.updatePortPasswd(port, passwd)
		if oldconfig.PortPassword != nil {
			delete(oldconfig.PortPassword, port)
		}
	}
	// port password still left in the old config should be closed
	for port := range oldconfig.PortPassword {
		log.Printf("closing port %s as it's deleted\n", port)
		passwdManager.del(port)
	}
	log.Println("password updated")
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			updatePasswd()
		} else {
			// is this going to happen?
			log.Printf("caught signal %v, exit", sig)
			os.Exit(0)
		}
	}
}

// original getRequest(...)
func getHost(oc *ss.ObfsConn) (host string, obfs_req_buf []byte, err error) {
    ss.SetReadTimeout(oc)
    buf := ss.ObfsLeakyBuf.Get()
    defer ss.ObfsLeakyBuf.Put(buf)
    n := 0
    if n, err = oc.Read(buf); err != nil {
        ss.Printn("read error:%s, n:%d", err.Error(), n)
        return "", nil, err
    }
    buf_str := string(buf[:n])
    str_arr := strings.Split(buf_str, "\r\n\r\n")
    arr_len := len(str_arr)
    expect_len := 2
    if arr_len < expect_len {
        err = fmt.Errorf("obfs header split len[%d] while expect[%d]", arr_len, expect_len)
        ss.Printn("%s", err.Error())
        return "", nil, err
    }
    obfs, err := ss.ParseObfsHeader(&(str_arr[0]))
    if err != nil {
        obfs = &ss.ObfsHeader{
            Pass: "foobar",
        }
        // return "", nil, err
        ss.Printn("get pass error, try mock in test env")
    }

    // get cipher
    cipher, exists := G_pass_cipher_map[obfs.Pass]
    if !exists || cipher == nil {
        err = fmt.Errorf("password[%s] not exist in config, cipher[%p]",
                obfs.Pass, cipher)
        ss.Printn("%s", err.Error())
        return "", nil, err
    }

    oc.Cipher = cipher.Copy()
    obfs_header_len := len(str_arr[0])
    encrypt_content_start_index := obfs_header_len + 4
    encrypt_bytes := buf[encrypt_content_start_index:n]
    rhead_len := len(obfs.RandHead)
    if rhead_len > 0 {
        // ss.Printn("rand head len[%d], try append to encrypt bytes.", rhead_len)
        encrypt_bytes = append(obfs.RandHead, encrypt_bytes...)
    }

    enc_len := len(encrypt_bytes)
    iv_bytes, err := ss.GetSlice(encrypt_bytes, enc_len, 0, oc.GetIvLen())
    if err != nil {
        err = fmt.Errorf("get iv bytes error:%s", err.Error())
        return "", nil, err
    }
    if err = oc.InitDecrypt(iv_bytes); err != nil {
        return "", nil, err
    }
    payload_bytes, err := ss.GetSlice(encrypt_bytes, enc_len, oc.GetIvLen(), enc_len)
    payload_len := len(payload_bytes)

    // decrypt
    decrypt_bytes := make([]byte, payload_len)
    if err = oc.DecryptByte(decrypt_bytes, payload_bytes); err != nil {
        err = fmt.Errorf("decrypt payload error:%s", err.Error())
        return "", nil, err
    }

    // get host
    addrBuf, err := ss.GetSlice(decrypt_bytes, payload_len, idType, idType + 1)
    if err != nil {
        err = fmt.Errorf("get addrtype error:%s", err.Error())
        return "", nil, err
    }

    var reqStart, reqEnd, dmLen int
    addrType := addrBuf[idType]
    switch addrType & ss.AddrMask {
    case typeIPv4:
        reqStart, reqEnd = idIP0, idIP0+lenIPv4
    case typeIPv6:
        reqStart, reqEnd = idIP0, idIP0+lenIPv6
    case typeDm:
        dmBuf, err := ss.GetSlice(decrypt_bytes, payload_len, idType + 1, idDmLen + 1)
        if err != nil {
            err = fmt.Errorf("try get domain request boundry error:%s", err.Error())
            return "", nil, err
        }
        dmLen = int(dmBuf[0])
        reqStart, reqEnd = idDm0, idDm0 + dmLen + lenDmBase
    default:
        err = fmt.Errorf("addr type %d not supported", addrType&ss.AddrMask)
        return
    }

    host_bytes, err := ss.GetSlice(decrypt_bytes, payload_len, reqStart, reqEnd)
    hlen := len(host_bytes)
    if err != nil {
        err = fmt.Errorf("try parse address error:%s", err.Error())
        return "", nil, err
    }
    switch addrType & ss.AddrMask {
    case typeIPv4:
        host = net.IP(host_bytes[: net.IPv4len]).String()
    case typeIPv6:
        host = net.IP(host_bytes[: net.IPv6len]).String()
    case typeDm:
        host = string(host_bytes[: dmLen])
    }
    port := binary.BigEndian.Uint16(host_bytes[hlen-2:hlen])
    host = net.JoinHostPort(host, strconv.Itoa(int(port)))
    obfs_req_buf, err = ss.GetSlice(decrypt_bytes, payload_len, reqEnd, payload_len)
    return
}

func obfsHandleConnection(oc *ss.ObfsConn) {
    // get host TODO close in pipe
    // defer oc.Close()
    host, obfs_req_buf, err := getHost(oc)
    if err != nil {
        debug.Printf("get error:%s\n", err.Error())
        oc.FakeResponse()
        return
    }
    // ensure the host does not contain some illegal characters, 
    // NUL may panic on Win32
    if strings.ContainsRune(host, 0x00) {
        ss.Printn("invalid domain name:%s", host)
        return
    }

    // dial
    remote, err := net.Dial("tcp", host)
    if err != nil {
        if ne, ok := err.(*net.OpError); ok &&
                (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
            // log too many open file error
            // EMFILE is process reaches open file limits, ENFILE is system limit
            ss.Printn("dial host %s error:%s", host, err.Error())
        } else {
            ss.Printn("connecting to %s error:%s", host, err.Error())
        }
        return
    }
    if len(obfs_req_buf) > 0 {
        remote.Write(obfs_req_buf)
    }
    defer func() {
        // remote.Close()
    }()

    // pipe
    if debug {
        debug.Printf("piping %s<->%s", sanitizeAddr(oc.RemoteAddr()), host)
    }
    go func() {
        ss.PipeThenClose(oc, remote, func(traffic int) {
            // TODO
        })
    }()

    ss.PipeThenClose(remote, oc, func(traffic int) {
        // TODO
    })

    return
}

func obfs_accept() (err error) {
    if G_listener == nil {
        err = fmt.Errorf("global listener[%p] error! Init first!", G_listener)
        ss.Printn(err.Error())
        return err
    }
    for {
        conn, err := (*G_listener).Accept()
        if err != nil {
            ss.Printn("accept connection error:%s", err.Error())
            // TODO: return ?
            continue
        }
        go obfsHandleConnection(ss.ObfsNewConn(conn))
        /*
        for {
            buf := make([]byte, 10)
            // _, err = conn.Read(buf)
            _, err = io.ReadFull(conn, buf)
            if err != nil {
                ss.Printn("read get error:%s", err.Error())
                break
            }
            fmt.Print(string(buf))
            conn.Write([]byte("ok"))
        }
        */
        // conn.Close()
    }
    return
}

func obfs_init(port, password string) (err error) {
    // obfs unify as one port, mark port param as user id
    ss.Printn("insert obfs port:%s, password:%s", port, password)
    // map password to encryptor & decryptor
    if password == "" {
        ss.Printn("port[%s] get empty password[%s]", port, password)
        return
    }
    _, exist := G_pass_cipher_map[password]
    if exist {
        ss.Printn("port[%s] password[%s] related cihper exists.",
                port, password)
        return
    }
    G_pass_cipher_map[password], err = ss.NewCipher(config.Method, password)
    return err
}

func run(port, password string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Printf("error listening port %v: %v\n", port, err)
		os.Exit(1)
	}
	passwdManager.add(port, password, ln)
	var cipher *ss.Cipher
	log.Printf("server listening port %v ...\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			// listener maybe closed to update password
			debug.Printf("accept error: %v\n", err)
			return
		}
		// Creating cipher upon first connection.
		if cipher == nil {
			log.Println("creating cipher for port:", port)
			cipher, err = ss.NewCipher(config.Method, password)
			if err != nil {
				log.Printf("Error generating cipher for port: %s %v\n", port, err)
				conn.Close()
				continue
			}
		}
		go handleConnection(ss.NewConn(conn, cipher.Copy()), port)
	}
}

func runUDP(port, password string) {
	var cipher *ss.Cipher
	port_i, _ := strconv.Atoi(port)
	log.Printf("listening udp port %v\n", port)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv6zero,
		Port: port_i,
	})
	passwdManager.addUDP(port, password, conn)
	if err != nil {
		log.Printf("error listening udp port %v: %v\n", port, err)
		return
	}
	defer conn.Close()
	cipher, err = ss.NewCipher(config.Method, password)
	if err != nil {
		log.Printf("Error generating cipher for udp port: %s %v\n", port, err)
		conn.Close()
	}
	SecurePacketConn := ss.NewSecurePacketConn(conn, cipher.Copy())
	for {
		if err := ss.ReadAndHandleUDPReq(SecurePacketConn, func(traffic int) {
			passwdManager.addTraffic(port, traffic)
		}); err != nil {
			debug.Printf("udp read error: %v\n", err)
			return
		}
	}
}

func enoughOptions(config *ss.Config) bool {
	return config.ServerPort != 0 && config.Password != ""
}

func unifyPortPassword(config *ss.Config) (err error) {
	if len(config.PortPassword) == 0 { // this handles both nil PortPassword and empty one
		if !enoughOptions(config) {
			fmt.Fprintln(os.Stderr, "must specify both port and password")
			return errors.New("not enough options")
		}
		port := strconv.Itoa(config.ServerPort)
		config.PortPassword = map[string]string{port: config.Password}
	} else {
		if config.Password != "" || config.ServerPort != 0 {
			fmt.Fprintln(os.Stderr, "given port_password, ignore server_port and password option")
		}
	}
	return
}

var configFile string
var config *ss.Config

func main() {
	log.SetOutput(os.Stdout)
    log.Printf("test abc")

	var cmdConfig ss.Config
	var printVer bool
	var core int

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime")
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")
	flag.BoolVar((*bool)(&sanitizeIps), "A", false, "anonymize client ip addresses in all output")
	flag.BoolVar(&udp, "u", false, "UDP Relay")
	flag.StringVar(&managerAddr, "manager-address", "", "shadowsocks manager listening address")
    flag.IntVar(&G_listen_port, "gport", 8088, "global listen port")

	flag.Parse()

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	ss.SetDebug(debug)

	var err error
	config, err = ss.ParseConfig(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}
		config = &cmdConfig
		ss.UpdateConfig(config, config)
	} else {
		ss.UpdateConfig(config, &cmdConfig)
	}
	if config.Method == "" {
		config.Method = "aes-256-cfb"
	}
	if err = ss.CheckCipherMethod(config.Method); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = unifyPortPassword(config); err != nil {
		os.Exit(1)
	}
	if core > 0 {
		runtime.GOMAXPROCS(core)
	}
    ss.Printn("global listener is %p", G_listener)
    if G_listener == nil {
        listener, err := net.Listen("tcp", fmt.Sprintf(":%d", G_listen_port))
        if err != nil {
            ss.Printn("listen on [:%d] error:%s",
                    G_listen_port, err.Error())
            os.Exit(1)
        }
        ss.Printn("listen on[:%d] ok.", G_listen_port)
        G_listener = &listener
    }
    log.Printf("abc")
	for port, password := range config.PortPassword {
		// go run(port, password)
        if err := obfs_init(port, password); err != nil {
            ss.Printn("obfs init port[%s] password[%s] error:%s",
                    port, password, err.Error())
        }
		if udp {
            // currently not support obfs udp
			// go runUDP(port, password)
		}
	}

    go obfs_accept()

	if managerAddr != "" {
		addr, err := net.ResolveUDPAddr("udp", managerAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Can't resolve address: ", err)
			os.Exit(1)
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error listening:", err)
			os.Exit(1)
		}
		log.Printf("manager listening udp addr %v ...\n", managerAddr)
		defer conn.Close()
		go managerDaemon(conn)
	}

	waitSignal()
}

func managerDaemon(conn *net.UDPConn) {
	// add a report address set for ping response
	// according to https://github.com/shadowsocks/shadowsocks/wiki/Manage-Multiple-Users#example-code
	ctx := make(chan bool, 1)
	defer close(ctx)
	reportconnSet := make(map[string]*net.UDPAddr, 1024)
	go func() {
		timer := time.Tick(10 * time.Second)
		for {
			select {
			case <-ctx:
				return
			case <-timer:
				for _, addr := range reportconnSet {
					res := reportStat()
					if len(res) == 0 {
						continue
					}
					conn.WriteToUDP(res, addr)
				}
			}
		}
	}()

	for {
		data := make([]byte, 300)
		_, remote, err := conn.ReadFromUDP(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to read UDP manage msg, error: ", err.Error())
			continue
		}
		command := string(data)
		var res []byte
		switch {
		case strings.HasPrefix(command, "add:"):
			res = handleAddPort(bytes.Trim(data[4:], "\x00\r\n "))
		case strings.HasPrefix(command, "remove:"):
			res = handleRemovePort(bytes.Trim(data[7:], "\x00\r\n "))
		case strings.HasPrefix(command, "ping"):
			conn.WriteToUDP(handlePing(), remote)
			reportconnSet[remote.String()] = remote // append the host into the report list
		case strings.HasPrefix(command, "ping-stop"): // add the stop ping command
			conn.WriteToUDP(handlePing(), remote)
			delete(reportconnSet, remote.String())
		}
		if len(res) == 0 {
			continue
		}
		_, err = conn.WriteToUDP(res, remote)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to write UDP manage msg, error: ", err.Error())
			continue
		}
	}
}

func handleAddPort(payload []byte) []byte {
	var params struct {
		ServerPort interface{} `json:"server_port"` // may be string or int
		Password   string      `json:"password"`
	}
	json.Unmarshal(payload, &params)
	if params.ServerPort == nil || params.Password == "" {
		fmt.Fprintln(os.Stderr, "Failed to parse add req: ", string(payload))
		return []byte("err")
	}
	port := parsePortNum(params.ServerPort)
	if port == "" {
		return []byte("err")
	}
	passwdManager.updatePortPasswd(port, params.Password)
	return []byte("ok")
}

func handleRemovePort(payload []byte) []byte {
	var params struct {
		ServerPort interface{} `json:"server_port"` // may be string or int
	}
	json.Unmarshal(payload, &params)
	if params.ServerPort == nil {
		fmt.Fprintln(os.Stderr, "Failed to parse remove req: ", string(payload))
		return []byte("err")
	}
	port := parsePortNum(params.ServerPort)
	if port == "" {
		return []byte("err")
	}
	log.Printf("closing port %s\n", port)
	passwdManager.del(port)
	return []byte("ok")
}

func handlePing() []byte {
	return []byte("pong")
}

// reportStat get the stat:trafficStat and return avery 10 sec as for the protocol
// https://github.com/shadowsocks/shadowsocks/wiki/Manage-Multiple-Users
func reportStat() []byte {
	stats := passwdManager.getTrafficStats()
	var buf bytes.Buffer
	buf.WriteString("stat: ")
	ret, _ := json.Marshal(stats)
	buf.Write(ret)
	return buf.Bytes()
}

func parsePortNum(in interface{}) string {
	var port string
	switch in.(type) {
	case string:
		// try to convert to number then convert back, to ensure valid value
		portNum, err := strconv.Atoi(in.(string))
		if portNum == 0 || err != nil {
			return ""
		}
		port = strconv.Itoa(portNum)
	case float64:
		port = strconv.Itoa(int(in.(float64)))
	default:
		return ""
	}
	return port
}
