package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/elitah/fast-io"
	"github.com/elitah/utils/autocert"
)

func main() {
	acm := autocert.NewAutoCertManager()

	go func() {
		http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); nil == err {
					defer conn.Close()
					acm.ServeRequest(conn, r)
				}
			}
		}))
	}()

	if ls, err := tls.Listen("tcp", ":443", &tls.Config{
		GetCertificate: acm.GetCertificate,
	}); nil == err {
		for {
			if conn, err := ls.Accept(); nil == err {
				go func() {
					//
					defer conn.Close()
					//
					if src, ok := conn.(*tls.Conn); ok {
						if err := src.Handshake(); nil == err {
							//
							var target string
							//
							state := src.ConnectionState()
							//
							fmt.Println(state.ServerName)
							//
							switch state.ServerName {
							case "elitah.xyz", "elitah.tk", "elitah.ml":
								target = "127.0.0.1:18880"
							case "ssh.elitah.xyz", "ssh.elitah.tk", "ssh.elitah.ml":
								target = "127.0.0.1:8788"
							default:
								target = "127.0.0.1:30080"
							}
							//
							if "" != target {
								if dst, err := net.DialTimeout("tcp", target, 5*time.Second); nil == err {
									fast_io.FastCopy(dst, src)
								} else {
									fmt.Println(err)
								}
							} else {
								fmt.Println("no target")
							}
						} else {
							fmt.Println(err)
						}
					} else {
						fmt.Println("no tls.Conn")
					}
				}()
			} else {
				fmt.Println(err)
				break
			}
		}
	} else {
		fmt.Println(err)
	}
}
