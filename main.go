package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	sshHost    string
	sshPort    int
	remoteHost string
	remotePort int
	localHost  string
	localPort  int
	sshUser    string
	sshKeyFile string
)

func init() {
	flag.StringVar(&sshHost, "sh", "localhost", "Name of SSH Host")
	flag.IntVar(&sshPort, "sp", 22, "SSH Host Port")

	flag.StringVar(&remoteHost, "rh", "localhost", "Name of Remote Host")
	flag.IntVar(&remotePort, "rp", 80, "Remote Host Port")

	flag.StringVar(&localHost, "lh", "localhost", "Name of Local Host")
	flag.IntVar(&localPort, "lp", 8080, "Local Host Port")

	flag.StringVar(&sshUser, "u", "ubuntu", "SSH User name")
	flag.StringVar(&sshKeyFile, "k", "./private.key", "Path to private key of SSH User")
}

func main() {
	flag.Parse()

	tunnel := &Tunnel{
		Local:  &Endpoint{Host: localHost, Port: localPort},
		Server: &Endpoint{Host: sshHost, Port: sshPort},
		Remote: &Endpoint{Host: remoteHost, Port: remotePort},
		Config: &ssh.ClientConfig{
			User:    sshUser,
			Timeout: time.Second * 30,
			Auth:    []ssh.AuthMethod{ssh.PublicKeys(privateKey(sshKeyFile))},
			HostKeyCallback: func(host string, conn net.Addr, key ssh.PublicKey) error {
				log.Printf("Insecure Host Key callback: %s: %+v\n%+v", host, conn, key)
				return nil
			},
		},
	}

	log.Printf("Tunneling through %s\n\tExposing remote %q as local %q", tunnel.Server, tunnel.Remote, tunnel.Local)
	if err := tunnel.Start(); err != nil {
		log.Fatal(err)
	}
}

type Endpoint struct {
	Host string
	Port int
}

func (e *Endpoint) String() string { return fmt.Sprintf("%s:%d", e.Host, e.Port) }

type Tunnel struct {
	Local  *Endpoint
	Server *Endpoint
	Remote *Endpoint
	Config *ssh.ClientConfig
}

func (tunnel *Tunnel) Start() error {
	listener, err := net.Listen("tcp", tunnel.Local.String())
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("listening for connections on %q", listener.Addr().String())

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		log.Printf("accept connection from %q", conn.RemoteAddr().String())
		go tunnel.forward(conn)
	}
}

func (tunnel *Tunnel) forward(local net.Conn) {
	log.Printf("Connecting %s", local.RemoteAddr())
	defer log.Printf("Disconnecting %s", local.RemoteAddr())

	server, err := ssh.Dial("tcp", tunnel.Server.String(), tunnel.Config)
	if err != nil {
		log.Fatal("dialing ssh server", err)
	}

	remote, err := server.Dial("tcp", tunnel.Remote.String())
	if err != nil {
		log.Fatal("dialing remote server", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(name string, w, r net.Conn) {
		defer wg.Done()
		_, err := io.Copy(w, r)
		if err != nil {
			log.Printf("io.Copy %s: %v", name, err)
		}
	}

	go copy("local->remote", local, remote)
	go copy("remote->local", remote, local)
	wg.Wait()
}

func privateKey(path string) ssh.Signer {
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("reading key", err)
	}
	key, err := ssh.ParsePrivateKey([]byte(keyBytes))
	if err != nil {
		log.Fatal("parsing key", err)
	}
	return key
}
