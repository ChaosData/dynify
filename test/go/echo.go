// $ CGO_ENABLED=0 go build echo.go
package main

import (
  "io"
  "log"
  "net"
)

func handleConn(conn net.Conn) {
  log.Println("Connection received")
  defer func() {
    conn.Close()
  }()
  io.Copy(conn, conn)
}

func main() {
  addr := "localhost:9999"
  server, err := net.Listen("tcp", addr)
  if err != nil {
    log.Fatalln(err)
  }
  defer server.Close()

  log.Println("Server is running on:", addr)

  for {
    conn, err := server.Accept()
    if err != nil {
      log.Println("Failed to accept conn.", err)
      continue
    }

    go handleConn(conn)
  }
}
