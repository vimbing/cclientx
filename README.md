# CClient

Fixes TLS and stuff. Uses the yawning utls fork instead of the original refraction-networking one.

# Example

```go
package main

import (
    "log"

    tls "github.com/Carcraftz/utls"
    "github.com/Carcraftz/cclient"
)

func main() {
    client, err := cclient.NewClient(tls.HelloChrome_Auto,"",true,6)
    if err != nil {
        log.Fatal(err)
    }

    resp, err := client.Get("https://www.google.com/")
    if err != nil {
        log.Fatal(err)
    }
    resp.Body.Close()

    log.Println(resp.Status)
}
```

# Notes

If you experience any issues with the gitlab.com/yawning/utls import during installation, please try: `go get gitlab.com/yawning/utls`. Some path issue with go and gitlab ¯\\\_(ツ)\_/¯

The go.mod issue with git etc. was fixed by using my fork of the project with a change to the go.mod file instead of yawning's fork
