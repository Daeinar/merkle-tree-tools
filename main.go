package main

import "fmt"
import "crypto/sha256"
import "encoding/hex"
import "./merkletree"

func to_hex(x []byte) string {
    return hex.EncodeToString(x)
}

func main() {
    data := []string{"a","b","c","d","e","f","g","h","i","j","k","l","m",
                     "n","o","p","q","r","s","t","u","v","w","x","y","z"}
    l := 7
    db := make([][]byte,0)
    for i := 0; i < l; i++ {
        db = append(db, []byte(data[i]))
    }

    mt := merkletree.MT{sha256.New()}
    h := mt.MTH(db)

    fmt.Println("---------------------------------------------------------------------")
    fmt.Println("MTH:", to_hex(h))

    fmt.Println()

    n := 6
    x := mt.MAP(n, db)
    fmt.Println("---------------------------------------------------------------------")
    fmt.Println("MAP for", db[n], ":")

    for i := 0; i < len(x); i++ {
        fmt.Println(i, to_hex(x[i]))
    }

    m := 6
    y := mt.MCP(m, db)
    fmt.Println("---------------------------------------------------------------------")
    fmt.Println("MCP for", db[0:m], ":")

    for i := 0; i < len(y); i++ {
        fmt.Println(i, to_hex(y[i]))
    }

}
