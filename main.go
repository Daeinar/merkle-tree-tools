package main

import "fmt"
import "crypto/sha256"
import "encoding/hex"
import "./merkletree"

func verify(x [][]byte, y []string) bool {
    f := true
    for i := 0; i < len(x); i++ {
        f = f && (hex.EncodeToString(x[i]) == y[i])
    }
    return f
}

func main() {
    data := []string{"a","b","c","d","e","f","g"}
    db := make([][]byte,0)
    for i := 0; i < len(data); i++ {
        db = append(db, []byte(data[i]))
    }

    // Merkle Tree Hash tests
    mt := merkletree.MT{sha256.New()}
    y := []string{"4ae191939f548d9934740b88dea2c5cb89bb8870fc4505cd79dec6bbfaaee9cb"}
    fmt.Println("MTH test:", verify([][]byte{mt.MTH(db)}, y))

    // Merkle Tree Audit Path tests
    y = []string{"57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31",
                  "dbbd68c325614a73dacb4e7a87a2b7b4ae9724b489e5629ee83151fe8f0eafd7",
                  "e286d3390665a7cdc759453bed0b00cded1842d757e3e6cfe87df53db177e725"}
    fmt.Println("MTAP test 1:", verify(mt.MTAP(0, db),y))

    y = []string{"597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8",
                 "b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb",
                 "e286d3390665a7cdc759453bed0b00cded1842d757e3e6cfe87df53db177e725"}
    fmt.Println("MTAP test 2:", verify(mt.MTAP(3, db),y))

    y = []string{"f5a06d3c52937089c51b7c6c1cc1948ccdc5581328b2ebb578e8cca66a7b5221",
                 "5aeb196e83598231b45c61f3e0c5a0fda49b0d4f86a6db5f893aacccf514fa99",
                 "33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0"}
    fmt.Println("MTAP test 3:", verify(mt.MTAP(4, db),y))

    y = []string{"918566184c9d5be235ad2b6dd60828f5cec14fc409f02f7db8647009ec6da588",
                 "33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0"}
    fmt.Println("MTAP test 4:", verify(mt.MTAP(6, db),y))

    y = []string{"597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8",
                 "d070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d",
                 "b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb",
                 "e286d3390665a7cdc759453bed0b00cded1842d757e3e6cfe87df53db177e725"}
    fmt.Println("MTCP test 1:", verify(mt.MTCP(3, db),y))

    y = []string{"e286d3390665a7cdc759453bed0b00cded1842d757e3e6cfe87df53db177e725"}
    fmt.Println("MTCP test 2:", verify(mt.MTCP(4, db),y))

    y = []string{"918566184c9d5be235ad2b6dd60828f5cec14fc409f02f7db8647009ec6da588",
                 "5aeb196e83598231b45c61f3e0c5a0fda49b0d4f86a6db5f893aacccf514fa99",
                 "33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0"}
    fmt.Println("MTCP test 3:", verify(mt.MTCP(6, db),y))
}
