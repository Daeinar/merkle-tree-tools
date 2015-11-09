package main

import "fmt"
import "math"
import "crypto/sha256"
import "encoding/hex"

func to_hex(x []byte) string {
    return hex.EncodeToString(x)
}

// SHA256 Hash
func hash(in []byte) []byte {
    sha256 := sha256.New()
    sha256.Write(in)
    return sha256.Sum(nil)
}

// Merkle Tree Hash
func MTH(x [][]byte) []byte {
    n := len(x)
    if n == 0 {
        t := hash([]byte{})
        fmt.Println("x=0:", to_hex(t))
        return t
    } else if n == 1 {
        t := hash(append([]byte{0}, x[0]...))
        fmt.Println("x=1:", to_hex(t), x[0])
        return t
    } else {
        k := int(math.Exp2(math.Ceil(math.Log2(float64(n)) - 1)))
        t := hash(append([]byte{1}, append(MTH(x[0:k]), MTH(x[k:n])...)... ))
        fmt.Println("x>1:", to_hex(t), x[0:k], x[k:n])
        return t
    }
}

// Merkle Audit Path
func MAP(m int, x[][]byte) [][]byte {
    n := len(x)
    if m == 0 && n == 1 {
        return [][]byte{}
    } else {
        k := int(math.Exp2(math.Ceil(math.Log2(float64(n)) - 1)))
        if m < k {
            return append(MAP(m, x[0:k]), [][]byte{MTH(x[k:n])}...)
        } else {
            return append(MAP(m - k, x[k:n]), [][]byte{MTH(x[0:k])}...)
        }
    }
}

// Merkle Consistency Proof
func MCP(m int, x[][]byte) [][]byte {
    return mcsp(m,x,true)
}

// Merkle Consistency Subproof
func mcsp(m int, x[][]byte, b bool) [][]byte {
    n := len(x)
    if m == n {
        if b == true {
            return [][]byte{}
        } else {
            return [][]byte{MTH(x)}
        }
    } else {
        k := int(math.Exp2(math.Ceil(math.Log2(float64(n)) - 1)))
        if m <= k {
            return append(mcsp(m, x[0:k], b), [][]byte{MTH(x[k:n])}...)
        } else {
            return append(mcsp(m - k, x[k:n], false), [][]byte{MTH(x[0:k])}...)
        }
    }
}


func main() {
    data := []string{"a","b","c","d","e","f","g","h","i","j","k","l","m",
                     "n","o","p","q","r","s","t","u","v","w","x","y","z"}
    l := 7
    db := make([][]byte,0)
    for i := 0; i < l; i++ {
        db = append(db, []byte(data[i]))
    }
    h := MTH(db)
    fmt.Println("---------------------------------------------------------------------")
    fmt.Println("MTH:", to_hex(h))

    fmt.Println()

    n := 6
    x := MAP(n, db)
    fmt.Println("---------------------------------------------------------------------")
    fmt.Println("MAP for", db[n], ":")

    for i := 0; i < len(x); i++ {
        fmt.Println(i, to_hex(x[i]))
    }

    m := 6
    y := MCP(m, db)
    fmt.Println("---------------------------------------------------------------------")
    fmt.Println("MCP for", db[0:m], ":")

    for i := 0; i < len(y); i++ {
        fmt.Println(i, to_hex(y[i]))
    }



}
