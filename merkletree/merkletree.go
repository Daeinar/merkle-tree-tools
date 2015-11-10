package merkletree

import "math"
import "hash"

type MT struct {
    H hash.Hash
}

func (self *MT) hash(in []byte) []byte {
    self.H.Reset()
    self.H.Write(in)
    return self.H.Sum(nil)
}

// Merkle Tree Hash
func (self *MT) MTH(x [][]byte) []byte {
    n := len(x)
    if n == 0 {
        return self.hash([]byte{})
    } else if n == 1 {
        return self.hash(append([]byte{0}, x[0]...))
    } else {
        k := int(math.Exp2(math.Ceil(math.Log2(float64(n)) - 1)))
        return self.hash(append([]byte{1}, append(self.MTH(x[0:k]), self.MTH(x[k:n])...)...))
    }
}

// Merkle Audit Path
func (self *MT) MAP(m int, x[][]byte) [][]byte {
    n := len(x)
    if m == 0 && n == 1 {
        return [][]byte{}
    } else {
        k := int(math.Exp2(math.Ceil(math.Log2(float64(n)) - 1)))
        if m < k {
            return append(self.MAP(m, x[0:k]), [][]byte{self.MTH(x[k:n])}...)
        } else {
            return append(self.MAP(m - k, x[k:n]), [][]byte{self.MTH(x[0:k])}...)
        }
    }
}

// Merkle Consistency Proof
func (self *MT) MCP(m int, x[][]byte) [][]byte {
    return self.mcsp(m,x,true)
}

// Merkle Consistency Subproof
func (self *MT) mcsp(m int, x[][]byte, b bool) [][]byte {
    n := len(x)
    if m == n {
        if b == true {
            return [][]byte{}
        } else {
            return [][]byte{self.MTH(x)}
        }
    } else {
        k := int(math.Exp2(math.Ceil(math.Log2(float64(n)) - 1)))
        if m <= k {
            return append(self.mcsp(m, x[0:k], b), [][]byte{self.MTH(x[k:n])}...)
        } else {
            return append(self.mcsp(m - k, x[k:n], false), [][]byte{self.MTH(x[0:k])}...)
        }
    }
}
