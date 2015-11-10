package merkletree

import "math"
import "hash"

type MT struct {
    H hash.Hash
}

func (self *MT) hash(data []byte) []byte {
    self.H.Reset()
    self.H.Write(data)
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

// Merkle Tree Audit Path
func (self *MT) MTAP(m int, x[][]byte) [][]byte {
    n := len(x)
    if m == 0 && n == 1 {
        return [][]byte{}
    } else {
        k := int(math.Exp2(math.Ceil(math.Log2(float64(n)) - 1)))
        if m < k {
            return append(self.MTAP(m, x[0:k]), [][]byte{self.MTH(x[k:n])}...)
        } else {
            return append(self.MTAP(m - k, x[k:n]), [][]byte{self.MTH(x[0:k])}...)
        }
    }
}

// Merkle Tree Consistency Proof
func (self *MT) MTCP(m int, x[][]byte) [][]byte {
    return self.mtcsp(m,x,true)
}

// Merkle Tree Consistency Subproof
func (self *MT) mtcsp(m int, x[][]byte, b bool) [][]byte {
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
            return append(self.mtcsp(m, x[0:k], b), [][]byte{self.MTH(x[k:n])}...)
        } else {
            return append(self.mtcsp(m - k, x[k:n], false), [][]byte{self.MTH(x[0:k])}...)
        }
    }
}
