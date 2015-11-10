package merkletree

import "testing"
import "crypto/sha256"
import "encoding/hex"

func verify(x []string, y [][]byte) bool {
    f := true
    for i := 0; i < len(y); i++ {
        f = f && (hex.EncodeToString(y[i]) == x[i])
    }
    return f
}

func chunks(data []string) [][]byte {
    db := make([][]byte, 0)
    for i := 0; i < len(data); i++ {
        db = append(db, []byte(data[i]))
    }
    return db
}

// Merkle Tree Hash tests
func TestMTH(t *testing.T) {
    db := chunks([]string{"a","b","c","d","e","f","g"})
    mt := MT{sha256.New()}
    x := []string{"4ae191939f548d9934740b88dea2c5cb89bb8870fc4505cd79dec6bbfaaee9cb"}
    y := [][]byte{mt.MTH(db)}
    if !verify(x, y) {
        t.Errorf("Error (exp vs got): ")
        for i:= 0; i < len(x); i++ {
            t.Errorf("%s vs %s", x[i], hex.EncodeToString(y[i]) )
        }
    }
}

// Merkle Tree Audit Path tests
func TestMTAP1(t *testing.T) {
    db := chunks([]string{"a","b","c","d","e","f","g"})
    mt := MT{sha256.New()}
    x := []string{"57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31",
                  "dbbd68c325614a73dacb4e7a87a2b7b4ae9724b489e5629ee83151fe8f0eafd7",
                  "e286d3390665a7cdc759453bed0b00cded1842d757e3e6cfe87df53db177e725"}
    y := mt.MTAP(0, db)
    if !verify(x, y) {
        t.Errorf("Error (exp vs got): ")
        for i:= 0; i < len(x); i++ {
            t.Errorf("%s vs %s", x[i], hex.EncodeToString(y[i]) )
        }
    }
}

func TestMTAP2(t *testing.T) {
    db := chunks([]string{"a","b","c","d","e","f","g"})
    mt := MT{sha256.New()}
    x := []string{"597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8",
                  "b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb",
                  "e286d3390665a7cdc759453bed0b00cded1842d757e3e6cfe87df53db177e725"}
    y := mt.MTAP(3, db)
    if !verify(x,y) {
        t.Errorf("Error (exp vs got): ")
        for i:= 0; i < len(x); i++ {
            t.Errorf("%s vs %s", x[i], hex.EncodeToString(y[i]) )
        }
    }
}

func TestMTAP3(t *testing.T) {
    db := chunks([]string{"a","b","c","d","e","f","g"})
    mt := MT{sha256.New()}
    x := []string{"f5a06d3c52937089c51b7c6c1cc1948ccdc5581328b2ebb578e8cca66a7b5221",
                  "5aeb196e83598231b45c61f3e0c5a0fda49b0d4f86a6db5f893aacccf514fa99",
                  "33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0"}
    y := mt.MTAP(4, db)
    if !verify(x,y) {
        t.Errorf("Error (exp vs got): ")
        for i:= 0; i < len(x); i++ {
            t.Errorf("%s vs %s", x[i], hex.EncodeToString(y[i]) )
        }
    }
}

func TestMTAP4(t *testing.T) {
    db := chunks([]string{"a","b","c","d","e","f","g"})
    mt := MT{sha256.New()}
    x := []string{"918566184c9d5be235ad2b6dd60828f5cec14fc409f02f7db8647009ec6da588",
                  "33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0"}
    y := mt.MTAP(6, db)
    if !verify(x,y) {
        t.Errorf("Error (exp vs got): ")
        for i:= 0; i < len(x); i++ {
            t.Errorf("%s vs %s", x[i], hex.EncodeToString(y[i]) )
        }
    }
}

// Merkle Tree Consistency Proof tests
func TestMTCP1(t *testing.T) {
    db := chunks([]string{"a","b","c","d","e","f","g"})
    mt := MT{sha256.New()}
    x := []string{"597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8",
                  "d070dc5b8da9aea7dc0f5ad4c29d89965200059c9a0ceca3abd5da2492dcb71d",
                  "b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb",
                  "e286d3390665a7cdc759453bed0b00cded1842d757e3e6cfe87df53db177e725"}
    y := mt.MTCP(3, db)
    if !verify(x,y) {
        t.Errorf("Error (exp vs got): ")
        for i:= 0; i < len(x); i++ {
            t.Errorf("%s vs %s", x[i], hex.EncodeToString(y[i]) )
        }
    }
}

func TestMTCP2(t *testing.T) {
    db := chunks([]string{"a","b","c","d","e","f","g"})
    mt := MT{sha256.New()}
    x := []string{"e286d3390665a7cdc759453bed0b00cded1842d757e3e6cfe87df53db177e725"}
    y := mt.MTCP(4, db)
    if !verify(x,y) {
        t.Errorf("Error (exp vs got): ")
        for i:= 0; i < len(x); i++ {
            t.Errorf("%s vs %s", x[i], hex.EncodeToString(y[i]) )
        }
    }
}

func TestMTCP3(t *testing.T) {
    db := chunks([]string{"a","b","c","d","e","f","g"})
    mt := MT{sha256.New()}
    x := []string{"918566184c9d5be235ad2b6dd60828f5cec14fc409f02f7db8647009ec6da588",
                  "5aeb196e83598231b45c61f3e0c5a0fda49b0d4f86a6db5f893aacccf514fa99",
                  "33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0"}
    y := mt.MTCP(6, db)
    if !verify(x,y) {
        t.Errorf("Error (exp vs got): ")
        for i:= 0; i < len(x); i++ {
            t.Errorf("%s vs %s", x[i], hex.EncodeToString(y[i]) )
        }
    }
}
