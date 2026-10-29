package vmess

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countedAuthBlock struct {
	cipher.Block
	calls atomic.Int64
}

func (b *countedAuthBlock) Decrypt(dst, src []byte) {
	b.calls.Add(1)
	b.Block.Decrypt(dst, src)
}

func encryptedAuthID(block cipher.Block, nonce uint32, timestamp int64) []byte {
	var plain, encrypted [16]byte
	binary.BigEndian.PutUint64(plain[:], uint64(timestamp))
	binary.BigEndian.PutUint32(plain[8:], nonce)
	binary.BigEndian.PutUint32(plain[12:], crc32.ChecksumIEEE(plain[:12]))
	block.Encrypt(encrypted[:], plain[:])
	return encrypted[:]
}

func TestHotAuthPrioritizesCandidatesAndFallsBackOnce(t *testing.T) {
	s := NewService[string](nil)
	if err := s.UpdateUsers([]string{"hot", "cold"}, []string{"key-one", "key-two"}, []int{0, 0}); err != nil {
		t.Fatal(err)
	}
	users := s.users.Load()
	hot := &countedAuthBlock{Block: users.userIdCipher["hot"]}
	cold := &countedAuthBlock{Block: users.userIdCipher["cold"]}
	users.userIdCipher["hot"], users.userIdCipher["cold"] = hot, cold
	s.UpdateHotUsersMatching(func(user string) bool { return user == "hot" })
	users = s.users.Load()
	if user, found, err := s.findAEADUser(users, encryptedAuthID(hot, 1, time.Now().Unix())); err != nil || !found || user != "hot" || hot.calls.Load() != 1 || cold.calls.Load() != 0 {
		t.Fatalf("hot lookup did not finish before the cold candidate: %q %v %v", user, found, err)
	}
	hot.calls.Store(0)
	authID := encryptedAuthID(cold, 2, time.Now().Unix())
	if user, found, err := s.findAEADUser(users, authID); err != nil || !found || user != "cold" || hot.calls.Load() != 1 || cold.calls.Load() != 1 {
		t.Fatalf("cold fallback repeated a hot candidate or lost access: %q %v %v", user, found, err)
	}
	if _, _, err := s.findAEADUser(users, authID); !errors.Is(err, ErrReplay) {
		t.Fatal("hot candidate acceleration bypassed the instance replay filter")
	}
	if _, _, err := s.findAEADUser(users, encryptedAuthID(hot, 3, time.Now().Add(-time.Hour).Unix())); !errors.Is(err, ErrBadTimestamp) {
		t.Fatal("hot candidate acceleration bypassed the timestamp check")
	}
}

func TestHotCredentialsRotateWithoutRetainingOldCipher(t *testing.T) {
	s := NewService[string](nil)
	s.UpdateUsers([]string{"a"}, []string{"old-secret"}, []int{0})
	s.UpdateHotUsersMatching(func(string) bool { return true })
	old := s.users.Load()
	s.UpdateUsers([]string{"a"}, []string{"new-secret"}, []int{0})
	current := s.users.Load()
	if current.hotUserIdCipher["a"] != current.userIdCipher["a"] ||
		current.hotUserIdCipher["a"] == old.hotUserIdCipher["a"] {
		t.Fatal("credential rotation retained an old hot cipher")
	}
	if _, found, err := s.findAEADUser(current, encryptedAuthID(old.userIdCipher["a"], 1, time.Now().Unix())); err != nil || found {
		t.Fatal("retired credential authenticated through the hot subset")
	}
	if user, found, err := s.findAEADUser(current, encryptedAuthID(current.userIdCipher["a"], 2, time.Now().Unix())); err != nil || !found || user != "a" {
		t.Fatal("new credential did not authenticate through the rebuilt subset")
	}
	s.UpdateUsers(nil, nil, nil)
	if len(s.users.Load().hotUserIdCipher) != 0 || len(old.hotUserIdCipher) != 1 {
		t.Fatal("removal retained a hot user or mutated an older snapshot")
	}
}

func TestHotPublicationSharesGenerationWithConcurrentUpdates(t *testing.T) {
	s := NewService[string](nil)
	s.UpdateUsers([]string{"a"}, []string{"secret"}, []int{0})
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		for index := 0; index < 100; index++ {
			s.UpdateHotUsersMatching(func(string) bool { return true })
		}
	}()
	go func() {
		defer workers.Done()
		for index := 0; index < 100; index++ {
			s.UpdateUsers([]string{"a"}, []string{string(rune(index + 1))}, []int{0})
		}
	}()
	go func() {
		defer workers.Done()
		for index := 0; index < 100; index++ {
			s.generateLegacyKeys()
			users := s.users.Load()
			for user, block := range users.hotUserIdCipher {
				if block != users.userIdCipher[user] {
					t.Error("hot subset mixed credential generations")
				}
			}
		}
	}()
	workers.Wait()
}
