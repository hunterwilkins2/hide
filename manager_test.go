package main

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
)

func TestGet(t *testing.T) {
	testCases := []struct {
		Key   string
		Value string
	}{
		{Key: "API_PUBLIC_KEY", Value: "123456789"},
		{Key: "API_PRIVATE_KEY", Value: "ABCDEFGHI"},
		{Key: "DB_USER", Value: "admin"},
		{Key: "DB_PASSWORD", Value: "pa55word"},
		{Key: "NON_EXISTENT", Value: ""},
	}

	manager, _, cleanup := initSecretsManager(t)
	t.Cleanup(cleanup)

	for n, tt := range testCases {
		value := manager.Get(tt.Key)
		if value != tt.Value {
			t.Errorf("#%d: value=%q, want=%q", n+1, value, tt.Value)
		}
	}
}

func TestList(t *testing.T) {
	testCases := []struct {
		Key   string
		Value string
	}{
		{Key: "API_PUBLIC_KEY", Value: "123456789"},
		{Key: "API_PRIVATE_KEY", Value: "ABCDEFGHI"},
		{Key: "DB_USER", Value: "admin"},
		{Key: "DB_PASSWORD", Value: "pa55word"},
		{Key: "NON_EXISTENT", Value: ""},
	}

	manager, _, cleanup := initSecretsManager(t)
	t.Cleanup(cleanup)

	secrets := manager.List()
	if len(secrets) != 4 {
		t.Errorf("len=%d, want=%d", len(secrets), 4)
	}

	for n, tt := range testCases {
		value := secrets[tt.Key]
		if value != tt.Value {
			t.Errorf("#%d: value=%q, want=%q", n+1, value, tt.Value)
		}
	}
}

func TestHasKey(t *testing.T) {
	testCases := []struct {
		Key    string
		HasKey bool
	}{
		{Key: "API_PUBLIC_KEY", HasKey: true},
		{Key: "API_PRIVATE_KEY", HasKey: true},
		{Key: "DB_USER", HasKey: true},
		{Key: "DB_PASSWORD", HasKey: true},
		{Key: "NON_EXISTENT", HasKey: false},
	}

	manager, _, cleanup := initSecretsManager(t)
	t.Cleanup(cleanup)

	for n, tt := range testCases {
		ok := manager.HasKey(tt.Key)
		if ok != tt.HasKey {
			t.Errorf("#%d: ok=%t, want=%t", n+1, ok, tt.HasKey)
		}
	}
}

func TestSet(t *testing.T) {
	testCases := []struct {
		Key   string
		Value string
	}{
		{Key: "API_PUBLIC_KEY", Value: "987654321"},
		{Key: "API_PRIVATE_KEY", Value: "ABCDEFGHI"},
		{Key: "DB_USER", Value: "admin"},
		{Key: "DB_PASSWORD", Value: "pa55word"},
		{Key: "DB_DATABASE", Value: "users"},
		{Key: "NON_EXISTENT", Value: ""},
	}

	manager, secretFile, _ := initSecretsManager(t)

	manager.Set("API_PUBLIC_KEY", "987654321")
	manager.Set("DB_DATABASE", "users")
	err := manager.Close()
	if err != nil {
		t.Fatalf("could not close secrets manager: %s", err)
	}

	manager, err = newSecretsManager(secretFile, getPrivKey())
	if err != nil {
		t.Fatalf("could not reopen secrets file: %s", err)
	}
	t.Cleanup(func() {
		err := manager.Close()
		if err != nil {
			t.Fatalf("could not close secrets manager: %s", err)
		}
		err = os.Remove(secretFile)
		if err != nil {
			t.Fatalf("could not remove temporary secrets file: %s", err)
		}
	})

	if len(manager.List()) != 5 {
		t.Errorf("len=%d, want=%d", len(manager.List()), 5)
	}
	for n, tt := range testCases {
		value := manager.Get(tt.Key)
		if value != tt.Value {
			t.Errorf("#%d: value=%q, want=%q", n+1, value, tt.Value)
		}
	}
}

func TestRemove(t *testing.T) {
	testCases := []struct {
		Key   string
		Value string
	}{
		{Key: "API_PRIVATE_KEY", Value: "ABCDEFGHI"},
		{Key: "DB_USER", Value: "admin"},
		{Key: "DB_PASSWORD", Value: "pa55word"},
		{Key: "API_PUBLIC_KEY", Value: ""},
		{Key: "NON_EXISTENT", Value: ""},
	}

	manager, secretFile, _ := initSecretsManager(t)

	manager.Remove("API_PUBLIC_KEY")
	manager.Remove("DB_DATABASE")
	err := manager.Close()
	if err != nil {
		t.Fatalf("could not close secrets manager: %s", err)
	}

	manager, err = newSecretsManager(secretFile, getPrivKey())
	if err != nil {
		t.Fatalf("could not reopen secrets file: %s", err)
	}
	t.Cleanup(func() {
		err := manager.Close()
		if err != nil {
			t.Fatalf("could not close secrets manager: %s", err)
		}
		err = os.Remove(secretFile)
		if err != nil {
			t.Fatalf("could not remove temporary secrets file: %s", err)
		}
	})

	if len(manager.List()) != 3 {
		t.Errorf("len=%d, want=%d", len(manager.List()), 3)
	}
	for n, tt := range testCases {
		value := manager.Get(tt.Key)
		if value != tt.Value {
			t.Errorf("#%d: value=%q, want=%q", n+1, value, tt.Value)
		}
	}
}

func initSecretsManager(t *testing.T) (*secretsManager, string, func()) {
	t.Helper()
	b := make([]byte, 5)
	rand.Read(b)
	name := fmt.Sprintf("test-secret_%x.enc.env", b)

	manager, err := newSecretsManager(name, getPrivKey())
	if err != nil {
		t.Fatalf("could not open secrets manager: %s", err)
	}

	manager.Set("API_PUBLIC_KEY", "123456789")
	manager.Set("API_PRIVATE_KEY", "ABCDEFGHI")
	manager.Set("DB_USER", "admin")
	manager.Set("DB_PASSWORD", "pa55word")

	err = manager.Close()
	if err != nil {
		t.Fatalf("could not write secrets to secrets manager: %s", err)
	}

	manager, err = newSecretsManager(name, getPrivKey())
	if err != nil {
		t.Fatalf("could not open secrets manager after writing: %s", err)
	}

	cleanup := func() {
		err := manager.Close()
		if err != nil {
			t.Fatalf("could not close secrets manager: %s", err)
		}
		err = os.Remove(name)
		if err != nil {
			t.Fatalf("could not remove temporary secrets file: %s", err)
		}
	}

	return manager, name, cleanup
}
