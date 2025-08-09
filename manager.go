package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/hunterwilkins2/rsv"
)

const (
	name  = "hide"
	email = "generated@hide.com"
)

type secretsManager struct {
	secretsFile       string
	secrets           map[string]string
	encryptionHandler crypto.PGPEncryption
	decryptionHandler crypto.PGPDecryption
}

func newSecretsManager(secretsFile string, pgpPrivKeyPath string) (*secretsManager, error) {
	encryptionHandler, decryptionHandler, err := createPGPHandlers(pgpPrivKeyPath)
	if err != nil {
		return nil, err
	}

	manager := &secretsManager{
		secretsFile:       secretsFile,
		encryptionHandler: encryptionHandler,
		decryptionHandler: decryptionHandler,
	}

	err = manager.readSecrets()
	if err != nil {
		return nil, err
	}

	return manager, nil
}

func (manager *secretsManager) Get(key string) string {
	return manager.secrets[key]
}

func (manager *secretsManager) List() map[string]string {
	return manager.secrets
}

func (manager *secretsManager) Set(key, value string) {
	manager.secrets[key] = value
}

func (manager *secretsManager) HasKey(key string) bool {
	_, ok := manager.secrets[key]
	return ok
}

func (manager *secretsManager) Remove(key string) {
	delete(manager.secrets, key)
}

func (manager *secretsManager) Close() error {
	err := manager.writeSecrets()
	manager.encryptionHandler.ClearPrivateParams()
	manager.decryptionHandler.ClearPrivateParams()
	manager.secrets = nil
	return err
}

func (manager *secretsManager) readSecrets() error {
	if _, err := os.Stat(manager.secretsFile); errors.Is(err, os.ErrNotExist) {
		manager.secrets = make(map[string]string)
		return nil
	}

	f, err := os.OpenFile(manager.secretsFile, os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	decryptionReader, err := manager.decryptionHandler.DecryptingReader(f, crypto.Bytes)
	if err != nil {
		fmt.Println("here")
		return err
	}

	r := rsv.NewReader(decryptionReader)
	data, err := r.ReadAll()
	if err != nil {
		return err
	}

	_, err = decryptionReader.VerifySignature()
	if err != nil {
		return err
	}

	secrets := map[string]string{}
	for _, row := range data {
		secrets[row[0]] = row[1]
	}

	manager.secrets = secrets
	return nil
}

func (manager *secretsManager) writeSecrets() error {
	basename := path.Base(manager.secretsFile)
	ext := path.Ext(manager.secretsFile)
	name := strings.TrimSuffix(basename, ext)

	// Creates tempory file then replaces original to avoid
	// corrupting secrets store if an error occurs during writing
	f, err := os.CreateTemp(".", fmt.Sprintf("%s.*%s", name, ext))
	if err != nil {
		return err
	}
	defer f.Close()

	encryptionWriter, err := manager.encryptionHandler.EncryptingWriter(f, crypto.Bytes)
	if err != nil {
		return err
	}
	defer encryptionWriter.Close()

	w := rsv.NewWriter(encryptionWriter)
	records := [][]string{}
	for key, value := range manager.secrets {
		records = append(records, []string{key, value})
	}

	err = w.WriteAll(records)
	if err != nil {
		return err
	}

	return os.Rename(f.Name(), manager.secretsFile)
}

func createPGPHandlers(pgpPrivKeyPath string) (crypto.PGPEncryption, crypto.PGPDecryption, error) {
	pgp := crypto.PGP()
	pgpProfile := crypto.PGPWithProfile(profile.Default())

	var privKey *crypto.Key
	var err error
	if _, err = os.Stat(pgpPrivKeyPath); errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(path.Dir(pgpPrivKeyPath), 0755)
		if err != nil {
			return nil, nil, err
		}

		privKey, err = pgpProfile.KeyGeneration().AddUserId(name, email).New().GenerateKey()
		if err != nil {
			return nil, nil, err
		}

		f, err := os.OpenFile(pgpPrivKeyPath, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return nil, nil, err
		}
		defer f.Close()

		armoredKey, err := privKey.Armor()
		if err != nil {
			return nil, nil, err
		}

		_, err = f.Write([]byte(armoredKey))
		if err != nil {
			return nil, nil, err
		}
	} else {
		f, err := os.OpenFile(pgpPrivKeyPath, os.O_RDONLY, 0644)
		if err != nil {
			return nil, nil, err
		}

		privKey, err = crypto.NewKeyFromReader(f)
		if err != nil {
			return nil, nil, err
		}
	}

	pubKey, err := privKey.ToPublic()
	if err != nil {
		return nil, nil, err
	}

	encHandler, err := pgp.Encryption().Recipient(pubKey).SigningKey(privKey).New()
	if err != nil {
		return nil, nil, err
	}

	decHandler, err := pgp.Decryption().DecryptionKey(privKey).VerificationKey(pubKey).New()
	if err != nil {
		return nil, nil, err
	}

	return encHandler, decHandler, nil
}
