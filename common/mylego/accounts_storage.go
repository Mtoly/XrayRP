package mylego

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"golang.org/x/crypto/acme"
)

const (
	baseAccountsRootFolderName = "accounts"
	baseKeysFolderName         = "keys"
	accountFileName            = "account.json"
)

// AccountsStorage A storage for account data.
//
// rootPath:
//
//	./.lego/accounts/
//	     │      └── root accounts directory
//	     └── "path" option
//
// rootUserPath:
//
//	./.lego/accounts/localhost_14000/hubert@hubert.com/
//	     │      │             │             └── userID ("email" option)
//	     │      │             └── CA server ("server" option)
//	     │      └── root accounts directory
//	     └── "path" option
//
// keysPath:
//
//	./.lego/accounts/localhost_14000/hubert@hubert.com/keys/
//	     │      │             │             │           └── root keys directory
//	     │      │             │             └── userID ("email" option)
//	     │      │             └── CA server ("server" option)
//	     │      └── root accounts directory
//	     └── "path" option
//
// accountFilePath:
//
//	./.lego/accounts/localhost_14000/hubert@hubert.com/account.json
//	     │      │             │             │             └── account file
//	     │      │             │             └── userID ("email" option)
//	     │      │             └── CA server ("server" option)
//	     │      └── root accounts directory
//	     └── "path" option
type AccountsStorage struct {
	userID          string
	rootPath        string
	rootUserPath    string
	keysPath        string
	accountFilePath string
}

// NewAccountsStorage Creates a new AccountsStorage.
func NewAccountsStorage(l *LegoCMD) *AccountsStorage {
	email := l.C.Email

	serverURL, err := url.Parse(acme.LetsEncryptURL)
	if err != nil {
		panic(fmt.Errorf("parse ACME server URL: %w", err))
	}

	rootPath := filepath.Join(l.path, baseAccountsRootFolderName)
	serverPath := strings.NewReplacer(":", "_", "/", string(os.PathSeparator)).Replace(serverURL.Host)
	accountsPath := filepath.Join(rootPath, serverPath)
	rootUserPath := filepath.Join(accountsPath, email)

	return &AccountsStorage{
		userID:          email,
		rootPath:        rootPath,
		rootUserPath:    rootUserPath,
		keysPath:        filepath.Join(rootUserPath, baseKeysFolderName),
		accountFilePath: filepath.Join(rootUserPath, accountFileName),
	}
}

func (s *AccountsStorage) ExistsAccountFilePath() bool {
	if err := s.validatePaths(); err != nil {
		panic(err)
	}
	if err := validateExistingRegularFile(s.accountFilePath); errors.Is(err, os.ErrNotExist) {
		return false
	} else if err != nil {
		panic(err)
	}
	return true
}

func (s *AccountsStorage) GetRootPath() string {
	return s.rootPath
}

func (s *AccountsStorage) GetRootUserPath() string {
	return s.rootUserPath
}

func (s *AccountsStorage) GetUserID() string {
	return s.userID
}

func (s *AccountsStorage) Save(account *Account) error {
	if err := s.validatePaths(); err != nil {
		return err
	}
	jsonBytes, err := json.MarshalIndent(account, "", "\t")
	if err != nil {
		return err
	}

	return writeFileTransaction([]fileTransactionEntry{{
		path: s.accountFilePath,
		data: jsonBytes,
		perm: filePerm,
	}}, nil)
}

func (s *AccountsStorage) LoadAccount(privateKey crypto.PrivateKey) *Account {
	if err := s.validatePaths(); err != nil {
		panic(err)
	}
	if err := validateExistingRegularFile(s.accountFilePath); err != nil {
		panic(err)
	}
	fileBytes, err := os.ReadFile(s.accountFilePath)
	if err != nil {
		panic(fmt.Errorf("load account file for %s: %w", s.userID, err))
	}

	var account Account
	err = json.Unmarshal(fileBytes, &account)
	if err != nil {
		panic(fmt.Errorf("parse account file for %s: %w", s.userID, err))
	}

	account.key = privateKey

	if account.Registration == nil || account.Registration.Body.Status == "" {
		reg, err := tryRecoverRegistration(privateKey)
		if err != nil {
			panic(fmt.Errorf("recover registration for account %s: %w", s.userID, err))
		}

		account.Registration = reg
		err = s.Save(&account)
		if err != nil {
			panic(fmt.Errorf("save recovered registration for account %s: %w", s.userID, err))
		}
	}

	return &account
}

func (s *AccountsStorage) GetPrivateKey(keyType certcrypto.KeyType) crypto.PrivateKey {
	if err := s.validatePaths(); err != nil {
		panic(err)
	}
	accKeyPath := filepath.Join(s.keysPath, s.userID+".key")

	if err := validateExistingRegularFile(accKeyPath); errors.Is(err, os.ErrNotExist) {
		log.Printf("No key found for account %s. Generating a %s key.", s.userID, keyType)
		s.createKeysFolder()

		privateKey, err := generatePrivateKey(accKeyPath, keyType)
		if err != nil {
			panic(fmt.Errorf("generate private account key for %s: %w", s.userID, err))
		}

		log.Printf("Saved key to %s", accKeyPath)
		return privateKey
	} else if err != nil {
		panic(err)
	}

	privateKey, err := loadPrivateKey(accKeyPath)
	if err != nil {
		panic(fmt.Errorf("load private account key for %s: %w", s.userID, err))
	}

	return privateKey
}

func (s *AccountsStorage) createKeysFolder() {
	if err := s.validatePaths(); err != nil {
		panic(err)
	}
	if err := createNonExistingFolder(s.keysPath); err != nil {
		panic(fmt.Errorf("check or create key directory for account %s: %w", s.userID, err))
	}
}

func (s *AccountsStorage) validatePaths() error {
	if s == nil {
		return errors.New("account storage is nil")
	}
	if err := validateAccountEmail(s.userID); err != nil {
		return err
	}
	for _, path := range []string{s.rootUserPath, s.keysPath, s.accountFilePath} {
		if strings.TrimSpace(path) == "" {
			return errors.New("account storage path is empty")
		}
		if err := rejectSymlinkPathComponents(path); err != nil {
			return fmt.Errorf("validate account storage path: %w", err)
		}
	}
	if err := recoverFileTransaction(filepath.Dir(s.accountFilePath)); err != nil {
		return err
	}
	return recoverFileTransaction(s.keysPath)
}

func generatePrivateKey(file string, keyType certcrypto.KeyType) (crypto.PrivateKey, error) {
	return generatePrivateKeyWithRename(file, keyType, nil)
}

func generatePrivateKeyWithRename(file string, keyType certcrypto.KeyType, renameFile func(string, string) error) (crypto.PrivateKey, error) {
	privateKey, err := certcrypto.GeneratePrivateKey(keyType)
	if err != nil {
		return nil, err
	}

	pemKey := certcrypto.PEMBlock(privateKey)
	encoded := pem.EncodeToMemory(pemKey)
	if len(encoded) == 0 {
		return nil, errors.New("encode private account key")
	}
	if err := writeFileTransaction([]fileTransactionEntry{{
		path: file,
		data: encoded,
		perm: filePerm,
	}}, renameFile); err != nil {
		return nil, err
	}

	return privateKey, nil
}

func loadPrivateKey(file string) (crypto.PrivateKey, error) {
	keyBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}

func tryRecoverRegistration(privateKey crypto.PrivateKey) (*registration.Resource, error) {
	// couldn't load account but got a key. Try to look the account up.
	config := lego.NewConfig(&Account{key: privateKey})
	config.CADirURL = acme.LetsEncryptURL
	config.UserAgent = "lego-cli/dev"

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.ResolveAccountByKey()
	if err != nil {
		return nil, err
	}
	return reg, nil
}
