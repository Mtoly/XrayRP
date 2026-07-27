package mylego

import (
	"errors"
	"sync"

	"github.com/go-acme/lego/v4/certificate"
)

// PreparedRenewal owns one serialized certificate renewal until the caller
// either commits its candidate resource or rolls it back.
type PreparedRenewal struct {
	mu                sync.Mutex
	storage           *CertificatesStorage
	resource          *certificate.Resource
	renewed           bool
	ownsOperationLock bool
	closed            bool
}

func newPreparedRenewal(storage *CertificatesStorage, resource *certificate.Resource, renewed, ownsOperationLock bool) *PreparedRenewal {
	return &PreparedRenewal{
		storage:           storage,
		resource:          resource,
		renewed:           renewed,
		ownsOperationLock: ownsOperationLock,
	}
}

func (r *PreparedRenewal) Renewed() bool {
	return r != nil && r.renewed
}

func (r *PreparedRenewal) CertificatePEM() []byte {
	if r == nil || r.resource == nil {
		return nil
	}
	return append([]byte(nil), r.resource.Certificate...)
}

func (r *PreparedRenewal) PrivateKeyPEM() []byte {
	if r == nil || r.resource == nil {
		return nil
	}
	return append([]byte(nil), r.resource.PrivateKey...)
}

func (r *PreparedRenewal) Commit() (err error) {
	if r == nil {
		return errors.New("prepared certificate renewal is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errors.New("prepared certificate renewal is already closed")
	}
	r.closed = true
	defer func() {
		err = errors.Join(err, panicValueError(recover()))
		r.releaseOperationLock()
	}()

	if !r.renewed {
		return nil
	}
	if r.storage == nil || r.resource == nil {
		return errors.New("prepared certificate renewal has no candidate resource")
	}
	return r.storage.storeResource(r.resource)
}

func (r *PreparedRenewal) Rollback() (err error) {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	defer func() {
		err = errors.Join(err, panicValueError(recover()))
		r.releaseOperationLock()
	}()
	return nil
}

func (r *PreparedRenewal) releaseOperationLock() {
	if !r.ownsOperationLock {
		return
	}
	r.ownsOperationLock = false
	certificateOperationMu.Unlock()
}

func PrepareRenewal(certConfig *CertConfig) (*PreparedRenewal, error) {
	lego, err := New(certConfig)
	if err != nil {
		return nil, err
	}
	return lego.PrepareRenewal()
}
