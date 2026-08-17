package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Mtoly/XrayRP/common/mylego"
	"github.com/Mtoly/XrayRP/service"
)

type preparedCertificateRenewal interface {
	Renewed() bool
	CertificatePEM() []byte
	PrivateKeyPEM() []byte
	Commit() error
	Rollback() error
}

type prepareCertificateRenewalFunc func(*mylego.CertConfig) (preparedCertificateRenewal, error)

// Check Cert
func (c *Controller) certMonitor() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return c.certMonitorContext(ctx)
}

func (c *Controller) certMonitorContext(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	return c.renewCertificateIfNeededContext(ctx)
}

func (c *Controller) certMonitorPeriodic() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return c.certMonitorPeriodicContext(ctx)
}

func (c *Controller) certMonitorPeriodicContext(ctx context.Context) error {
	if err := c.certMonitorContext(ctx); err != nil {
		c.health.RecordFailure(service.FailureStageCertificate, time.Now())
		if c.logger != nil {
			if c.showErrorDetails() {
				c.logger.WithError(err).Warn("certificate renewal failed")
			} else {
				c.logger.Warn("certificate renewal failed; error details omitted because they may contain credentials")
			}
		}
	} else {
		c.refreshCertificateExpiry()
	}
	return nil
}

func (c *Controller) renewCertificateIfNeeded() error {
	ctx, cancel := service.WithDefaultTimeout(context.Background(), service.DefaultSyncTimeout)
	defer cancel()
	return c.renewCertificateIfNeededContext(ctx)
}

func (c *Controller) renewCertificateIfNeededContext(ctx context.Context) (err error) {
	if c == nil || c.config == nil {
		return nil
	}
	currentNodeSnapshot, currentTag, currentUsers := c.getSnapshotState()
	if currentNodeSnapshot != nil && currentNodeSnapshot.EnableTLS && c.config.EnableREALITY == false && c.config.CertConfig != nil {
		switch c.config.CertConfig.CertMode {
		case "dns", "http", "tls":
			prepare := c.prepareRenewal
			if prepare == nil {
				prepare = defaultControllerPrepareCertificateRenewal
			}
			var renewal preparedCertificateRenewal
			renewal, err = prepare(c.config.CertConfig)
			if err != nil {
				return err
			}
			if renewal == nil {
				return errors.New("certificate renewal preparation returned nil")
			}
			defer func() {
				panicErr := certificateRenewalPanicError(recover())
				err = errors.Join(err, panicErr, rollbackPreparedCertificateRenewal(renewal))
			}()
			if !renewal.Renewed() {
				return renewal.Rollback()
			}
			if currentTag == "" {
				return errors.Join(
					errors.New("cannot replace certificate runtime without an applied node tag"),
					renewal.Rollback(),
				)
			}
			certificatePEM := renewal.CertificatePEM()
			privateKeyPEM := renewal.PrivateKeyPEM()
			if len(certificatePEM) == 0 || len(privateKeyPEM) == 0 {
				return errors.Join(
					errors.New("prepared certificate renewal is missing certificate or private key PEM"),
					renewal.Rollback(),
				)
			}

			appliedConfig := cloneControllerConfig(c.config)
			candidateConfig := cloneControllerConfig(c.config)
			candidateConfig.CertConfig.CertMode = "content"
			candidateConfig.CertConfig.CertFile = ""
			candidateConfig.CertConfig.KeyFile = ""
			candidateConfig.CertConfig.CertContent = string(certificatePEM)
			candidateConfig.CertConfig.KeyContent = string(privateKeyPEM)
			if err := ctx.Err(); err != nil {
				return errors.Join(err, renewal.Rollback())
			}
			return newNodeRuntimeStateApplyModule(c, ctx).replaceCertificateRuntime(
				currentNodeSnapshot,
				currentTag,
				currentUsers,
				appliedConfig,
				candidateConfig,
				renewal,
			)
		}
	}
	return nil
}

func rollbackPreparedCertificateRenewal(renewal preparedCertificateRenewal) (err error) {
	if renewal == nil {
		return nil
	}
	defer func() {
		err = errors.Join(err, certificateRenewalPanicError(recover()))
	}()
	return renewal.Rollback()
}

func certificateRenewalPanicError(value any) error {
	if value == nil {
		return nil
	}
	if err, ok := value.(error); ok {
		return fmt.Errorf("certificate renewal transaction panicked: %w", err)
	}
	return fmt.Errorf("certificate renewal transaction panicked: %v", value)
}

func defaultControllerPrepareCertificateRenewal(certConfig *mylego.CertConfig) (preparedCertificateRenewal, error) {
	return mylego.PrepareRenewal(certConfig)
}
