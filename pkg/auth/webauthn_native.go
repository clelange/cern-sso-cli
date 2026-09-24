//go:build !nowebauthn

package auth

/*
#cgo darwin,arm64 CFLAGS: -I/opt/homebrew/opt/libfido2/include -I/opt/homebrew/opt/openssl@3/include
#cgo darwin,amd64 CFLAGS: -I/usr/local/opt/libfido2/include -I/usr/local/opt/openssl@3/include
#include <fido.h>
#include <fido/credman.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"
	"unsafe"

	"github.com/keys-pub/go-libfido2"
)

var errCredentialManagementUnsupported = errors.New("credential management is unsupported")

// nativeWebAuthnDevice only implements the read/assertion operations needed for
// login. The pinned Go wrapper cannot set timeouts and its Cancel races open.
// libfido2 itself also forbids concurrent operations on the same handle:
// https://github.com/Yubico/libfido2/discussions/757
// The caller owns this handle on a single locked OS thread for its entire life.
type nativeWebAuthnDevice struct {
	dev *C.fido_dev_t
}

func openNativeWebAuthnDevice(ctx context.Context, path string) (webAuthnDevice, error) {
	dev := C.fido_dev_new()
	if dev == nil {
		return nil, errors.New("failed to allocate FIDO2 device")
	}
	d := &nativeWebAuthnDevice{dev: dev}
	if err := d.setTimeout(ctx); err != nil {
		d.Close()
		return nil, err
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	if err := nativeWebAuthnError(ctx, C.fido_dev_open(dev, cPath)); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

func (d *nativeWebAuthnDevice) Close() {
	if d.dev != nil {
		// A close on an unopened handle is a documented no-op.
		C.fido_dev_close(d.dev)
		C.fido_dev_free(&d.dev) //nolint:gocritic // False positive in cgo-generated pointer checks.
	}
}

func (d *nativeWebAuthnDevice) HasPIN() bool {
	// open already fetched device capabilities; unlike RetryCount, this cannot
	// mistake a transport failure for a device with no PIN configured.
	return bool(C.fido_dev_has_pin(d.dev))
}

func (d *nativeWebAuthnDevice) setTimeout(ctx context.Context) error {
	ms, err := nativeTimeoutMilliseconds(ctx)
	if err != nil {
		return err
	}
	return nativeWebAuthnError(ctx, C.fido_dev_set_timeout(d.dev, C.int(ms)))
}

func nativeTimeoutMilliseconds(ctx context.Context) (int32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0, errors.New("FIDO2 communication requires a deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, context.DeadlineExceeded
	}
	// Round up to avoid a sub-millisecond deadline becoming a zero timeout.
	ms := remaining / time.Millisecond
	if remaining%time.Millisecond != 0 {
		ms++
	}
	if ms > math.MaxInt32 {
		ms = math.MaxInt32
	}
	return int32(ms), nil
}

func nativeWebAuthnError(ctx context.Context, code C.int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	if code != C.FIDO_OK {
		return fmt.Errorf("libfido2: %s", C.GoString(C.fido_strerr(code)))
	}
	return nil
}

func (d *nativeWebAuthnDevice) Credentials(ctx context.Context, rpID, pin string) ([][]byte, error) {
	if !bool(C.fido_dev_supports_credman(d.dev)) {
		return nil, errCredentialManagementUnsupported
	}
	if err := d.setTimeout(ctx); err != nil {
		return nil, err
	}
	credentials := C.fido_credman_rk_new()
	if credentials == nil {
		return nil, errors.New("failed to allocate FIDO2 credential list")
	}
	defer C.fido_credman_rk_free(&credentials) //nolint:gocritic // False positive in cgo-generated pointer checks.
	cRP, cPIN := C.CString(rpID), C.CString(pin)
	defer C.free(unsafe.Pointer(cRP))
	defer C.free(unsafe.Pointer(cPIN))
	if err := nativeWebAuthnError(ctx, C.fido_credman_get_dev_rk(d.dev, cRP, credentials, cPIN)); err != nil {
		// In particular, never swallow invalid/blocked PIN or transport errors
		// and then attempt the same PIN again in an assertion.
		return nil, err
	}
	count := C.fido_credman_rk_count(credentials)
	if count > math.MaxInt32 {
		return nil, errors.New("FIDO2 credential count is too large")
	}
	ids := make([][]byte, 0, int(count))
	for i := C.size_t(0); i < count; i++ {
		cred := C.fido_credman_rk(credentials, i)
		id, err := copyNativeBytes(C.fido_cred_id_ptr(cred), C.fido_cred_id_len(cred))
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (d *nativeWebAuthnDevice) Assertion(ctx context.Context, rpID string, hash []byte, ids [][]byte, pin string) (*libfido2.Assertion, error) {
	if err := d.setTimeout(ctx); err != nil {
		return nil, err
	}
	assertion := C.fido_assert_new()
	if assertion == nil {
		return nil, errors.New("failed to allocate FIDO2 assertion")
	}
	defer C.fido_assert_free(&assertion) //nolint:gocritic // False positive in cgo-generated pointer checks.
	if err := prepareNativeAssertion(ctx, assertion, rpID, hash, ids); err != nil {
		return nil, err
	}
	var cPIN *C.char
	if pin != "" {
		cPIN = C.CString(pin)
		defer C.free(unsafe.Pointer(cPIN))
	}
	if err := nativeWebAuthnError(ctx, C.fido_dev_get_assert(d.dev, assertion, cPIN)); err != nil {
		return nil, err
	}
	if C.fido_assert_count(assertion) == 0 {
		return nil, errors.New("FIDO2 device returned no assertions")
	}
	result := &libfido2.Assertion{}
	fields := []struct {
		target *[]byte
		ptr    *C.uchar
		size   C.size_t
	}{
		{&result.AuthDataCBOR, C.fido_assert_authdata_ptr(assertion, 0), C.fido_assert_authdata_len(assertion, 0)},
		{&result.Sig, C.fido_assert_sig_ptr(assertion, 0), C.fido_assert_sig_len(assertion, 0)},
		{&result.CredentialID, C.fido_assert_id_ptr(assertion, 0), C.fido_assert_id_len(assertion, 0)},
		{&result.User.ID, C.fido_assert_user_id_ptr(assertion, 0), C.fido_assert_user_id_len(assertion, 0)},
	}
	for _, field := range fields {
		data, err := copyNativeBytes(field.ptr, field.size)
		if err != nil {
			return nil, err
		}
		*field.target = data
	}
	return result, nil
}

func copyNativeBytes(ptr *C.uchar, size C.size_t) ([]byte, error) {
	if size > math.MaxInt32 {
		return nil, errors.New("FIDO2 response is too large")
	}
	if size > 0 && ptr == nil {
		return nil, errors.New("FIDO2 response data is missing")
	}
	length := int32(size)
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length)), nil
}

func prepareNativeAssertion(ctx context.Context, assertion *C.fido_assert_t, rpID string, hash []byte, ids [][]byte) error {
	cRP := C.CString(rpID)
	defer C.free(unsafe.Pointer(cRP))
	if err := nativeWebAuthnError(ctx, C.fido_assert_set_rp(assertion, cRP)); err != nil {
		return err
	}
	if len(hash) == 0 {
		return errors.New("FIDO2 client data hash is empty")
	}
	if err := nativeWebAuthnError(ctx, C.fido_assert_set_clientdata_hash(assertion, (*C.uchar)(unsafe.Pointer(&hash[0])), C.size_t(len(hash)))); err != nil {
		return err
	}
	for _, id := range ids {
		if len(id) == 0 {
			return errors.New("FIDO2 credential ID is empty")
		}
		if err := nativeWebAuthnError(ctx, C.fido_assert_allow_cred(assertion, (*C.uchar)(unsafe.Pointer(&id[0])), C.size_t(len(id)))); err != nil {
			return err
		}
	}
	return nativeWebAuthnError(ctx, C.fido_assert_set_up(assertion, C.FIDO_OPT_TRUE))
}
