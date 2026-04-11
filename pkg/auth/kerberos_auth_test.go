package auth

import (
	"fmt"
	"os"
	"testing"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

func TestTryUserCacheAuthDoesNotMutateKRB5CCNAME(t *testing.T) {
	cfg, err := loadTestKrb5Config()
	if err != nil {
		t.Fatalf("failed to load test config: %v", err)
	}

	oldIsMacOSAPICCacheFunc := isMacOSAPICCacheFunc
	oldFindCacheByUsernameFunc := findCacheByUsernameFunc
	oldConvertSpecificCacheToFile := convertSpecificCacheToFile
	oldNewClientFromCCachePath := newClientFromCCachePath
	defer func() {
		isMacOSAPICCacheFunc = oldIsMacOSAPICCacheFunc
		findCacheByUsernameFunc = oldFindCacheByUsernameFunc
		convertSpecificCacheToFile = oldConvertSpecificCacheToFile
		newClientFromCCachePath = oldNewClientFromCCachePath
	}()

	isMacOSAPICCacheFunc = func() bool { return true }
	findCacheByUsernameFunc = func(username string) (*CacheInfo, error) {
		return &CacheInfo{
			Principal: NormalizePrincipal(username),
			CacheName: "API:stub",
		}, nil
	}
	convertSpecificCacheToFile = func(cacheInfo *CacheInfo) (string, error) {
		return "/tmp/converted-cache", nil
	}
	newClientFromCCachePath = func(cfg *config.Config, path string) (*client.Client, error) {
		if path != "/tmp/converted-cache" {
			return nil, fmt.Errorf("unexpected cache path %q", path)
		}
		return &client.Client{}, nil
	}

	t.Setenv("KRB5CCNAME", "FILE:/tmp/original-cache")

	_, _, err = tryUserCacheAuth(cfg, "alice")
	if err != nil {
		t.Fatalf("tryUserCacheAuth failed: %v", err)
	}

	if got := os.Getenv("KRB5CCNAME"); got != "FILE:/tmp/original-cache" {
		t.Fatalf("expected KRB5CCNAME to remain unchanged, got %q", got)
	}
}

func TestTryDefaultCacheAuthConvertedCacheDoesNotMutateKRB5CCNAME(t *testing.T) {
	cfg, err := loadTestKrb5Config()
	if err != nil {
		t.Fatalf("failed to load test config: %v", err)
	}

	oldIsMacOSAPICCacheFunc := isMacOSAPICCacheFunc
	oldConvertAPICacheToFile := convertAPICacheToFile
	oldNewClientFromCCacheFunc := newClientFromCCacheFunc
	oldNewClientFromCCachePath := newClientFromCCachePath
	defer func() {
		isMacOSAPICCacheFunc = oldIsMacOSAPICCacheFunc
		convertAPICacheToFile = oldConvertAPICacheToFile
		newClientFromCCacheFunc = oldNewClientFromCCacheFunc
		newClientFromCCachePath = oldNewClientFromCCachePath
	}()

	isMacOSAPICCacheFunc = func() bool { return true }
	convertAPICacheToFile = func() (string, error) {
		return "/tmp/converted-default-cache", nil
	}
	newClientFromCCacheFunc = func(cfg *config.Config) (*client.Client, error) {
		return nil, fmt.Errorf("no cache")
	}
	newClientFromCCachePath = func(cfg *config.Config, path string) (*client.Client, error) {
		if path != "/tmp/converted-default-cache" {
			return nil, fmt.Errorf("unexpected cache path %q", path)
		}
		return &client.Client{}, nil
	}

	t.Setenv("KRB5CCNAME", "FILE:/tmp/original-cache")

	_, _, err = tryDefaultCacheAuth(cfg)
	if err != nil {
		t.Fatalf("tryDefaultCacheAuth failed: %v", err)
	}

	if got := os.Getenv("KRB5CCNAME"); got != "FILE:/tmp/original-cache" {
		t.Fatalf("expected KRB5CCNAME to remain unchanged, got %q", got)
	}
}
