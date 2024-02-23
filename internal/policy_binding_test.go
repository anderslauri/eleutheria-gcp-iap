package internal_test

import (
	"context"
	"github.com/anderslauri/open-iap/internal"
	"testing"
	"time"
)

func TestLoadUsersWithRoleForIdentityAwareProxy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gwsReader, err := internal.NewGoogleWorkspaceReader(ctx)
	if err != nil {
		t.Fatalf("Could not load google workspace reader. Error returned: %s", err)
	}
	defaultInterval := 5 * time.Minute

	service, _ := internal.NewProjectPolicyReaderService(ctx, gwsReader, defaultInterval)

	if err := service.LoadUsersWithRoleForIdentityAwareProxy(ctx); err != nil {
		t.Fatalf("Expected no error, returned with error %s.", err.Error())
	}
}
