package internal_test

import (
	"context"
	"github.com/anderslauri/k8s-gws-authn/internal"
	"testing"
)

func TestLoadUsersWithRoleForIdentityAwareProxy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gwsReader, err := internal.NewGoogleWorkspaceReader(ctx)
	if err != nil {
		t.Fatalf("Could not load google workspace reader. Error returned: %s", err)
	}
	service, _ := internal.NewProjectPolicyReaderService(ctx, gwsReader)

	if err := service.LoadUsersWithRoleForIdentityAwareProxy(ctx); err != nil {
		t.Fatalf("Expected no error, returned with error %s.", err.Error())
	}
}
