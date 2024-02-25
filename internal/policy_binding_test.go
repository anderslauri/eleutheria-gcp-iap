package internal_test

import (
	"context"
	"github.com/anderslauri/open-iap/internal"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"testing"
	"time"
)

func googleCredentials() (*google.Credentials, error) {
	credentials, err := google.FindDefaultCredentials(
		context.Background(),
		admin.AdminDirectoryGroupScope,
		// TODO: What const is this?
		"https://www.googleapis.com/auth/cloud-platform.read-only",
	)
	return credentials, err
}

func TestLoadUsersWithRoleForIdentityAwareProxy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	credentials, _ := googleCredentials()

	googleWorkspaceClient, err := internal.NewGoogleWorkspaceClient(ctx, credentials)
	if err != nil {
		t.Fatalf("Could not load google workspace reader. Error returned: %s", err)
	}
	policyClientService, _ := internal.NewPolicyBindingClient(ctx,
		googleWorkspaceClient, credentials, 5*time.Minute)

	if err := policyClientService.LoadUsersWithRoleForIdentityAwareProxy(ctx); err != nil {
		t.Fatalf("Expected no error, returned with error %s.", err.Error())
	}
}
