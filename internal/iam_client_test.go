package internal_test

import (
	"context"
	"github.com/anderslauri/open-iap/internal"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/iamcredentials/v1"
	"testing"
	"time"
)

func googleCredentials() (*google.Credentials, error) {
	credentials, err := google.FindDefaultCredentials(
		context.Background(),
		admin.AdminDirectoryGroupScope,
		iamcredentials.CloudPlatformScope,
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
	policyClientService, _ := internal.NewIdentityAccessManagementClient(ctx,
		googleWorkspaceClient, credentials, 5*time.Minute)

	if err := policyClientService.RefreshRoleAndBindingsForIdentityAwareProxy(ctx); err != nil {
		t.Fatalf("Expected no error, returned with error %s.", err.Error())
	}
}
