package internal

import (
	"context"
	"errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
	"strings"
	"sync/atomic"
	"time"
)

// IdentityAccessManagementClient is a service implementation to retrieve bindings from Google Cloud.
type IdentityAccessManagementClient struct {
	service            *cloudresourcemanager.Service
	pid                string
	roleCollectionCopy atomic.Value
	gwsClient          GoogleWorkspaceClientReader
}

// PolicyBinding is a struct to retain policy information (of what is relevant).
type PolicyBinding struct {
	Expression string
	Title      string
}

const iapWebPermission = "roles/iap.httpsResourceAccessor"

// GoogleServiceAccount is custom type representation of identifier in Google Cloud (email).
type GoogleServiceAccount string

// Role is a custom type representation of Role in GCP.
type Role string

// PolicyBindings is a list of bindings attached to a role.
type PolicyBindings []PolicyBinding

// PolicyBindingCollection is custom map type for Role to policy bindings.
type PolicyBindingCollection map[Role]PolicyBindings

// GoogleServiceAccountRoleCollection is a collection of service account id to bindings per role.
type GoogleServiceAccountRoleCollection map[GoogleServiceAccount]PolicyBindingCollection

// IdentityAccessManagementReader is an interface to abstract PolicyBindingService.
type IdentityAccessManagementReader interface {
	RefreshRoleAndBindingsForIdentityAwareProxy(ctx context.Context) error
	LoadBindingForGoogleServiceAccount(uid GoogleServiceAccount) (PolicyBindings, error)
	LoadRoleCollection() GoogleServiceAccountRoleCollection
}

// ErrNoIdentityAwareProxyRoleForUser is returned when user does not have role for IAP.
var ErrNoIdentityAwareProxyRoleForUser = errors.New("no iap role found")

// NewIdentityAccessManagementClient generates an implementation of PolicyBindingReader.
func NewIdentityAccessManagementClient(ctx context.Context, googleWorkspaceClient GoogleWorkspaceClientReader,
	credentials *google.Credentials, refresh time.Duration) (*IdentityAccessManagementClient, error) {
	service, err := cloudresourcemanager.NewService(ctx, option.WithCredentials(credentials))
	if err != nil {
		return nil, err
	}
	ps := &IdentityAccessManagementClient{
		service:   service,
		pid:       credentials.ProjectID,
		gwsClient: googleWorkspaceClient,
	}
	if err = ps.RefreshRoleAndBindingsForIdentityAwareProxy(ctx); err != nil {
		return nil, err
	}
	go ps.refreshProjectPolicyBindings(ctx, refresh)
	return ps, nil
}

// LoadBindingForGoogleServiceAccount look up which bindings (roles and expressions) google service account has.
func (i *IdentityAccessManagementClient) LoadBindingForGoogleServiceAccount(uid GoogleServiceAccount) (PolicyBindings, error) {
	collection, ok := i.roleCollectionCopy.Load().(GoogleServiceAccountRoleCollection)
	val, ok := collection[uid]
	if !ok {
		return nil, ErrNoIdentityAwareProxyRoleForUser
	}
	return val[iapWebPermission], nil
}

// LoadRoleCollection retrieve entire collection of policy bindings per user.
func (i *IdentityAccessManagementClient) LoadRoleCollection() GoogleServiceAccountRoleCollection {
	val := i.roleCollectionCopy.Load()
	return val.(GoogleServiceAccountRoleCollection)
}

func (i *IdentityAccessManagementClient) refreshProjectPolicyBindings(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := i.RefreshRoleAndBindingsForIdentityAwareProxy(ctx); err != nil {
				log.WithField("error", err).Error("Could not refresh project policy bindings.")
			}
		}
	}
}

// RefreshRoleAndBindingsForIdentityAwareProxy load UserRoleCollection into local memory for usage.
func (i *IdentityAccessManagementClient) RefreshRoleAndBindingsForIdentityAwareProxy(ctx context.Context) error {
	policies, err := i.service.Projects.GetIamPolicy(i.pid,
		&cloudresourcemanager.GetIamPolicyRequest{
			Options: &cloudresourcemanager.GetPolicyOptions{
				RequestedPolicyVersion: 3,
			},
		}).Context(ctx).Do()

	if err != nil {
		return err
	}
	userRoleCollection := make(GoogleServiceAccountRoleCollection, 100)

	for _, iamPolicy := range policies.Bindings {
		for _, policyMember := range iamPolicy.Members {
			if !(strings.HasPrefix(policyMember, "serviceAccount:") || strings.HasPrefix(policyMember, "group:")) {
				continue
			}
			var (
				expression, title string
				members           = make([]GoogleServiceAccount, 100)
				identifier        = strings.Split(policyMember, ":")[1]
			)
			// Reference to Group in Google Workspace. Expand group to include members.
			if strings.HasPrefix(policyMember, "group:") {
				if members, err = i.gwsClient.ListGoogleServiceAccounts(ctx, identifier); err != nil {
					log.WithField("error", err).Error("Can't retrieve members from group in Google workspace.")
					continue
				}
			} else {
				members = append(members, GoogleServiceAccount(identifier))
			}
			for _, member := range members {
				if _, ok := userRoleCollection[member]; !ok {
					userRoleCollection[member] = make(PolicyBindingCollection, 5)
				}
				if iamPolicy.Condition != nil {
					expression = iamPolicy.Condition.Expression
					title = iamPolicy.Condition.Title
				}
				userRoleCollection[member][Role(iamPolicy.Role)] = append(
					userRoleCollection[member][Role(iamPolicy.Role)],
					PolicyBinding{
						Expression: expression,
						Title:      title,
					})
			}
		}
	}
	i.roleCollectionCopy.Store(userRoleCollection)
	return nil
}
