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

const iapRole = "roles/iap.httpsResourceAccessor"

// UserID is custom type representation of identifier in Google Cloud (email).
type UserID string

// Role is a custom type representation of Role in GCP.
type Role string

// PolicyBindings is a list of bindings attached to a role.
type PolicyBindings []PolicyBinding

// PolicyBindingCollection is custom map type for Role to policy bindings.
type PolicyBindingCollection map[Role]PolicyBindings

// UserRoleCollection is a collection of user id to bindings per role.
type UserRoleCollection map[UserID]PolicyBindingCollection

// IdentityAccessManagementReader is an interface to abstract PolicyBindingService.
type IdentityAccessManagementReader interface {
	RefreshRoleAndBindingsForIdentityAwareProxy(ctx context.Context) error
	IdentityAwareProxyPolicyBindingForUser(uid UserID) (PolicyBindings, error)
	IdentityAwareProxyUserRoleCollection() UserRoleCollection
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

// IdentityAwareProxyPolicyBindingForUser look up which bindings (roles and expressions) a user have.
func (i *IdentityAccessManagementClient) IdentityAwareProxyPolicyBindingForUser(uid UserID) (PolicyBindings, error) {
	collection, ok := i.roleCollectionCopy.Load().(UserRoleCollection)
	val, ok := collection[uid]
	if !ok {
		return nil, ErrNoIdentityAwareProxyRoleForUser
	}
	return val[iapRole], nil
}

// IdentityAwareProxyUserRoleCollection retrieve entire collection of policy bindings per user.
func (i *IdentityAccessManagementClient) IdentityAwareProxyUserRoleCollection() UserRoleCollection {
	val := i.roleCollectionCopy.Load()
	return val.(UserRoleCollection)
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
	// FIXME: Bindings on organizational/folder level must be accounted - is not at the moment!
	userRoleCollection := make(UserRoleCollection, 100)
	for _, policy := range policies.Bindings {
		if policy.Role != iapRole {
			continue
		}

		for _, user := range policy.Members {
			// https://cloud.google.com/iam/docs/policies#example-deleted-member
			if strings.HasPrefix(user, "deleted:") {
				continue
			}
			var (
				expression string
				title      string
				// Probably we should revert to first sighting of :
				uid = UserID(strings.Split(user, ":")[1])
			)
			// Reference to Group in Google Workspace. Expand group to include members.
			if strings.HasPrefix(user, "group:") {
				membersInGroup, err := i.gwsClient.MembersInGroup(ctx, string(uid))
				if err != nil {
					log.WithField("error", err).Error("Can't retrieve members from group in Google workspace.")
					continue
				}
				// TODO: Code duplication - clean up.
				for _, member := range membersInGroup {
					if _, ok := userRoleCollection[member]; !ok {
						userRoleCollection[member] = make(PolicyBindingCollection, 5)
					}
					if policy.Condition != nil {
						expression = policy.Condition.Expression
						title = policy.Condition.Title
					}
					userRoleCollection[member][Role(policy.Role)] = append(
						userRoleCollection[member][Role(policy.Role)],
						PolicyBinding{
							Expression: expression,
							Title:      title,
						})
				}
			}
			// Directly referenced user.
			if _, ok := userRoleCollection[uid]; !ok {
				userRoleCollection[uid] = make(PolicyBindingCollection, 5)
			}
			if policy.Condition != nil {
				expression = policy.Condition.Expression
				title = policy.Condition.Title
			}
			userRoleCollection[uid][Role(policy.Role)] = append(
				userRoleCollection[uid][Role(policy.Role)],
				PolicyBinding{
					Expression: expression,
					Title:      title,
				})
		}
	}
	i.roleCollectionCopy.Store(userRoleCollection)
	return nil
}
