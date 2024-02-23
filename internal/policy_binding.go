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

// ProjectPolicyReaderService is a service implementation to retrieve bindings from Google Cloud.
type ProjectPolicyReaderService struct {
	service            *cloudresourcemanager.Service
	pid                string
	roleCollectionCopy atomic.Value
	reader             GoogleWorkspaceReader
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

// PolicyReader is an interface to abstract PolicyBindingService.
type PolicyReader interface {
	LoadUsersWithRoleForIdentityAwareProxy(ctx context.Context) error
	IdentityAwareProxyPolicyBindingForUser(uid UserID) (PolicyBindings, error)
	UserRoleCollection() UserRoleCollection
}

var (
	// ErrNoIdentityAwareProxyRoleForUser is returned when user does not have role for IAP.
	ErrNoIdentityAwareProxyRoleForUser = errors.New("no iap role found")
)

// IdentityAwareProxyPolicyBindingForUser look up which bindings (roles and expressions) a user have.
func (p *ProjectPolicyReaderService) IdentityAwareProxyPolicyBindingForUser(uid UserID) (PolicyBindings, error) {
	collection, ok := p.roleCollectionCopy.Load().(UserRoleCollection)
	val, ok := collection[uid]
	if !ok {
		return nil, ErrNoIdentityAwareProxyRoleForUser
	}
	return val[iapRole], nil
}

// NewProjectPolicyReaderService generates an implementation of PolicyBindingReader.
func NewProjectPolicyReaderService(ctx context.Context, reader GoogleWorkspaceReader, refreshInterval time.Duration) (*ProjectPolicyReaderService, error) {
	credentials, err := google.FindDefaultCredentials(ctx,
		"https://www.googleapis.com/auth/cloud-platform.read-only")
	if err != nil {
		return nil, err
	}
	service, err := cloudresourcemanager.NewService(ctx, option.WithCredentials(credentials))
	if err != nil {
		return nil, err
	}
	ps := &ProjectPolicyReaderService{
		service: service,
		pid:     credentials.ProjectID,
		reader:  reader,
	}
	if err = ps.LoadUsersWithRoleForIdentityAwareProxy(ctx); err != nil {
		return nil, err
	}
	go ps.refreshProjectPolicyBindings(ctx, refreshInterval)
	return ps, nil
}

// UserRoleCollection retrieve entire collection of policy bindings per user.
func (p *ProjectPolicyReaderService) UserRoleCollection() UserRoleCollection {
	val := p.roleCollectionCopy.Load()
	return val.(UserRoleCollection)
}

func (p *ProjectPolicyReaderService) refreshProjectPolicyBindings(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.LoadUsersWithRoleForIdentityAwareProxy(ctx); err != nil {
				log.WithField("error", err).Error("Could not refresh project policy bindings.")
			}
		}
	}
}

// LoadUsersWithRoleForIdentityAwareProxy load UserRoleCollection into local memory for usage.
func (p *ProjectPolicyReaderService) LoadUsersWithRoleForIdentityAwareProxy(ctx context.Context) error {
	policies, err := p.service.Projects.GetIamPolicy(p.pid,
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
				membersInGroup, err := p.reader.ListMembersInGroup(ctx, string(uid))
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
	p.roleCollectionCopy.Store(userRoleCollection)
	return nil
}
