package internal

import (
	"context"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
	"strings"
)

// GoogleWorkspaceClient is an implementation of interface GoogleWorkspaceReader.
type GoogleWorkspaceClient struct {
	admin *admin.Service
}

type emailSet map[string]struct{}

// GoogleWorkspaceClientReader interface abstracts functions required.
type GoogleWorkspaceClientReader interface {
	ListGoogleServiceAccounts(ctx context.Context, groupEmail string) ([]GoogleServiceAccount, error)
}

// NewGoogleWorkspaceClient creates new client for Google Workspace.
func NewGoogleWorkspaceClient(ctx context.Context, credentials *google.Credentials) (*GoogleWorkspaceClient, error) {
	gws, err := admin.NewService(ctx, option.WithCredentials(credentials))
	if err != nil {
		return nil, err
	}
	return &GoogleWorkspaceClient{
		admin: gws,
	}, nil
}

func (g *GoogleWorkspaceClient) traverseGroups(ctx context.Context, email string, doTraverse bool, seenGroupEmails, emailOfAllGroups emailSet, members []GoogleServiceAccount) ([]GoogleServiceAccount, error) {
	response, err := g.admin.Members.List(email).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	for _, member := range response.Members {
		if ok := doTraverse && seenGroupEmails.hasEmail(member.Email); ok {
			log.Debugf("%s email already seen, skipping.", member.Email)
			continue
		} else if ok = doTraverse && emailOfAllGroups.hasEmail(member.Email); ok {
			seenGroupEmails[member.Email] = struct{}{}

			log.Debugf("%s email identified as group within group %s. Requesting group information.", member.Email, email)
			members, err = g.traverseGroups(ctx, member.Email, doTraverse, seenGroupEmails, emailOfAllGroups, members)
			if err != nil {
				return nil, err
			}
		} else if strings.HasSuffix(member.Email, "iam.gserviceaccount.com") {
			members = append(members, GoogleServiceAccount(member.Email))
		}
	}
	return members, nil
}

// listAllGroupEmails returns a set of group emails which are present within Google Workspace.
func (g *GoogleWorkspaceClient) listAllGroupEmails(ctx context.Context, domain string) (emailSet, error) {
	allGroups, err := g.admin.Groups.List().Domain(domain).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	allGroupsEmails := make(emailSet, len(allGroups.Groups))

	for _, group := range allGroups.Groups {
		allGroupsEmails[group.Email] = struct{}{}
	}
	return allGroupsEmails, nil
}

// ListGoogleServiceAccounts returns list of Google Service Accounts inside Google Workspace groups.
func (g *GoogleWorkspaceClient) ListGoogleServiceAccounts(ctx context.Context, groupEmail string) ([]GoogleServiceAccount, error) {
	var (
		doTraverse = true
		domainPart = groupEmail[strings.LastIndex(groupEmail, "@")+1:]
		seenGroups = make(emailSet, 100)
		members    = make([]GoogleServiceAccount, 0, 100)
	)

	allGroupsInDomain, err := g.listAllGroupEmails(ctx, domainPart)
	if err != nil {
		log.Warnf("Domain %s was not found in Google Workspace, will not traverse group in group.", domainPart)
		doTraverse = false
	}
	log.Debugf("Request group %s for member information.", groupEmail)
	return g.traverseGroups(ctx, groupEmail, doTraverse, seenGroups, allGroupsInDomain, members)
}

func (e emailSet) hasEmail(email string) bool {
	_, ok := e[email]
	return ok
}
