package internal

import (
	"context"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

// GoogleWorkspaceClient is an implementation of interface GoogleWorkspaceReader.
type GoogleWorkspaceClient struct {
	admin *admin.Service
}

// GoogleWorkspaceClientReader interface abstracts functions required.
type GoogleWorkspaceClientReader interface {
	MembersInGroup(ctx context.Context, email string) ([]UserID, error)
}

// NewGoogleWorkspaceClient creates a new client to use with Google Workspace.
func NewGoogleWorkspaceClient(ctx context.Context, credentials *google.Credentials) (*GoogleWorkspaceClient, error) {
	gws, err := admin.NewService(ctx, option.WithCredentials(credentials))
	if err != nil {
		return nil, err
	}
	return &GoogleWorkspaceClient{
		admin: gws,
	}, nil
}

// MembersInGroup returns list of members inside Google Workspace group.
func (g *GoogleWorkspaceClient) MembersInGroup(ctx context.Context, email string) ([]UserID, error) {
	response, err := g.admin.Members.List(email).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	members := make([]UserID, 0, len(response.Members))
	for _, member := range response.Members {
		members = append(members, UserID(member.Email))
	}
	return members, nil
}
