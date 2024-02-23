package internal

import (
	"context"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

type googleWorkspaceReader struct {
	admin *admin.Service
}

// GoogleWorkspaceReader interface abstracts functions required.
type GoogleWorkspaceReader interface {
	ListMembersInGroup(ctx context.Context, email string) ([]UserID, error)
}

// NewGoogleWorkspaceReader creates a new client to use with Google Workspace.
func NewGoogleWorkspaceReader(ctx context.Context) (*googleWorkspaceReader, error) {
	credentials, err := google.FindDefaultCredentials(ctx, admin.AdminDirectoryGroupScope)
	if err != nil {
		return nil, err
	}
	gws, err := admin.NewService(ctx, option.WithCredentials(credentials))
	if err != nil {
		return nil, err
	}
	return &googleWorkspaceReader{
		admin: gws,
	}, nil
}

// ListMembersInGroup returns list of members inside Google Workspace group.
func (g *googleWorkspaceReader) ListMembersInGroup(ctx context.Context, email string) ([]UserID, error) {
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
