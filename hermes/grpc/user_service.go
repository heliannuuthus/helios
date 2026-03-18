package grpc

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/pkg/dto"
	"github.com/heliannuuthus/helios/pkg/models"
	"github.com/heliannuuthus/helios/pkg/pagination"
)

type userServiceServer struct {
	hermesv1.UnimplementedUserServiceServer
	userSvc *hermes.UserService
	svc     *hermes.Service
}

func NewUserServiceServer(userSvc *hermes.UserService, svc *hermes.Service) hermesv1.UserServiceServer {
	return &userServiceServer{userSvc: userSvc, svc: svc}
}

func (s *userServiceServer) GetByOpenID(ctx context.Context, req *hermesv1.OpenIDRequest) (*hermesv1.User, error) {
	u, err := s.userSvc.GetByOpenID(ctx, req.GetOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	return userToProto(u), nil
}

func (s *userServiceServer) GetByIdentity(ctx context.Context, req *hermesv1.GetByIdentityRequest) (*hermesv1.User, error) {
	identity := &models.UserIdentity{
		Domain:  req.GetDomain(),
		IDP:     req.GetIdp(),
		TOpenID: req.GetTOpenid(),
	}
	u, err := s.userSvc.GetByIdentity(ctx, identity)
	if err != nil {
		return nil, toStatus(err)
	}
	return userToProto(u), nil
}

func (s *userServiceServer) GetByEmail(ctx context.Context, req *hermesv1.GetByEmailRequest) (*hermesv1.DecryptedUser, error) {
	u, err := s.userSvc.GetByEmail(ctx, req.GetEmail())
	if err != nil {
		return nil, toStatus(err)
	}
	return decryptedUserToProto(u), nil
}

func (s *userServiceServer) GetByPhonePlain(ctx context.Context, req *hermesv1.GetByPhonePlainRequest) (*hermesv1.DecryptedUser, error) {
	u, err := s.userSvc.GetByPhonePlain(ctx, req.GetPhone())
	if err != nil {
		return nil, toStatus(err)
	}
	return decryptedUserToProto(u), nil
}

func (s *userServiceServer) GetDecryptedUser(ctx context.Context, req *hermesv1.OpenIDRequest) (*hermesv1.DecryptedUser, error) {
	u, err := s.userSvc.GetUserWithDecrypted(ctx, req.GetOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	return decryptedUserToProto(u), nil
}

func (s *userServiceServer) GetDecryptedUserByIdentity(ctx context.Context, req *hermesv1.GetByIdentityRequest) (*hermesv1.DecryptedUser, error) {
	identity := &models.UserIdentity{
		Domain:  req.GetDomain(),
		IDP:     req.GetIdp(),
		TOpenID: req.GetTOpenid(),
	}
	u, err := s.userSvc.GetUserWithDecryptedByIdentity(ctx, identity)
	if err != nil {
		return nil, toStatus(err)
	}
	return decryptedUserToProto(u), nil
}

func (s *userServiceServer) CreateUser(ctx context.Context, req *hermesv1.CreateUserRequest) (*hermesv1.DecryptedUser, error) {
	identity := &models.UserIdentity{
		Domain:  req.GetIdentity().GetDomain(),
		IDP:     req.GetIdentity().GetIdp(),
		TOpenID: req.GetIdentity().GetTOpenid(),
		RawData: ptrOrEmpty(req.GetIdentity().RawData),
	}

	var userInfo *models.TUserInfo
	if req.UserInfo != nil {
		ui := req.GetUserInfo()
		userInfo = &models.TUserInfo{
			TOpenID: ui.GetTOpenid(),
		}
		if ui.Nickname != nil {
			userInfo.Nickname = *ui.Nickname
		}
		if ui.Email != nil {
			userInfo.Email = *ui.Email
		}
		if ui.Phone != nil {
			userInfo.Phone = *ui.Phone
		}
		if ui.Picture != nil {
			userInfo.Picture = *ui.Picture
		}
		if ui.RawData != nil {
			userInfo.RawData = *ui.RawData
		}
	}

	u, err := s.userSvc.CreateUser(ctx, identity, userInfo)
	if err != nil {
		return nil, toStatus(err)
	}
	return decryptedUserToProto(u), nil
}

func (s *userServiceServer) UpdateUser(ctx context.Context, req *hermesv1.UpdateUserRequest) (*hermesv1.User, error) {
	updates := make(map[string]any)
	if req.Nickname != nil {
		updates["nickname"] = *req.Nickname
	}
	if req.Picture != nil {
		updates["picture"] = *req.Picture
	}
	if req.Email != nil {
		updates["email"] = *req.Email
	}
	if req.Status != nil {
		updates["status"] = *req.Status
	}

	if len(updates) > 0 {
		if err := s.userSvc.Update(ctx, req.GetOpenid(), updates); err != nil {
			return nil, toStatus(err)
		}
	}

	u, err := s.userSvc.GetByOpenID(ctx, req.GetOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	return userToProto(u), nil
}

func (s *userServiceServer) UpdateLastLogin(ctx context.Context, req *hermesv1.OpenIDRequest) (*emptypb.Empty, error) {
	if err := s.userSvc.UpdateLastLogin(ctx, req.GetOpenid()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) UpdatePassword(ctx context.Context, req *hermesv1.UpdatePasswordRequest) (*emptypb.Empty, error) {
	if err := s.userSvc.UpdatePassword(ctx, req.GetOpenid(), req.GetOldPassword(), req.GetNewPassword()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) GetIdentities(ctx context.Context, req *hermesv1.OpenIDRequest) (*hermesv1.IdentityList, error) {
	identities, err := s.userSvc.GetIdentities(ctx, req.GetOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	return identitiesToProto(identities), nil
}

func (s *userServiceServer) GetIdentitiesByIdentity(ctx context.Context, req *hermesv1.GetByIdentityRequest) (*hermesv1.IdentityList, error) {
	identity := &models.UserIdentity{
		Domain:  req.GetDomain(),
		IDP:     req.GetIdp(),
		TOpenID: req.GetTOpenid(),
	}
	identities, err := s.userSvc.GetIdentitiesByIdentity(ctx, identity)
	if err != nil {
		return nil, toStatus(err)
	}
	return identitiesToProto(identities), nil
}

func (s *userServiceServer) GetIdentityByType(ctx context.Context, req *hermesv1.GetIdentityByTypeRequest) (*hermesv1.UserIdentity, error) {
	identity, err := s.userSvc.GetIdentityByType(ctx, req.GetDomain(), req.GetOpenid(), req.GetIdpType())
	if err != nil {
		return nil, toStatus(err)
	}
	return identityToProto(identity), nil
}

func (s *userServiceServer) AddIdentity(ctx context.Context, req *hermesv1.AddIdentityRequest) (*emptypb.Empty, error) {
	identity := &models.UserIdentity{
		Domain:  req.GetDomain(),
		UID:     req.GetOpenid(),
		IDP:     req.GetIdp(),
		TOpenID: req.GetTOpenid(),
		RawData: ptrOrEmpty(req.RawData),
	}
	if err := s.userSvc.AddIdentity(ctx, identity); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) GetUserByIdentifier(ctx context.Context, req *hermesv1.GetByIdentifierRequest) (*hermesv1.PasswordStoreCredential, error) {
	cred, err := s.userSvc.GetUserByIdentifier(ctx, req.GetIdentifier())
	if err != nil {
		return nil, toStatus(err)
	}
	return passwordStoreCredentialToProto(cred), nil
}

func (s *userServiceServer) GetStaffByIdentifier(ctx context.Context, req *hermesv1.GetByIdentifierRequest) (*hermesv1.PasswordStoreCredential, error) {
	cred, err := s.userSvc.GetStaffByIdentifier(ctx, req.GetIdentifier())
	if err != nil {
		return nil, toStatus(err)
	}
	return passwordStoreCredentialToProto(cred), nil
}

func (s *userServiceServer) CreateCredential(ctx context.Context, req *hermesv1.CreateCredentialRequest) (*emptypb.Empty, error) {
	cred := &models.UserCredential{
		OpenID:  req.GetOpenid(),
		Type:    req.GetType(),
		Enabled: req.GetEnabled(),
		Secret:  req.GetSecret(),
	}
	if req.CredentialId != nil {
		cred.CredentialID = req.CredentialId
	}
	if err := s.userSvc.CreateCredential(ctx, cred); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) GetCredentialByID(ctx context.Context, req *hermesv1.CredentialIDRequest) (*hermesv1.UserCredential, error) {
	cred, err := s.userSvc.GetCredentialByID(ctx, req.GetCredentialId())
	if err != nil {
		return nil, toStatus(err)
	}
	return userCredentialToProto(cred), nil
}

func (s *userServiceServer) GetUserCredentials(ctx context.Context, req *hermesv1.OpenIDRequest) (*hermesv1.UserCredentialList, error) {
	creds, err := s.userSvc.GetUserCredentials(ctx, req.GetOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	return userCredentialListToProto(creds), nil
}

func (s *userServiceServer) GetUserCredentialsByType(ctx context.Context, req *hermesv1.GetCredentialsByTypeRequest) (*hermesv1.UserCredentialList, error) {
	creds, err := s.userSvc.GetUserCredentialsByType(ctx, req.GetOpenid(), req.GetType())
	if err != nil {
		return nil, toStatus(err)
	}
	return userCredentialListToProto(creds), nil
}

func (s *userServiceServer) GetEnabledUserCredentialsByType(ctx context.Context, req *hermesv1.GetCredentialsByTypeRequest) (*hermesv1.UserCredentialList, error) {
	creds, err := s.userSvc.GetEnabledUserCredentialsByType(ctx, req.GetOpenid(), req.GetType())
	if err != nil {
		return nil, toStatus(err)
	}
	return userCredentialListToProto(creds), nil
}

func (s *userServiceServer) UpdateCredential(ctx context.Context, req *hermesv1.UpdateCredentialRequest) (*emptypb.Empty, error) {
	updates := make(map[string]any)
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if req.Secret != nil {
		updates["secret"] = *req.Secret
	}
	if req.LastUsedAt != nil {
		updates["last_used_at"] = req.LastUsedAt.AsTime()
	}

	if len(updates) > 0 {
		if err := s.userSvc.UpdateCredential(ctx, req.GetCredentialId(), updates); err != nil {
			return nil, toStatus(err)
		}
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) UpdateCredentialSignCount(ctx context.Context, req *hermesv1.UpdateCredentialSignCountRequest) (*emptypb.Empty, error) {
	if err := s.userSvc.UpdateCredentialSignCount(ctx, req.GetCredentialId(), req.GetSignCount()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) EnableCredential(ctx context.Context, req *hermesv1.CredentialIDRequest) (*emptypb.Empty, error) {
	if err := s.userSvc.EnableCredential(ctx, req.GetCredentialId()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) DisableCredential(ctx context.Context, req *hermesv1.CredentialIDRequest) (*emptypb.Empty, error) {
	if err := s.userSvc.DisableCredential(ctx, req.GetCredentialId()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) DeleteCredential(ctx context.Context, req *hermesv1.DeleteCredentialRequest) (*emptypb.Empty, error) {
	if err := s.userSvc.DeleteCredential(ctx, req.GetOpenid(), req.GetCredentialId()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) GetOpenIDByCredentialID(ctx context.Context, req *hermesv1.CredentialIDRequest) (*hermesv1.OpenIDResponse, error) {
	openid, err := s.userSvc.GetOpenIDByCredentialID(ctx, req.GetCredentialId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &hermesv1.OpenIDResponse{Openid: openid}, nil
}

// ==================== Group ====================

func (s *userServiceServer) CreateGroup(ctx context.Context, req *hermesv1.CreateGroupRequest) (*hermesv1.Group, error) {
	createReq := &dto.GroupCreateRequest{
		GroupID:     req.GetGroupId(),
		ServiceID:   req.GetServiceId(),
		Name:        req.GetName(),
		Description: req.Description,
	}

	g, err := s.svc.CreateGroup(ctx, createReq)
	if err != nil {
		return nil, toStatus(err)
	}
	return groupToProto(g), nil
}

func (s *userServiceServer) GetGroup(ctx context.Context, req *hermesv1.GetGroupRequest) (*hermesv1.Group, error) {
	g, err := s.svc.GetGroup(ctx, req.GetGroupId())
	if err != nil {
		return nil, toStatus(err)
	}
	return groupToProto(g), nil
}

func (s *userServiceServer) ListGroups(ctx context.Context, req *hermesv1.ListGroupsRequest) (*hermesv1.GroupList, error) {
	listReq := &dto.ListRequest{Filter: req.GetFilter()}
	if p := req.GetPagination(); p != nil {
		listReq.Pagination = pagination.Pagination{Token: p.GetCursor(), Size: int(p.GetLimit())}
	}

	items, err := s.svc.ListGroups(ctx, listReq)
	if err != nil {
		return nil, toStatus(err)
	}

	out := make([]*hermesv1.Group, 0, len(items.Items))
	for i := range items.Items {
		out = append(out, groupToProto(&items.Items[i]))
	}
	return &hermesv1.GroupList{Groups: out, NextCursor: items.Next}, nil
}

func (s *userServiceServer) UpdateGroup(ctx context.Context, req *hermesv1.UpdateGroupRequest) (*hermesv1.Group, error) {
	updateReq := &dto.GroupUpdateRequest{
		Name:        optionalFromPtr(req.Name),
		Description: optionalFromPtr(req.Description),
	}
	if err := s.svc.UpdateGroup(ctx, req.GetGroupId(), updateReq); err != nil {
		return nil, toStatus(err)
	}
	g, err := s.svc.GetGroup(ctx, req.GetGroupId())
	if err != nil {
		return nil, toStatus(err)
	}
	return groupToProto(g), nil
}

func (s *userServiceServer) DeleteGroup(ctx context.Context, req *hermesv1.GetGroupRequest) (*emptypb.Empty, error) {
	if err := s.svc.DeleteGroup(ctx, req.GetGroupId()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) SetGroupMembers(ctx context.Context, req *hermesv1.SetGroupMembersRequest) (*emptypb.Empty, error) {
	memberReq := &dto.GroupMemberRequest{
		GroupID: req.GetGroupId(),
		UserIDs: req.GetUserIds(),
	}
	if err := s.svc.SetGroupMembers(ctx, memberReq); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) GetGroupMembers(ctx context.Context, req *hermesv1.GetGroupRequest) (*hermesv1.StringList, error) {
	members, err := s.svc.GetGroupMembers(ctx, req.GetGroupId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &hermesv1.StringList{Values: members}, nil
}

// ==================== conversion helpers ====================

func userToProto(u *models.User) *hermesv1.User {
	pb := &hermesv1.User{
		Id:            safeUint32(u.ID),
		Openid:        u.OpenID,
		Status:        int32(u.Status),
		Nickname:      u.Nickname,
		Picture:       u.Picture,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		CreatedAt:     timestamppb.New(u.CreatedAt),
		UpdatedAt:     timestamppb.New(u.UpdatedAt),
	}
	if u.LastLoginAt != nil {
		pb.LastLoginAt = timestamppb.New(*u.LastLoginAt)
	}
	return pb
}

func decryptedUserToProto(u *models.UserWithDecrypted) *hermesv1.DecryptedUser {
	return &hermesv1.DecryptedUser{
		User:  userToProto(&u.User),
		Phone: u.Phone,
	}
}

func identityToProto(i *models.UserIdentity) *hermesv1.UserIdentity {
	pb := &hermesv1.UserIdentity{
		Id:        safeUint32(i.ID),
		Domain:    i.Domain,
		Openid:    i.UID,
		Idp:       i.IDP,
		TOpenid:   i.TOpenID,
		CreatedAt: timestamppb.New(i.CreatedAt),
	}
	if i.RawData != "" {
		pb.RawData = &i.RawData
	}
	return pb
}

func identitiesToProto(identities models.Identities) *hermesv1.IdentityList {
	out := make([]*hermesv1.UserIdentity, 0, len(identities))
	for _, i := range identities {
		out = append(out, identityToProto(i))
	}
	return &hermesv1.IdentityList{Identities: out}
}

func passwordStoreCredentialToProto(c *dto.PasswordStoreCredential) *hermesv1.PasswordStoreCredential {
	pb := &hermesv1.PasswordStoreCredential{
		Openid:       c.OpenID,
		PasswordHash: c.PasswordHash,
		Status:       int32(c.Status),
	}
	if c.Nickname != "" {
		pb.Nickname = &c.Nickname
	}
	if c.Email != "" {
		pb.Email = &c.Email
	}
	if c.Picture != "" {
		pb.Picture = &c.Picture
	}
	return pb
}

func userCredentialToProto(c *models.UserCredential) *hermesv1.UserCredential {
	pb := &hermesv1.UserCredential{
		Id:           safeUint32(c.ID),
		Openid:       c.OpenID,
		CredentialId: c.CredentialID,
		Type:         c.Type,
		Enabled:      c.Enabled,
		CreatedAt:    timestamppb.New(c.CreatedAt),
		UpdatedAt:    timestamppb.New(c.UpdatedAt),
	}
	if c.LastUsedAt != nil {
		pb.LastUsedAt = timestamppb.New(*c.LastUsedAt)
	}
	return pb
}

func userCredentialListToProto(creds []models.UserCredential) *hermesv1.UserCredentialList {
	out := make([]*hermesv1.UserCredential, 0, len(creds))
	for i := range creds {
		out = append(out, userCredentialToProto(&creds[i]))
	}
	return &hermesv1.UserCredentialList{Credentials: out}
}

func ptrOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func groupToProto(g *models.Group) *hermesv1.Group {
	return &hermesv1.Group{
		Id:          safeUint32(g.ID),
		GroupId:     g.GroupID,
		ServiceId:   g.ServiceID,
		Name:        g.Name,
		Description: g.Description,
		CreatedAt:   timestamppb.New(g.CreatedAt),
		UpdatedAt:   timestamppb.New(g.UpdatedAt),
	}
}
