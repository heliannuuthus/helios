package grpc

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/hermes/dto"
	"github.com/heliannuuthus/helios/hermes/models"
)

type userServiceServer struct {
	hermesv1.UnimplementedUserServiceServer
	svc *hermes.UserService
}

func NewUserServiceServer(svc *hermes.UserService) hermesv1.UserServiceServer {
	return &userServiceServer{svc: svc}
}

// ==================== User ====================

func (s *userServiceServer) GetByEmail(ctx context.Context, req *hermesv1.GetByEmailRequest) (*hermesv1.DecryptedUser, error) {
	u, err := s.svc.GetUserByEmail(ctx, req.GetEmail())
	if err != nil {
		return nil, toStatus(err)
	}
	return decryptedUserToProto(u), nil
}

func (s *userServiceServer) GetByPhonePlain(ctx context.Context, req *hermesv1.GetByPhonePlainRequest) (*hermesv1.DecryptedUser, error) {
	u, err := s.svc.GetUserByPhone(ctx, req.GetPhone())
	if err != nil {
		return nil, toStatus(err)
	}
	return decryptedUserToProto(u), nil
}

func (s *userServiceServer) GetDecryptedUser(ctx context.Context, req *hermesv1.OpenIDRequest) (*hermesv1.DecryptedUser, error) {
	u, err := s.svc.GetDecryptedUserByOpenID(ctx, req.GetOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	return decryptedUserToProto(u), nil
}

func (s *userServiceServer) CreateUser(ctx context.Context, req *hermesv1.CreateUserRequest) (*hermesv1.DecryptedUser, error) {
	identity := protoToIdentity(req.GetIdentity())
	var userInfo *models.TUserInfo
	if req.UserInfo != nil {
		userInfo = protoToTUserInfo(req.GetUserInfo())
	}
	u, err := s.svc.CreateUser(ctx, identity, userInfo)
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
		updates["status"] = int8(*req.Status)
	}
	if err := s.svc.UpdateUser(ctx, req.GetOpenid(), updates); err != nil {
		return nil, toStatus(err)
	}
	u, err := s.svc.GetUserByOpenID(ctx, req.GetOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	return userToProto(u), nil
}

func (s *userServiceServer) UpdateLastLogin(ctx context.Context, req *hermesv1.OpenIDRequest) (*emptypb.Empty, error) {
	if err := s.svc.UpdateLastLogin(ctx, req.GetOpenid()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) UpdatePassword(ctx context.Context, req *hermesv1.UpdatePasswordRequest) (*emptypb.Empty, error) {
	if err := s.svc.UpdatePassword(ctx, req.GetOpenid(), req.GetOldPassword(), req.GetNewPassword()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

// ==================== Identity ====================

func (s *userServiceServer) GetIdentities(ctx context.Context, req *hermesv1.OpenIDRequest) (*hermesv1.IdentityList, error) {
	ids, err := s.svc.GetUserIdentitiesByOpenID(ctx, req.GetOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	return identitiesToProto(ids), nil
}

func (s *userServiceServer) GetIdentitiesByIdentity(ctx context.Context, req *hermesv1.GetByIdentityRequest) (*hermesv1.IdentityList, error) {
	ids, err := s.svc.GetIdentities(ctx, req.GetDomain(), req.GetIdp(), req.GetTOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	return identitiesToProto(ids), nil
}

func (s *userServiceServer) AddIdentity(ctx context.Context, req *hermesv1.AddIdentityRequest) (*emptypb.Empty, error) {
	identity := &models.UserIdentity{
		Domain:  req.GetDomain(),
		UID:     req.GetOpenid(),
		IDP:     req.GetIdp(),
		TOpenID: req.GetTOpenid(),
		RawData: req.GetRawData(),
	}
	if err := s.svc.AddIdentity(ctx, identity); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

// ==================== Password Store ====================

func (s *userServiceServer) GetUserByIdentifier(ctx context.Context, req *hermesv1.GetByIdentifierRequest) (*hermesv1.PasswordStoreCredential, error) {
	c, err := s.svc.GetUserByIdentifier(ctx, req.GetIdentifier())
	if err != nil {
		return nil, toStatus(err)
	}
	return passwordStoreCredentialToProto(c), nil
}

func (s *userServiceServer) GetStaffByIdentifier(ctx context.Context, req *hermesv1.GetByIdentifierRequest) (*hermesv1.PasswordStoreCredential, error) {
	c, err := s.svc.GetStaffByIdentifier(ctx, req.GetIdentifier())
	if err != nil {
		return nil, toStatus(err)
	}
	return passwordStoreCredentialToProto(c), nil
}

// ==================== Credential ====================

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
	if err := s.svc.CreateCredential(ctx, cred); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) GetCredentialByID(ctx context.Context, req *hermesv1.CredentialIDRequest) (*hermesv1.UserCredential, error) {
	c, err := s.svc.GetCredentialByID(ctx, req.GetCredentialId())
	if err != nil {
		return nil, toStatus(err)
	}
	return credentialToProto(c), nil
}

func (s *userServiceServer) GetUserCredentials(ctx context.Context, req *hermesv1.OpenIDRequest) (*hermesv1.UserCredentialList, error) {
	cs, err := s.svc.GetUserCredentials(ctx, req.GetOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	return credentialListToProto(cs), nil
}

func (s *userServiceServer) GetUserCredentialsByType(ctx context.Context, req *hermesv1.GetCredentialsByTypeRequest) (*hermesv1.UserCredentialList, error) {
	cs, err := s.svc.GetUserCredentialsByType(ctx, req.GetOpenid(), req.GetType())
	if err != nil {
		return nil, toStatus(err)
	}
	return credentialListToProto(cs), nil
}

func (s *userServiceServer) GetEnabledUserCredentialsByType(ctx context.Context, req *hermesv1.GetCredentialsByTypeRequest) (*hermesv1.UserCredentialList, error) {
	cs, err := s.svc.GetEnabledUserCredentialsByType(ctx, req.GetOpenid(), req.GetType())
	if err != nil {
		return nil, toStatus(err)
	}
	return credentialListToProto(cs), nil
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
	if err := s.svc.UpdateCredential(ctx, req.GetCredentialId(), updates); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) UpdateCredentialSignCount(ctx context.Context, req *hermesv1.UpdateCredentialSignCountRequest) (*emptypb.Empty, error) {
	if err := s.svc.UpdateCredentialSignCount(ctx, req.GetCredentialId(), req.GetSignCount()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) EnableCredential(ctx context.Context, req *hermesv1.CredentialIDRequest) (*emptypb.Empty, error) {
	if err := s.svc.EnableCredential(ctx, req.GetCredentialId()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) DisableCredential(ctx context.Context, req *hermesv1.CredentialIDRequest) (*emptypb.Empty, error) {
	if err := s.svc.DisableCredential(ctx, req.GetCredentialId()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) DeleteCredential(ctx context.Context, req *hermesv1.DeleteCredentialRequest) (*emptypb.Empty, error) {
	if err := s.svc.DeleteCredential(ctx, req.GetOpenid(), req.GetCredentialId()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) GetOpenIDByCredentialID(ctx context.Context, req *hermesv1.CredentialIDRequest) (*hermesv1.OpenIDResponse, error) {
	openid, err := s.svc.GetOpenIDByCredentialID(ctx, req.GetCredentialId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &hermesv1.OpenIDResponse{Openid: openid}, nil
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

func identityToProto(id *models.UserIdentity) *hermesv1.UserIdentity {
	pb := &hermesv1.UserIdentity{
		Id:        safeUint32(id.ID),
		Domain:    id.Domain,
		Openid:    id.UID,
		Idp:       id.IDP,
		TOpenid:   id.TOpenID,
		CreatedAt: timestamppb.New(id.CreatedAt),
		UpdatedAt: timestamppb.New(id.UpdatedAt),
	}
	if id.RawData != "" {
		pb.RawData = &id.RawData
	}
	return pb
}

func identitiesToProto(ids models.Identities) *hermesv1.IdentityList {
	out := make([]*hermesv1.UserIdentity, 0, len(ids))
	for _, id := range ids {
		out = append(out, identityToProto(id))
	}
	return &hermesv1.IdentityList{Identities: out}
}

func protoToIdentity(pb *hermesv1.UserIdentity) *models.UserIdentity {
	return &models.UserIdentity{
		Domain:  pb.GetDomain(),
		UID:     pb.GetOpenid(),
		IDP:     pb.GetIdp(),
		TOpenID: pb.GetTOpenid(),
		RawData: pb.GetRawData(),
	}
}

func protoToTUserInfo(pb *hermesv1.TUserInfo) *models.TUserInfo {
	return &models.TUserInfo{
		TOpenID:  pb.GetTOpenid(),
		Nickname: pb.GetNickname(),
		Email:    pb.GetEmail(),
		Phone:    pb.GetPhone(),
		Picture:  pb.GetPicture(),
		RawData:  pb.GetRawData(),
	}
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

func credentialToProto(c *models.UserCredential) *hermesv1.UserCredential {
	pb := &hermesv1.UserCredential{
		Id:           safeUint32(c.ID),
		Openid:       c.OpenID,
		CredentialId: c.CredentialID,
		Type:         c.Type,
		Enabled:      c.Enabled,
		Secret:       c.Secret,
		CreatedAt:    timestamppb.New(c.CreatedAt),
		UpdatedAt:    timestamppb.New(c.UpdatedAt),
	}
	if c.LastUsedAt != nil {
		pb.LastUsedAt = timestamppb.New(*c.LastUsedAt)
	}
	return pb
}

func credentialListToProto(cs []models.UserCredential) *hermesv1.UserCredentialList {
	out := make([]*hermesv1.UserCredential, 0, len(cs))
	for i := range cs {
		out = append(out, credentialToProto(&cs[i]))
	}
	return &hermesv1.UserCredentialList{Credentials: out}
}
