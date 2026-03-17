package grpc

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/pkg/dto"
	"github.com/heliannuuthus/helios/pkg/models"
)

type userServiceServer struct {
	hermesv1.UnimplementedUserServiceServer
	userSvc *hermes.UserService
	credSvc *hermes.CredentialService
}

func NewUserServiceServer(userSvc *hermes.UserService, credSvc *hermes.CredentialService) hermesv1.UserServiceServer {
	return &userServiceServer{userSvc: userSvc, credSvc: credSvc}
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

// ==================== TOTP delegates ====================

func (s *userServiceServer) SetupTOTP(ctx context.Context, req *hermesv1.SetupTOTPRequest) (*hermesv1.SetupTOTPResponse, error) {
	resp, err := s.credSvc.SetupTOTP(ctx, &dto.TOTPSetupRequest{
		OpenID:  req.GetOpenid(),
		AppName: req.GetAppName(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &hermesv1.SetupTOTPResponse{
		Secret:       resp.Secret,
		OtpauthUri:   resp.OTPAuthURI,
		CredentialId: safeUint32(resp.CredentialID),
	}, nil
}

func (s *userServiceServer) ConfirmTOTP(ctx context.Context, req *hermesv1.ConfirmTOTPRequest) (*emptypb.Empty, error) {
	if err := s.credSvc.ConfirmTOTP(ctx, &dto.ConfirmTOTPRequest{
		OpenID:       req.GetOpenid(),
		CredentialID: uint(req.GetCredentialId()),
		Code:         req.GetCode(),
	}); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) VerifyTOTP(ctx context.Context, req *hermesv1.VerifyTOTPRequest) (*emptypb.Empty, error) {
	if err := s.credSvc.VerifyTOTP(ctx, &dto.VerifyTOTPRequest{
		OpenID: req.GetOpenid(),
		Code:   req.GetCode(),
	}); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) DisableTOTP(ctx context.Context, req *hermesv1.OpenIDRequest) (*emptypb.Empty, error) {
	if err := s.credSvc.DisableTOTP(ctx, req.GetOpenid()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) CheckTOTPEnabled(ctx context.Context, req *hermesv1.OpenIDRequest) (*hermesv1.BoolValue, error) {
	enabled, err := s.credSvc.HasTOTP(ctx, req.GetOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	return &hermesv1.BoolValue{Value: enabled}, nil
}

func (s *userServiceServer) SetTOTPEnabled(ctx context.Context, req *hermesv1.SetTOTPEnabledRequest) (*emptypb.Empty, error) {
	if err := s.credSvc.SetTOTPEnabled(ctx, req.GetOpenid(), req.GetEnabled()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

// ==================== WebAuthn delegates ====================

func (s *userServiceServer) RegisterWebAuthn(ctx context.Context, req *hermesv1.RegisterWebAuthnRequest) (*hermesv1.UserCredential, error) {
	cred, err := s.credSvc.RegisterWebAuthn(ctx, &dto.RegisterWebAuthnRequest{
		OpenID:          req.GetOpenid(),
		CredentialID:    req.GetCredentialId(),
		PublicKey:       req.GetPublicKey(),
		AAGUID:          req.GetAaguid(),
		Transport:       req.GetTransport(),
		AttestationType: req.GetAttestationType(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return userCredentialToProto(cred), nil
}

func (s *userServiceServer) GetWebAuthnByCredentialID(ctx context.Context, req *hermesv1.CredentialIDRequest) (*hermesv1.WebAuthnCredentialDetail, error) {
	cred, secret, err := s.credSvc.GetWebAuthnByCredentialID(ctx, req.GetCredentialId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &hermesv1.WebAuthnCredentialDetail{
		Credential: userCredentialToProto(cred),
		Secret: &hermesv1.WebAuthnSecret{
			PublicKey:       secret.PublicKey,
			SignCount:       secret.SignCount,
			Aaguid:          secret.AAGUID,
			Transport:       secret.Transport,
			AttestationType: secret.AttestationType,
		},
	}, nil
}

func (s *userServiceServer) UpdateWebAuthnSignCount(ctx context.Context, req *hermesv1.UpdateWebAuthnSignCountRequest) (*emptypb.Empty, error) {
	if err := s.credSvc.UpdateWebAuthnSignCount(ctx, req.GetCredentialId(), req.GetSignCount()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) ListUserWebAuthn(ctx context.Context, req *hermesv1.OpenIDRequest) (*hermesv1.UserCredentialList, error) {
	creds, err := s.credSvc.ListUserWebAuthn(ctx, req.GetOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	return userCredentialListToProto(creds), nil
}

func (s *userServiceServer) DeleteWebAuthn(ctx context.Context, req *hermesv1.DeleteWebAuthnRequest) (*emptypb.Empty, error) {
	if err := s.credSvc.DeleteWebAuthn(ctx, req.GetOpenid(), req.GetCredentialId()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) SetWebAuthnEnabled(ctx context.Context, req *hermesv1.SetWebAuthnEnabledRequest) (*emptypb.Empty, error) {
	if err := s.credSvc.SetWebAuthnEnabled(ctx, req.GetOpenid(), req.GetCredentialId(), req.GetEnabled()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *userServiceServer) GetPublicKeyForCredential(ctx context.Context, req *hermesv1.CredentialIDRequest) (*hermesv1.PublicKeyResponse, error) {
	pk, err := s.credSvc.GetPublicKeyForCredential(ctx, req.GetCredentialId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &hermesv1.PublicKeyResponse{PublicKey: pk}, nil
}

func (s *userServiceServer) GetUserCredentialSummaries(ctx context.Context, req *hermesv1.OpenIDRequest) (*hermesv1.CredentialSummaryList, error) {
	summaries, err := s.credSvc.GetUserCredentialSummaries(ctx, req.GetOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*hermesv1.CredentialSummary, 0, len(summaries))
	for i := range summaries {
		cs := &hermesv1.CredentialSummary{
			Id:           safeUint32(summaries[i].ID),
			Type:         summaries[i].Type,
			CredentialId: summaries[i].CredentialID,
			Enabled:      summaries[i].Enabled,
			CreatedAt:    timestamppb.New(summaries[i].CreatedAt),
		}
		if summaries[i].LastUsedAt != nil {
			cs.LastUsedAt = timestamppb.New(*summaries[i].LastUsedAt)
		}
		out = append(out, cs)
	}
	return &hermesv1.CredentialSummaryList{Summaries: out}, nil
}

func (s *userServiceServer) GetUserMFAStatus(ctx context.Context, req *hermesv1.OpenIDRequest) (*hermesv1.MFAStatus, error) {
	status, err := s.credSvc.GetUserMFAStatus(ctx, req.GetOpenid())
	if err != nil {
		return nil, toStatus(err)
	}
	return &hermesv1.MFAStatus{
		TotpEnabled:   status.TOTPEnabled,
		WebauthnCount: safeInt32(status.WebAuthnCount),
		PasskeyCount:  safeInt32(status.PasskeyCount),
	}, nil
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
