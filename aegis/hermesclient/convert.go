package hermesclient

import (
	"math"
	"time"

	"github.com/go-json-experiment/json"
	"google.golang.org/protobuf/types/known/timestamppb"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/pkg/dto"
	"github.com/heliannuuthus/helios/pkg/models"
	"github.com/heliannuuthus/helios/pkg/patch"
)

func domainFromProto(pb *hermesv1.Domain) *models.Domain {
	if pb == nil {
		return nil
	}
	return &models.Domain{
		DomainID:    pb.DomainId,
		Name:        pb.Name,
		Description: pb.Description,
	}
}

func applicationFromProto(pb *hermesv1.Application) *models.Application {
	if pb == nil {
		return nil
	}
	app := &models.Application{
		ID:                            uint(pb.Id),
		DomainID:                      pb.DomainId,
		AppID:                         pb.AppId,
		Name:                          pb.Name,
		Description:                   pb.Description,
		LogoURL:                       pb.LogoUrl,
		IDTokenExpiresIn:              uint(pb.IdTokenExpiresIn),
		RefreshTokenExpiresIn:         uint(pb.RefreshTokenExpiresIn),
		RefreshTokenAbsoluteExpiresIn: uint(pb.RefreshTokenAbsoluteExpiresIn),
	}
	app.AllowedRedirectURIs = marshalStringSlice(pb.AllowedRedirectUris)
	app.AllowedOrigins = marshalStringSlice(pb.AllowedOrigins)
	app.AllowedLogoutURIs = marshalStringSlice(pb.AllowedLogoutUris)
	if pb.CreatedAt != nil {
		app.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		app.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	return app
}

func serviceFromProto(pb *hermesv1.Service) *models.Service {
	if pb == nil {
		return nil
	}
	svc := &models.Service{
		ID:                   uint(pb.Id),
		DomainID:             pb.DomainId,
		ServiceID:            pb.ServiceId,
		Name:                 pb.Name,
		Description:          pb.Description,
		LogoURL:              pb.LogoUrl,
		AccessTokenExpiresIn: uint(pb.AccessTokenExpiresIn),
	}
	if len(pb.RequiredIdentityTypes) > 0 {
		s := marshalStringSlice(pb.RequiredIdentityTypes)
		svc.RequiredIdentities = s
	}
	if pb.CreatedAt != nil {
		svc.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		svc.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	for _, cs := range pb.ChallengeSettings {
		svc.ChallengeSettings = append(svc.ChallengeSettings, *challengeSettingFromProto(cs))
	}
	return svc
}

func challengeSettingFromProto(pb *hermesv1.ServiceChallengeSetting) *models.ServiceChallengeSetting {
	if pb == nil {
		return nil
	}
	cs := &models.ServiceChallengeSetting{
		ID:        uint(pb.Id),
		ServiceID: pb.ServiceId,
		Type:      pb.Type,
		ExpiresIn: uint(pb.ExpiresIn),
	}
	if len(pb.Limits) > 0 {
		cs.Limits = make(models.RateLimits, len(pb.Limits))
		for k, v := range pb.Limits {
			cs.Limits[k] = int(v)
		}
	}
	if pb.CreatedAt != nil {
		cs.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		cs.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	return cs
}

func relationshipFromProto(pb *hermesv1.Relationship) *models.Relationship {
	if pb == nil {
		return nil
	}
	rel := &models.Relationship{
		ID:          uint(pb.Id),
		ServiceID:   pb.ServiceId,
		SubjectType: pb.SubjectType,
		SubjectID:   pb.SubjectId,
		Relation:    pb.Relation,
		ObjectType:  pb.ObjectType,
		ObjectID:    pb.ObjectId,
	}
	if pb.CreatedAt != nil {
		rel.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.ExpiresAt != nil {
		t := pb.ExpiresAt.AsTime()
		rel.ExpiresAt = &t
	}
	return rel
}

func groupFromProto(pb *hermesv1.Group) *models.Group {
	if pb == nil {
		return nil
	}
	g := &models.Group{
		ID:          uint(pb.Id),
		GroupID:     pb.GroupId,
		ServiceID:   pb.ServiceId,
		Name:        pb.Name,
		Description: pb.Description,
	}
	if pb.CreatedAt != nil {
		g.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		g.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	return g
}

func idpConfigFromProto(pb *hermesv1.ApplicationIDPConfig) *models.ApplicationIDPConfig {
	if pb == nil {
		return nil
	}
	return &models.ApplicationIDPConfig{
		ID:       uint(pb.Id),
		AppID:    pb.AppId,
		Type:     pb.Type,
		Priority: int(pb.Priority),
		Strategy: pb.Strategy,
	}
}

func domainIDPConfigFromProto(pb *hermesv1.DomainIDPConfig) *models.DomainIDPConfig {
	if pb == nil {
		return nil
	}
	cfg := &models.DomainIDPConfig{
		ID:       uint(pb.Id),
		DomainID: pb.DomainId,
		IDPType:  pb.Type,
		Priority: int(pb.Priority),
		Strategy: pb.Strategy,
	}
	if pb.CreatedAt != nil {
		cfg.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		cfg.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	return cfg
}

func idpKeyFromProto(pb *hermesv1.IDPKey) *models.IDPKey {
	if pb == nil {
		return nil
	}
	k := &models.IDPKey{
		ID:      uint(pb.Id),
		IDPType: pb.IdpType,
		TAppID:  pb.TAppId,
	}
	if pb.CreatedAt != nil {
		k.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		k.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	return k
}

func appServiceRelationFromProto(pb *hermesv1.ApplicationServiceRelation) models.ApplicationServiceRelation {
	r := models.ApplicationServiceRelation{
		ID:        uint(pb.Id),
		AppID:     pb.AppId,
		ServiceID: pb.ServiceId,
		Relation:  pb.Relation,
	}
	if pb.CreatedAt != nil {
		r.CreatedAt = pb.CreatedAt.AsTime()
	}
	return r
}

func userFromProto(pb *hermesv1.User) *models.User {
	if pb == nil {
		return nil
	}
	u := &models.User{
		ID:            uint(pb.Id),
		OpenID:        pb.Openid,
		Status:        safeInt8(pb.Status),
		Nickname:      pb.Nickname,
		Picture:       pb.Picture,
		Email:         pb.Email,
		EmailVerified: pb.EmailVerified,
	}
	if pb.LastLoginAt != nil {
		t := pb.LastLoginAt.AsTime()
		u.LastLoginAt = &t
	}
	if pb.CreatedAt != nil {
		u.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		u.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	return u
}

func decryptedUserFromProto(pb *hermesv1.DecryptedUser) *models.UserWithDecrypted {
	if pb == nil {
		return nil
	}
	u := userFromProto(pb.User)
	if u == nil {
		return nil
	}
	return &models.UserWithDecrypted{
		User:  *u,
		Phone: pb.Phone,
	}
}

func identityFromProto(pb *hermesv1.UserIdentity) *models.UserIdentity {
	if pb == nil {
		return nil
	}
	id := &models.UserIdentity{
		ID:      uint(pb.Id),
		Domain:  pb.Domain,
		UID:     pb.Openid,
		IDP:     pb.Idp,
		TOpenID: pb.TOpenid,
	}
	if pb.RawData != nil {
		id.RawData = *pb.RawData
	}
	if pb.CreatedAt != nil {
		id.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		id.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	return id
}

func credentialFromProto(pb *hermesv1.UserCredential) *models.UserCredential {
	if pb == nil {
		return nil
	}
	c := &models.UserCredential{
		ID:           uint(pb.Id),
		OpenID:       pb.Openid,
		CredentialID: pb.CredentialId,
		Type:         pb.Type,
		Enabled:      pb.Enabled,
		Secret:       pb.Secret,
	}
	if pb.LastUsedAt != nil {
		t := pb.LastUsedAt.AsTime()
		c.LastUsedAt = &t
	}
	if pb.CreatedAt != nil {
		c.CreatedAt = pb.CreatedAt.AsTime()
	}
	if pb.UpdatedAt != nil {
		c.UpdatedAt = pb.UpdatedAt.AsTime()
	}
	return c
}

func passwordStoreCredentialFromProto(pb *hermesv1.PasswordStoreCredential) *dto.PasswordStoreCredential {
	if pb == nil {
		return nil
	}
	cred := &dto.PasswordStoreCredential{
		OpenID:       pb.Openid,
		PasswordHash: pb.PasswordHash,
		Status:       safeInt8(pb.Status),
	}
	if pb.Nickname != nil {
		cred.Nickname = *pb.Nickname
	}
	if pb.Email != nil {
		cred.Email = *pb.Email
	}
	if pb.Picture != nil {
		cred.Picture = *pb.Picture
	}
	return cred
}

func marshalStringSlice(s []string) *string {
	if len(s) == 0 {
		return nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil
	}
	str := string(b)
	return &str
}

func toTimestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func safeInt8(v int32) int8 {
	if v > 127 {
		return 127
	}
	if v < -128 {
		return -128
	}
	return int8(v)
}

func safeInt32[T ~int | ~uint](v T) int32 {
	if v > T(math.MaxInt32) {
		return math.MaxInt32
	}
	return int32(v)
}

func safeUint32[T ~uint | ~int](v T) uint32 {
	if v > T(math.MaxUint32) {
		return math.MaxUint32
	}
	return uint32(v)
}

func setOptionalString(dst **string, src patch.Optional[string]) {
	if src.IsPresent() && !src.IsNull() {
		v := src.Value()
		*dst = &v
	}
}

func setOptionalUint32(dst **uint32, src patch.Optional[uint]) {
	if src.IsPresent() && !src.IsNull() {
		v := safeUint32(src.Value())
		*dst = &v
	}
}
