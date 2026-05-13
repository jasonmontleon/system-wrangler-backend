// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// RegisterTOTP wires the protected TOTP/device endpoints onto mux. Mirrors
// the pattern used by RegisterProtected: the caller supplies the same
// requireUser middleware so we never reach inside this package for it.
func (s *Service) RegisterTOTP(mux *http.ServeMux, requireUser func(http.Handler) http.Handler) {
	mux.HandleFunc("POST /api/auth/totp/verify", s.handleTOTPVerify)
	mux.Handle("POST /api/auth/totp/setup", requireUser(http.HandlerFunc(s.handleTOTPSetup)))
	mux.Handle("POST /api/auth/totp/confirm", requireUser(http.HandlerFunc(s.handleTOTPConfirm)))
	mux.Handle("DELETE /api/auth/totp", requireUser(http.HandlerFunc(s.handleTOTPDisable)))
	mux.Handle("GET /api/auth/devices", requireUser(http.HandlerFunc(s.handleListDevices)))
	mux.Handle("DELETE /api/auth/devices/{id}", requireUser(http.HandlerFunc(s.handleRevokeDevice)))
}

type totpSetupResponse struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	QRPng  string `json:"qrPng"` // base64-encoded PNG for inline <img src="data:..."> use
}

func (s *Service) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	u, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !s.totpReady() {
		writeError(w, http.StatusServiceUnavailable, "totp not configured")
		return
	}
	secret, uri, qr, err := GenerateTOTPSecret(u.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp setup failed")
		slog.Error("totp setup generate", "err", err, "user_id", u.ID)
		return
	}
	sealed, err := SealWith(s.Vault, secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp setup failed")
		slog.Error("totp setup seal", "err", err, "user_id", u.ID)
		return
	}
	if err := s.TOTPStore.SetPendingSecret(u.ID, sealed); err != nil {
		writeError(w, http.StatusInternalServerError, "totp setup failed")
		slog.Error("totp setup persist", "err", err, "user_id", u.ID)
		return
	}
	resp := totpSetupResponse{
		Secret: totpEncoding.EncodeToString(secret),
		URI:    uri,
		QRPng:  base64.StdEncoding.EncodeToString(qr),
	}
	writeJSON(w, http.StatusOK, resp)
}

type totpConfirmRequest struct {
	Code string `json:"code"`
}

type totpConfirmResponse struct {
	RecoveryCodes []string `json:"recoveryCodes"`
}

func (s *Service) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	u, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !s.totpReady() {
		writeError(w, http.StatusServiceUnavailable, "totp not configured")
		return
	}
	var req totpConfirmRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	code := strings.TrimSpace(req.Code)
	if code == "" {
		writeError(w, http.StatusBadRequest, "code required")
		return
	}
	state, err := s.TOTPStore.GetTOTPState(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp confirm failed")
		slog.Error("totp confirm state", "err", err, "user_id", u.ID)
		return
	}
	if state.Pending.IsZero() {
		writeError(w, http.StatusBadRequest, "no pending enrollment; call /totp/setup first")
		return
	}
	secret, err := OpenWith(s.Vault, state.Pending)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp confirm failed")
		slog.Error("totp confirm decrypt", "err", err, "user_id", u.ID)
		return
	}
	if _, err := VerifyTOTPCode(secret, code, s.Now(), 0); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	codes, err := GenerateRecoveryCodes(RecoveryCodeCount)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "totp confirm failed")
		slog.Error("totp confirm recovery gen", "err", err, "user_id", u.ID)
		return
	}
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		h, err := HashRecoveryCode(c)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "totp confirm failed")
			slog.Error("totp confirm recovery hash", "err", err, "user_id", u.ID)
			return
		}
		hashes = append(hashes, h)
	}
	if err := s.TOTPStore.ActivateTOTP(u.ID, state.Pending, s.Now()); err != nil {
		writeError(w, http.StatusInternalServerError, "totp confirm failed")
		slog.Error("totp confirm activate", "err", err, "user_id", u.ID)
		return
	}
	if err := s.RecoveryStore.InsertRecoveryCodes(u.ID, hashes); err != nil {
		writeError(w, http.StatusInternalServerError, "totp confirm failed")
		slog.Error("totp confirm recovery insert", "err", err, "user_id", u.ID)
		return
	}
	writeJSON(w, http.StatusOK, totpConfirmResponse{RecoveryCodes: codes})
}

type totpVerifyRequest struct {
	Code           string `json:"code"`
	RememberDevice bool   `json:"rememberDevice"`
}

func (s *Service) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	if !s.totpReady() {
		writeError(w, http.StatusServiceUnavailable, "totp not configured")
		return
	}
	c, err := r.Cookie(TOTPChallengeCookie)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "no challenge")
		return
	}
	claims, err := VerifyToken(s.Secret, s.Now(), PurposeTOTPChallenge, c.Value)
	if err != nil {
		s.clearChallengeCookie(w)
		writeError(w, http.StatusUnauthorized, "challenge invalid")
		return
	}
	var req totpVerifyRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	code := strings.TrimSpace(req.Code)
	if code == "" {
		writeError(w, http.StatusBadRequest, "code required")
		return
	}
	u, err := s.Store.GetByID(claims.UID)
	if err != nil {
		s.clearChallengeCookie(w)
		writeError(w, http.StatusUnauthorized, "challenge invalid")
		return
	}
	if u.Disabled {
		s.clearChallengeCookie(w)
		writeError(w, http.StatusUnauthorized, "challenge invalid")
		return
	}
	state, err := s.TOTPStore.GetTOTPState(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verify failed")
		slog.Error("totp verify state", "err", err, "user_id", u.ID)
		return
	}
	if !state.Enabled || state.Secret.IsZero() {
		s.clearChallengeCookie(w)
		writeError(w, http.StatusUnauthorized, "challenge invalid")
		return
	}
	verified, viaRecovery := s.tryVerifyCode(u.ID, state, code)
	if !verified {
		// Don't clear the challenge cookie on a wrong code — let the user
		// retry within the 5-min window. Failure to verify on a *valid*
		// challenge is a normal user mistake, not a poisoned cookie.
		writeError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	s.clearChallengeCookie(w)
	if req.RememberDevice && s.DeviceStore != nil {
		if err := s.rememberDevice(w, r, u.ID, state.Epoch); err != nil {
			// Failure to persist trust is non-fatal — log and proceed with
			// the session cookie. Better to log the user in than to error
			// out because the trust persistence had a transient hiccup.
			slog.Warn("totp verify remember device", "err", err, "user_id", u.ID)
		}
	}
	if err := s.issueCookie(w, u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "session failed")
		slog.Error("totp verify cookie", "err", err, "user_id", u.ID)
		return
	}
	if viaRecovery {
		slog.Info("recovery_code_consumed", "user_id", u.ID)
	}
	writeJSON(w, http.StatusOK, u)
}

// tryVerifyCode attempts TOTP first then recovery-code fallback. Returns
// (verified, viaRecovery). On success the matching credential has already
// been consumed (step bumped or row marked used).
func (s *Service) tryVerifyCode(userID string, state TOTPState, code string) (bool, bool) {
	secret, err := OpenWith(s.Vault, state.Secret)
	if err == nil {
		step, err := VerifyTOTPCode(secret, code, s.Now(), state.LastStep)
		if err == nil {
			if err := s.TOTPStore.ConsumeStep(userID, step); err == nil {
				return true, false
			}
		}
	}
	// Fall back to recovery code if TOTP didn't match.
	if s.RecoveryStore == nil {
		return false, false
	}
	if err := s.RecoveryStore.ConsumeRecoveryCode(userID, code, s.Now()); err == nil {
		return true, true
	}
	return false, false
}

// rememberDevice persists a trusted-device row and writes the cookie.
func (s *Service) rememberDevice(w http.ResponseWriter, r *http.Request, userID string, epoch int64) error {
	id := s.NewID()
	now := s.Now()
	d := TrustedDevice{
		ID:         id,
		UserID:     userID,
		Label:      LabelFromUserAgent(r.UserAgent()),
		CreatedAt:  now,
		LastUsedAt: now,
		ExpiresAt:  now.Add(TrustedDeviceTTL),
		TOTPEpoch:  epoch,
	}
	if err := s.DeviceStore.InsertDevice(d); err != nil {
		return err
	}
	return s.issueTrustedDeviceCookie(w, id, userID, epoch)
}

type totpDisableRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (s *Service) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	u, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !s.totpReady() {
		writeError(w, http.StatusServiceUnavailable, "totp not configured")
		return
	}
	var req totpDisableRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Password == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "password and code required")
		return
	}
	hash, err := s.Store.GetHashByID(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "disable failed")
		slog.Error("totp disable hash", "err", err, "user_id", u.ID)
		return
	}
	if err := VerifyPassword(hash, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	state, err := s.TOTPStore.GetTOTPState(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "disable failed")
		slog.Error("totp disable state", "err", err, "user_id", u.ID)
		return
	}
	if !state.Enabled || state.Secret.IsZero() {
		writeError(w, http.StatusBadRequest, "totp not enabled")
		return
	}
	secret, err := OpenWith(s.Vault, state.Secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "disable failed")
		slog.Error("totp disable decrypt", "err", err, "user_id", u.ID)
		return
	}
	if _, err := VerifyTOTPCode(secret, strings.TrimSpace(req.Code), s.Now(), state.LastStep); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	if err := s.TOTPStore.DisableTOTP(u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "disable failed")
		slog.Error("totp disable persist", "err", err, "user_id", u.ID)
		return
	}
	// The DB has wiped trusted-device rows; clear the cookie too so this
	// browser doesn't carry a stale value.
	s.clearTrustedDeviceCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleListDevices(w http.ResponseWriter, r *http.Request) {
	u, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.DeviceStore == nil {
		writeJSON(w, http.StatusOK, []TrustedDevice{})
		return
	}
	devices, err := s.DeviceStore.ListDevices(u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("list devices", "err", err, "user_id", u.ID)
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (s *Service) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	u, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.DeviceStore == nil {
		writeError(w, http.StatusServiceUnavailable, "devices not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "device id required")
		return
	}
	if err := s.DeviceStore.DeleteDevice(id, u.ID); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "device not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "revoke failed")
		slog.Error("revoke device", //nolint:gosec // structured kv pairs are not log injectable
			"err", err, "user_id", u.ID, "device_id", id)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// totpReady reports whether the Service has the dependencies needed to run
// the TOTP path: a TOTP store, a recovery store, and a Vault. Without any
// of these we return 503 rather than panic on a nil deref.
func (s *Service) totpReady() bool {
	return s.TOTPStore != nil && s.RecoveryStore != nil && s.Vault != nil
}
