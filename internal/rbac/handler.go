// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/auth"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/router"
)

// UserLookup is the slice of auth.UserStore the handler needs. Kept
// narrow so tests can stub it without implementing the full UserStore
// surface; auth.SQLiteAuthStore satisfies it.
type UserLookup interface {
	GetByID(id string) (auth.User, error)
}

// GroupLookup is the slice of groups.Store the handler needs. Lookups
// confirm the target group exists before a grant and recover the name
// for response hydration; groups.SQLiteStore satisfies it.
type GroupLookup interface {
	Get(id string) (groups.Group, error)
}

// Handler exposes the role-assignments endpoints described in
// research/rbac.md. Two surfaces:
//
//   - /api/groups/{id}/role-assignments — group-scoped. Visible to
//     anyone who can read the group; mutable by Global Admin (any
//     role) and Group Admin of that group (Operator/Auditor only).
//   - /api/admin/role-assignments — install-wide. Global Admin only;
//     used by the user-detail Roles panel and to assign global roles.
//
// Every mutation emits a role.grant or role.revoke audit row with
// target_kind=user, target_id=userId, and a detail payload carrying
// group_id (or null) and role.
type Handler struct {
	Store  Store
	Users  UserLookup
	Groups GroupLookup
	Audit  *audit.Store
}

// NewHandler binds a Handler to the supplied dependencies.
func NewHandler(store Store, users UserLookup, gs GroupLookup) *Handler {
	return &Handler{Store: store, Users: users, Groups: gs}
}

// Register attaches the role-assignment routes to mux. mw must be the
// same auth + scope-resolving middleware applied to the rest of the
// protected API; the handlers read both User and Scope off the
// request context.
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/groups/{id}/role-assignments", mw(http.HandlerFunc(h.listGroup)))
	mux.Handle("POST /api/groups/{id}/role-assignments", mw(http.HandlerFunc(h.grantGroup)))
	mux.Handle("DELETE /api/groups/{id}/role-assignments/{userId}/{role}", mw(http.HandlerFunc(h.revokeGroup)))
	mux.Handle("GET /api/admin/role-assignments", mw(http.HandlerFunc(h.listAdmin)))
	mux.Handle("POST /api/admin/role-assignments", mw(http.HandlerFunc(h.grantAdmin)))
	mux.Handle("DELETE /api/admin/role-assignments", mw(http.HandlerFunc(h.revokeAdmin)))
	mux.Handle("GET /api/me/scope", mw(http.HandlerFunc(h.myScope)))
}

// scopeDTO is the response shape of GET /api/me/scope. Used by the
// frontend to decide which controls to render: only Global Admin gets
// the unrestricted picker, Group Admin gets a picker without the
// "Admin" choice, Group Operator/Auditor sees the table read-only.
type scopeDTO struct {
	Global Role            `json:"global,omitempty"`
	Groups map[string]Role `json:"groups"`
}

func (h *Handler) myScope(w http.ResponseWriter, r *http.Request) {
	scope, ok := ScopeFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "scope missing")
		return
	}
	dto := scopeDTO{Global: scope.Global, Groups: map[string]Role{}}
	for _, gid := range scope.VisibleGroupIDs() {
		dto.Groups[gid] = scope.RoleOnGroup(gid)
	}
	writeJSON(w, http.StatusOK, dto)
}

// roleAssignmentDTO is the response shape returned to the frontend.
// It hydrates the bare (user_id, group_id, role) tuple with the
// frozen-at-response-time username and group name so the table
// renders without a second round-trip per row. GroupID is the JSON
// `null` for global-scope rows.
type roleAssignmentDTO struct {
	UserID    string  `json:"userId"`
	Username  string  `json:"username"`
	GroupID   *string `json:"groupId"`
	GroupName string  `json:"groupName,omitempty"`
	Role      Role    `json:"role"`
}

func (h *Handler) listGroup(w http.ResponseWriter, r *http.Request) {
	scope, ok := ScopeFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "scope missing")
		return
	}
	groupID := r.PathValue("id")
	if !scope.CanReadGroup(groupID) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	g, err := h.Groups.Get(groupID)
	if err != nil {
		if errors.Is(err, groups.ErrNotFound) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup failed")
		slog.Error("rbac list group lookup", "err", err)
		return
	}
	rows, err := h.Store.ListByGroup(groupID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("rbac list group", "err", err)
		return
	}
	out := make([]roleAssignmentDTO, 0, len(rows))
	for _, a := range rows {
		out = append(out, h.hydrate(a, g.Name))
	}
	writeJSON(w, http.StatusOK, map[string]any{"assignments": out})
}

func (h *Handler) grantGroup(w http.ResponseWriter, r *http.Request) {
	scope, ok := ScopeFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "scope missing")
		return
	}
	groupID := r.PathValue("id")
	var body struct {
		UserID string `json:"userId"`
		Role   Role   `json:"role"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if !body.Role.IsValid() {
		writeError(w, http.StatusBadRequest, "unknown role")
		return
	}
	if body.UserID == "" {
		writeError(w, http.StatusBadRequest, "userId required")
		return
	}
	if !scope.CanGrantOnGroup(groupID, body.Role) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	g, err := h.Groups.Get(groupID)
	if err != nil {
		if errors.Is(err, groups.ErrNotFound) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "group lookup failed")
		slog.Error("rbac grant group lookup", "err", err)
		return
	}
	u, err := h.Users.GetByID(body.UserID)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "user lookup failed")
		slog.Error("rbac grant group user lookup", "err", err)
		return
	}
	gid := groupID
	assignment := Assignment{UserID: body.UserID, GroupID: &gid, Role: body.Role}
	if err := h.Store.Grant(assignment); err != nil {
		switch {
		case errors.Is(err, ErrDuplicate):
			writeError(w, http.StatusConflict, "assignment already exists")
		case errors.Is(err, ErrInvalid):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "grant failed")
			slog.Error("rbac grant group", "err", err)
		}
		return
	}
	h.logGrant(r.Context(), u, &g, body.Role)
	writeJSON(w, http.StatusCreated, h.hydrate(assignment, g.Name))
}

func (h *Handler) revokeGroup(w http.ResponseWriter, r *http.Request) {
	scope, ok := ScopeFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "scope missing")
		return
	}
	groupID := r.PathValue("id")
	userID := r.PathValue("userId")
	role := Role(r.PathValue("role"))
	if !role.IsValid() {
		writeError(w, http.StatusBadRequest, "unknown role")
		return
	}
	if !scope.CanGrantOnGroup(groupID, role) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	g, gErr := h.Groups.Get(groupID)
	u, uErr := h.Users.GetByID(userID)
	gid := groupID
	if err := h.Store.Revoke(Assignment{UserID: userID, GroupID: &gid, Role: role}); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "assignment not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "revoke failed")
		slog.Error("rbac revoke group", "err", err)
		return
	}
	var gp *groups.Group
	if gErr == nil {
		gp = &g
	}
	if uErr == nil {
		h.logRevoke(r.Context(), u, gp, role)
	} else {
		// User row already gone (e.g. cascade-delete race). Log the
		// revoke against the bare userID so the audit trail still
		// records the action.
		h.logRevoke(r.Context(), auth.User{ID: userID}, gp, role)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listAdmin(w http.ResponseWriter, r *http.Request) {
	scope, ok := ScopeFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "scope missing")
		return
	}
	if !scope.IsGlobalAdmin() {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	rows, err := h.Store.ListAll()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		slog.Error("rbac list admin", "err", err)
		return
	}
	// Cache user / group name lookups so a user with many rows or a
	// group with many members doesn't fan out N×M queries.
	users := map[string]string{}
	groupNames := map[string]string{}
	out := make([]roleAssignmentDTO, 0, len(rows))
	for _, a := range rows {
		if _, seen := users[a.UserID]; !seen {
			if u, err := h.Users.GetByID(a.UserID); err == nil {
				users[a.UserID] = u.Username
			} else {
				users[a.UserID] = ""
			}
		}
		groupName := ""
		if a.GroupID != nil {
			if cached, seen := groupNames[*a.GroupID]; seen {
				groupName = cached
			} else {
				if gg, err := h.Groups.Get(*a.GroupID); err == nil {
					groupName = gg.Name
				}
				groupNames[*a.GroupID] = groupName
			}
		}
		out = append(out, roleAssignmentDTO{
			UserID:    a.UserID,
			Username:  users[a.UserID],
			GroupID:   a.GroupID,
			GroupName: groupName,
			Role:      a.Role,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"assignments": out})
}

// adminBody is the shape of both POST and DELETE /api/admin/role-assignments.
// GroupID is a pointer so the JSON `null` distinguishes "global" from
// "this group ID is the empty string" — the latter is rejected.
type adminBody struct {
	UserID  string  `json:"userId"`
	GroupID *string `json:"groupId"`
	Role    Role    `json:"role"`
}

func (h *Handler) grantAdmin(w http.ResponseWriter, r *http.Request) {
	scope, ok := ScopeFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "scope missing")
		return
	}
	if !scope.IsGlobalAdmin() {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var body adminBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if !body.Role.IsValid() {
		writeError(w, http.StatusBadRequest, "unknown role")
		return
	}
	if body.UserID == "" {
		writeError(w, http.StatusBadRequest, "userId required")
		return
	}
	if body.GroupID != nil && *body.GroupID == "" {
		writeError(w, http.StatusBadRequest, "groupId must be omitted or non-empty")
		return
	}
	u, err := h.Users.GetByID(body.UserID)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "user lookup failed")
		slog.Error("rbac grant admin user lookup", "err", err)
		return
	}
	var gp *groups.Group
	if body.GroupID != nil {
		g, err := h.Groups.Get(*body.GroupID)
		if err != nil {
			if errors.Is(err, groups.ErrNotFound) {
				writeError(w, http.StatusNotFound, "group not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "group lookup failed")
			slog.Error("rbac grant admin group lookup", "err", err)
			return
		}
		gp = &g
	}
	a := Assignment(body)
	if err := h.Store.Grant(a); err != nil {
		switch {
		case errors.Is(err, ErrDuplicate):
			writeError(w, http.StatusConflict, "assignment already exists")
		case errors.Is(err, ErrInvalid):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "grant failed")
			slog.Error("rbac grant admin", "err", err)
		}
		return
	}
	h.logGrant(r.Context(), u, gp, body.Role)
	dto := roleAssignmentDTO{
		UserID:   body.UserID,
		Username: u.Username,
		GroupID:  body.GroupID,
		Role:     body.Role,
	}
	if gp != nil {
		dto.GroupName = gp.Name
	}
	writeJSON(w, http.StatusCreated, dto)
}

func (h *Handler) revokeAdmin(w http.ResponseWriter, r *http.Request) {
	scope, ok := ScopeFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "scope missing")
		return
	}
	if !scope.IsGlobalAdmin() {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	var body adminBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if !body.Role.IsValid() {
		writeError(w, http.StatusBadRequest, "unknown role")
		return
	}
	if body.UserID == "" {
		writeError(w, http.StatusBadRequest, "userId required")
		return
	}
	if body.GroupID != nil && *body.GroupID == "" {
		writeError(w, http.StatusBadRequest, "groupId must be omitted or non-empty")
		return
	}
	u, uErr := h.Users.GetByID(body.UserID)
	var gp *groups.Group
	if body.GroupID != nil {
		if g, err := h.Groups.Get(*body.GroupID); err == nil {
			gp = &g
		}
	}
	if err := h.Store.Revoke(Assignment(body)); err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusNotFound, "assignment not found")
		case errors.Is(err, ErrLastGlobalAdmin):
			writeError(w, http.StatusConflict, "cannot remove the last global admin; promote another user first")
		default:
			writeError(w, http.StatusInternalServerError, "revoke failed")
			slog.Error("rbac revoke admin", "err", err)
		}
		return
	}
	if uErr != nil {
		u = auth.User{ID: body.UserID}
	}
	h.logRevoke(r.Context(), u, gp, body.Role)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) hydrate(a Assignment, fallbackGroupName string) roleAssignmentDTO {
	dto := roleAssignmentDTO{
		UserID:  a.UserID,
		GroupID: a.GroupID,
		Role:    a.Role,
	}
	if u, err := h.Users.GetByID(a.UserID); err == nil {
		dto.Username = u.Username
	}
	if a.GroupID != nil {
		dto.GroupName = fallbackGroupName
	}
	return dto
}

// logGrant writes a role.grant audit row. user.Username is the
// frozen-at-log-time label; group.Name carries the same for the
// detail. Group is optional (nil for global grants).
func (h *Handler) logGrant(ctx context.Context, u auth.User, g *groups.Group, role Role) {
	h.logRoleEvent(ctx, "role.grant", u, g, role)
}

func (h *Handler) logRevoke(ctx context.Context, u auth.User, g *groups.Group, role Role) {
	h.logRoleEvent(ctx, "role.revoke", u, g, role)
}

func (h *Handler) logRoleEvent(ctx context.Context, action string, u auth.User, g *groups.Group, role Role) {
	if h.Audit == nil {
		return
	}
	detail := audit.Detail{"role": string(role)}
	if g != nil {
		detail["group_id"] = g.ID
		detail["group_name"] = g.Name
	} else {
		detail["group_id"] = nil
	}
	if err := h.Audit.Log(ctx, audit.Event{
		Action:      action,
		Outcome:     audit.Success,
		TargetKind:  "user",
		TargetID:    u.ID,
		TargetLabel: u.Username,
		Detail:      detail,
	}); err != nil {
		slog.Error("rbac audit log", "err", err, "action", action)
	}
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("rbac json encode", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
