// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/secrets"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "notif.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	vault, err := secrets.NewVaultFromKey(make([]byte, secrets.KeySize))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	st.Vault = vault
	return st
}

func TestSchemaIdempotent(t *testing.T) {
	st := newTestStore(t)
	if _, err := NewSQLiteStore(st.db); err != nil {
		t.Fatalf("re-run schema should be a no-op: %v", err)
	}
}

func TestCreateGetRoundTrip(t *testing.T) {
	st := newTestStore(t)
	c, err := st.Create(emailInput(), "user-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.ID == "" || c.CreatedBy != "user-1" {
		t.Errorf("server fields not set: %+v", c)
	}
	got, err := st.Get(c.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Config.SMTPHost != "smtp.example.com" || got.Config.SMTPPort != 587 || len(got.Config.To) != 1 {
		t.Errorf("config not persisted: %+v", got.Config)
	}
	// Secret round-trips through the vault.
	if got.Secret.IsZero() {
		t.Fatal("secret not stored")
	}
	pt, err := OpenWith(st.Vault, got.Secret)
	if err != nil {
		t.Fatalf("open secret: %v", err)
	}
	if string(pt) != "hunter2" {
		t.Errorf("secret = %q, want hunter2", pt)
	}
}

func TestCreateRequiresSecretForSlack(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.Create(ChannelInput{Name: "s", Type: TypeSlack}, "u"); !errors.Is(err, ErrInvalid) {
		t.Errorf("slack without secret should be ErrInvalid, got %v", err)
	}
}

func TestCreateNoVaultWithSecret(t *testing.T) {
	st := newTestStore(t)
	st.Vault = nil
	if _, err := st.Create(emailInput(), "u"); !errors.Is(err, ErrInvalid) {
		t.Errorf("sealing without a vault should be ErrInvalid, got %v", err)
	}
}

func TestCreateRejectsInvalidAndNoUser(t *testing.T) {
	st := newTestStore(t)
	bad := emailInput()
	bad.Name = ""
	if _, err := st.Create(bad, "u"); !errors.Is(err, ErrInvalid) {
		t.Errorf("expected ErrInvalid, got %v", err)
	}
	if _, err := st.Create(emailInput(), ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty createdBy should be ErrInvalid, got %v", err)
	}
}

func TestGetNotFound(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdatePreservesSecretOnOmit(t *testing.T) {
	st := newTestStore(t)
	c, _ := st.Create(emailInput(), "u")
	in := emailInput()
	in.Secret = "" // omit → keep stored password
	in.Config.From = "new@x"
	updated, err := st.Update(c.ID, in)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Config.From != "new@x" {
		t.Errorf("config not updated: %+v", updated.Config)
	}
	pt, err := OpenWith(st.Vault, updated.Secret)
	if err != nil || string(pt) != "hunter2" {
		t.Errorf("secret not preserved: %q %v", pt, err)
	}
}

func TestUpdateReSealsNewSecret(t *testing.T) {
	st := newTestStore(t)
	c, _ := st.Create(emailInput(), "u")
	in := emailInput()
	in.Secret = "newpass"
	updated, _ := st.Update(c.ID, in)
	pt, _ := OpenWith(st.Vault, updated.Secret)
	if string(pt) != "newpass" {
		t.Errorf("secret not re-sealed: %q", pt)
	}
}

func TestUpdateTypeChangeClearsSecretAndRequiresNew(t *testing.T) {
	st := newTestStore(t)
	c, _ := st.Create(emailInput(), "u")
	// email → slack with no new secret: the old password must not be
	// reused as a Slack URL; the store rejects it.
	toSlack := ChannelInput{Name: "now slack", Type: TypeSlack}
	if _, err := st.Update(c.ID, toSlack); !errors.Is(err, ErrInvalid) {
		t.Errorf("type change to slack without secret should be ErrInvalid, got %v", err)
	}
	// With a fresh URL it succeeds and the old secret is gone.
	toSlack.Secret = "https://hooks.slack.com/services/abc"
	updated, err := st.Update(c.ID, toSlack)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	pt, _ := OpenWith(st.Vault, updated.Secret)
	if string(pt) != "https://hooks.slack.com/services/abc" {
		t.Errorf("secret not replaced: %q", pt)
	}
}

func TestUpdateMissing(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.Update("nope", emailInput()); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestListAndListEnabled(t *testing.T) {
	st := newTestStore(t)
	on := emailInput()
	on.Enabled = true
	off := emailInput()
	off.Name = "disabled"
	off.Enabled = false
	if _, err := st.Create(on, "u"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(off, "u"); err != nil {
		t.Fatal(err)
	}
	all, _ := st.List()
	if len(all) != 2 {
		t.Fatalf("List = %d, want 2", len(all))
	}
	en, _ := st.ListEnabled()
	if len(en) != 1 || !en[0].Enabled {
		t.Errorf("ListEnabled = %d, want 1 enabled", len(en))
	}
}

func TestDelete(t *testing.T) {
	st := newTestStore(t)
	c, _ := st.Create(emailInput(), "u")
	if err := st.Delete(c.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.Get(c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("channel should be gone, got %v", err)
	}
	if err := st.Delete(c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete should be ErrNotFound, got %v", err)
	}
}

func TestDeliveriesOrderLimitAndSurviveDelete(t *testing.T) {
	st := newTestStore(t)
	c, _ := st.Create(emailInput(), "u")
	base := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if _, err := st.RecordDelivery(Delivery{
			ChannelID: c.ID, ChannelName: c.Name, ChannelType: c.Type,
			Kind: "fired", RuleName: "r", SystemID: "sys", Status: DeliverySuccess,
			At: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.ListDeliveries(2)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("limit not applied: %d", len(got))
	}
	// Most recent first.
	if !got[0].At.After(got[1].At) {
		t.Errorf("not ordered newest-first: %v then %v", got[0].At, got[1].At)
	}
	// Deleting the channel keeps the denormalized delivery history.
	_ = st.Delete(c.ID)
	after, _ := st.ListDeliveries(0)
	if len(after) != 3 {
		t.Errorf("deliveries should survive channel delete, got %d", len(after))
	}
	if after[0].ChannelName != c.Name {
		t.Errorf("denormalized name lost: %+v", after[0])
	}
}

func TestRecordDeliveryFillsIDAndTime(t *testing.T) {
	st := newTestStore(t)
	d, err := st.RecordDelivery(Delivery{ChannelID: "c", ChannelName: "n", ChannelType: TypeWebhook, Kind: "fired", RuleName: "r", SystemID: "s", Status: DeliveryFailed, Error: "boom"})
	if err != nil {
		t.Fatal(err)
	}
	if d.ID == "" || d.At.IsZero() {
		t.Errorf("id/at not filled: %+v", d)
	}
}

// TestNewSQLiteStoreMigratesPreUserIDInstall guards the migration order:
// a pre-per-user database has notification_deliveries / notification_pending
// without a user_id column. NewSQLiteStore must add the column and build the
// user_id index afterward, not fail because the index in `schema` ran before
// the ALTER. Regression for "no such column: user_id" on restart.
func TestNewSQLiteStoreMigratesPreUserIDInstall(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "legacy.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Old-shape tables: no user_id column.
	for _, ddl := range []string{
		`CREATE TABLE notification_deliveries (
			id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, channel_name TEXT NOT NULL,
			channel_type TEXT NOT NULL, kind TEXT NOT NULL, rule_name TEXT NOT NULL,
			system_id TEXT NOT NULL, status TEXT NOT NULL, error TEXT, at INTEGER NOT NULL
		) STRICT;`,
		`CREATE TABLE notification_pending (
			id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, rule_name TEXT NOT NULL,
			system_id TEXT NOT NULL, severity TEXT NOT NULL, kind TEXT NOT NULL,
			message TEXT NOT NULL, enqueued_at INTEGER NOT NULL
		) STRICT;`,
	} {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("seed legacy schema: %v", err)
		}
	}

	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("NewSQLiteStore on legacy DB: %v", err)
	}

	// Idempotent: a second open (the steady-state restart) must also succeed.
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("NewSQLiteStore second pass: %v", err)
	}

	assertColumn := func(table string) {
		row := db.QueryRow(`SELECT 1 FROM pragma_table_info(?) WHERE name = 'user_id'`, table)
		var n int
		if err := row.Scan(&n); err != nil {
			t.Fatalf("%s missing user_id after migration: %v", table, err)
		}
	}
	assertColumn("notification_deliveries")
	assertColumn("notification_pending")

	row := db.QueryRow(
		`SELECT 1 FROM sqlite_master WHERE type='index' AND name='notification_deliveries_user'`)
	var n int
	if err := row.Scan(&n); err != nil {
		t.Fatalf("user_id index not created: %v", err)
	}
}
