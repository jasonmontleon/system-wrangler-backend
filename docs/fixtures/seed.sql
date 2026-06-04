-- SPDX-License-Identifier: Apache-2.0
--
-- Deterministic demo dataset for documentation screenshots.
-- Loaded by docs/fixtures/docs-serve.sh into a scratch SQLite whose schema
-- the server already created. Pure INSERTs — no schema here (avoids drift).
--
-- Timestamp units differ by table: audit_log.occurred_at is UnixMilli,
-- every other timestamp column is UnixNano. The anchor "now" is
-- 2026-06-03 18:00:00 UTC; relative times are expressed as offsets so the
-- data reads sensibly and regenerates identically.
--
-- Demo login: docs / docsdemo1  (Global Admin). All seeded users share that
-- password (same bcrypt hash) — demo only.

PRAGMA foreign_keys = ON;
BEGIN;

-- ---------------------------------------------------------------------------
-- Runtime-neutering settings (see docs-screenshots plan): a high probe
-- interval + max failure threshold means a seeded "reachable" host won't flip
-- for ~10h; a high alert-eval interval means one evaluation at startup.
-- ---------------------------------------------------------------------------
INSERT INTO system_settings (key, value) VALUES
  ('probe_interval_seconds',     '3600'),
  ('probe_failure_threshold',    '10'),
  ('probe_success_threshold',    '10'),
  ('alert_eval_interval_seconds','3600');

-- ---------------------------------------------------------------------------
-- Groups
-- ---------------------------------------------------------------------------
INSERT INTO system_groups (id, name, created_at) VALUES
  ('grp-web',  'Web Tier',      CAST(strftime('%s','2026-05-01 09:00:00') AS INTEGER)*1000000000),
  ('grp-db',   'Database Tier', CAST(strftime('%s','2026-05-01 09:01:00') AS INTEGER)*1000000000),
  ('grp-edge', 'Edge / Branch', CAST(strftime('%s','2026-05-01 09:02:00') AS INTEGER)*1000000000);

-- ---------------------------------------------------------------------------
-- Hosts — varied OS / virt / status / reboot. status ∈ reachable |
-- unreachable | unprobed. created_at staggered so List() order is stable;
-- last_seen recent for reachable, stale for unreachable, NULL for unprobed.
-- ---------------------------------------------------------------------------
INSERT INTO hosts
  (id, name, hostname, created_at, status, last_seen, group_id, is_windows,
   os_family, os_distribution, virtualization, reboot_required_at,
   consecutive_failures, consecutive_successes)
VALUES
  ('sys-web-01','web-01','web-01.corp.example',
     CAST(strftime('%s','2026-05-01 10:00:00') AS INTEGER)*1000000000,'reachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-90)*1000000000,'grp-web',0,
     'Debian','Ubuntu 24.04 LTS','kvm',NULL,0,1),
  ('sys-web-02','web-02','web-02.corp.example',
     CAST(strftime('%s','2026-05-01 10:01:00') AS INTEGER)*1000000000,'reachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-75)*1000000000,'grp-web',0,
     'Debian','Ubuntu 24.04 LTS','kvm',NULL,0,1),
  ('sys-web-03','web-03','web-03.corp.example',
     CAST(strftime('%s','2026-05-01 10:02:00') AS INTEGER)*1000000000,'reachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-60)*1000000000,'grp-web',0,
     'Debian','Debian 12','bare-metal',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-86400)*1000000000,0,1),
  ('sys-cache-01','cache-01','cache-01.corp.example',
     CAST(strftime('%s','2026-05-01 10:03:00') AS INTEGER)*1000000000,'reachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-50)*1000000000,'grp-web',0,
     'Alpine','Alpine 3.20','lxc',NULL,0,1),
  ('sys-db-01','db-01','db-01.corp.example',
     CAST(strftime('%s','2026-05-01 10:04:00') AS INTEGER)*1000000000,'reachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-110)*1000000000,'grp-db',0,
     'RedHat','Fedora 40','kvm',NULL,0,1),
  ('sys-db-02','db-02','db-02.corp.example',
     CAST(strftime('%s','2026-05-01 10:05:00') AS INTEGER)*1000000000,'reachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-95)*1000000000,'grp-db',0,
     'RedHat','Fedora 40','kvm',NULL,0,1),
  ('sys-bsd-01','bsd-01','bsd-01.corp.example',
     CAST(strftime('%s','2026-05-01 10:06:00') AS INTEGER)*1000000000,'reachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-130)*1000000000,'grp-db',0,
     'FreeBSD','FreeBSD 14.0','bare-metal',NULL,0,1),
  ('sys-mac-01','mac-build','mac-build.corp.example',
     CAST(strftime('%s','2026-05-01 10:07:00') AS INTEGER)*1000000000,'reachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-200)*1000000000,NULL,0,
     'Darwin','macOS 14 Sonoma','none',NULL,0,1),
  ('sys-win-01','win-01','win-01.corp.example',
     CAST(strftime('%s','2026-05-01 10:08:00') AS INTEGER)*1000000000,'reachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-140)*1000000000,'grp-db',1,
     'Windows','Windows Server 2022','hyperv',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-43200)*1000000000,0,1),
  ('sys-edge-fra-01','edge-fra-01','edge-fra-01.corp.example',
     CAST(strftime('%s','2026-05-01 10:09:00') AS INTEGER)*1000000000,'reachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-180)*1000000000,'grp-edge',0,
     'OpenWrt','OpenWrt 23.05','bare-metal',NULL,0,1),
  ('sys-edge-nyc-01','edge-nyc-01','edge-nyc-01.corp.example',
     CAST(strftime('%s','2026-05-01 10:10:00') AS INTEGER)*1000000000,'reachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-160)*1000000000,'grp-edge',0,
     'Alpine','Alpine 3.20','none',NULL,0,1),
  ('sys-edge-syd-01','edge-syd-01','edge-syd-01.corp.example',
     CAST(strftime('%s','2026-05-01 10:11:00') AS INTEGER)*1000000000,'unreachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-172800)*1000000000,'grp-edge',0,
     'OpenBSD','OpenBSD 7.5','bare-metal',NULL,10,0),
  ('sys-win-02','win-02','win-02.corp.example',
     CAST(strftime('%s','2026-05-01 10:12:00') AS INTEGER)*1000000000,'unreachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-90000)*1000000000,'grp-db',1,
     'Windows','Windows Server 2019','vmware',NULL,10,0),
  ('sys-db-03','db-03','db-03.corp.example',
     CAST(strftime('%s','2026-05-01 10:13:00') AS INTEGER)*1000000000,'unreachable',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-126000)*1000000000,'grp-db',0,
     'Debian','Debian 12','kvm',NULL,10,0),
  ('sys-app-07','app-07','app-07.corp.example',
     CAST(strftime('%s','2026-06-03 17:40:00') AS INTEGER)*1000000000,'unprobed',
     NULL,'grp-web',0,'','','',NULL,0,0),
  ('sys-app-08','app-08','app-08.corp.example',
     CAST(strftime('%s','2026-06-03 17:42:00') AS INTEGER)*1000000000,'unprobed',
     NULL,NULL,0,'','','',NULL,0,0);

-- ---------------------------------------------------------------------------
-- Labels (N:M key=value)
-- ---------------------------------------------------------------------------
INSERT INTO system_labels (system_id, key, value) VALUES
  ('sys-web-01','env','prod'),   ('sys-web-01','role','web'),   ('sys-web-01','team','platform'),
  ('sys-web-02','env','prod'),   ('sys-web-02','role','web'),   ('sys-web-02','team','platform'),
  ('sys-web-03','env','staging'),('sys-web-03','role','web'),
  ('sys-cache-01','env','prod'), ('sys-cache-01','role','cache'),
  ('sys-db-01','env','prod'),    ('sys-db-01','role','db'),     ('sys-db-01','team','data'),
  ('sys-db-02','env','prod'),    ('sys-db-02','role','db'),     ('sys-db-02','team','data'),
  ('sys-bsd-01','env','prod'),   ('sys-bsd-01','role','db'),
  ('sys-win-01','env','prod'),   ('sys-win-01','role','db'),    ('sys-win-01','team','data'),
  ('sys-edge-fra-01','env','prod'),('sys-edge-fra-01','role','edge'),('sys-edge-fra-01','site','fra'),
  ('sys-edge-nyc-01','env','prod'),('sys-edge-nyc-01','role','edge'),('sys-edge-nyc-01','site','nyc'),
  ('sys-edge-syd-01','env','prod'),('sys-edge-syd-01','role','edge'),('sys-edge-syd-01','site','syd'),
  ('sys-mac-01','env','ci'),     ('sys-mac-01','role','build');

INSERT INTO label_styles (key, color) VALUES
  ('env','red'),
  ('role','purple'),
  ('site','blue'),
  ('team','green');

-- ---------------------------------------------------------------------------
-- Users + RBAC. docs = Global Admin (login). Others show the roles matrix.
-- password_hash is bcrypt of "docsdemo1".
-- ---------------------------------------------------------------------------
INSERT INTO users (id, username, password_hash, email, theme, created_at) VALUES
  ('usr-docs', 'docs',  '$2a$10$ayhXshTjn6msjLA6logntOv2O41FzxUTU.STax.X.908OFH.kUD2e','docs@corp.example','', CAST(strftime('%s','2026-05-01 08:00:00') AS INTEGER)*1000000000),
  ('usr-opal', 'opal',  '$2a$10$ayhXshTjn6msjLA6logntOv2O41FzxUTU.STax.X.908OFH.kUD2e','opal@corp.example','', CAST(strftime('%s','2026-05-02 08:00:00') AS INTEGER)*1000000000),
  ('usr-audra','audra', '$2a$10$ayhXshTjn6msjLA6logntOv2O41FzxUTU.STax.X.908OFH.kUD2e','audra@corp.example','',CAST(strftime('%s','2026-05-03 08:00:00') AS INTEGER)*1000000000),
  ('usr-gail', 'gail',  '$2a$10$ayhXshTjn6msjLA6logntOv2O41FzxUTU.STax.X.908OFH.kUD2e','gail@corp.example','', CAST(strftime('%s','2026-05-04 08:00:00') AS INTEGER)*1000000000),
  ('usr-glenn','glenn', '$2a$10$ayhXshTjn6msjLA6logntOv2O41FzxUTU.STax.X.908OFH.kUD2e','glenn@corp.example','',CAST(strftime('%s','2026-05-05 08:00:00') AS INTEGER)*1000000000);

-- group_id NULL = a global role; a group id = a per-group role.
INSERT INTO user_roles (user_id, group_id, role) VALUES
  ('usr-docs', NULL,      'admin'),
  ('usr-opal', NULL,      'operator'),
  ('usr-audra',NULL,      'auditor'),
  ('usr-gail', 'grp-web', 'admin'),
  ('usr-glenn','grp-db',  'operator');

-- ---------------------------------------------------------------------------
-- Alert rules. The unreachable rule fires at the startup evaluation (the
-- three unreachable hosts breach) and populates /api/alerts/active. It is
-- routed to no channels (selected mode, empty set) so the startup fire makes
-- no outbound calls. The metric rules can't fire without Prometheus (the
-- query errors and the rule is skipped) — they fire once metrics are wired.
-- ---------------------------------------------------------------------------
INSERT INTO alert_rules
  (id, name, description, condition_kind, metric, expr, comparator, threshold,
   for_seconds, severity, target_kind, target_value, enabled, created_by, created_at, updated_at)
VALUES
  ('alr-unreach','Host unreachable','Fires when a system stops answering the reachability probe.',
     'unreachable','','','',0,0,'critical','global','',1,'usr-docs',
     CAST(strftime('%s','2026-05-10 12:00:00') AS INTEGER)*1000000000,
     CAST(strftime('%s','2026-05-10 12:00:00') AS INTEGER)*1000000000),
  ('alr-mem','High memory usage','Memory utilisation above 85%.',
     'metric','mem_used_pct','','gt',85,300,'warning','global','',1,'usr-docs',
     CAST(strftime('%s','2026-05-10 12:05:00') AS INTEGER)*1000000000,
     CAST(strftime('%s','2026-05-10 12:05:00') AS INTEGER)*1000000000),
  ('alr-disk','Disk almost full','Any filesystem above 90% used.',
     'metric','fs_used_pct','','gt',90,300,'critical','global','',1,'usr-docs',
     CAST(strftime('%s','2026-05-10 12:10:00') AS INTEGER)*1000000000,
     CAST(strftime('%s','2026-05-10 12:10:00') AS INTEGER)*1000000000),
  ('alr-cpu','Web tier CPU saturated','Sustained CPU above 90% on the web tier.',
     'metric','cpu_busy_pct','','gt',90,600,'warning','group','grp-web',1,'usr-gail',
     CAST(strftime('%s','2026-05-11 09:00:00') AS INTEGER)*1000000000,
     CAST(strftime('%s','2026-05-11 09:00:00') AS INTEGER)*1000000000),
  ('alr-promql','TCP connections (custom)','Raw PromQL example; disabled.',
     'promql','','sum by (system_id) (node_netstat_Tcp_CurrEstab) > 5000','gt',5000,300,'info','global','',0,'usr-docs',
     CAST(strftime('%s','2026-05-12 14:00:00') AS INTEGER)*1000000000,
     CAST(strftime('%s','2026-05-12 14:00:00') AS INTEGER)*1000000000);

-- Route the unreachable rule to no channels (selected mode, no members).
INSERT INTO alert_rule_routing (rule_id, mode) VALUES ('alr-unreach','selected');

-- ---------------------------------------------------------------------------
-- Notification channels (no secrets needed for display) + a delivery log.
-- ---------------------------------------------------------------------------
INSERT INTO notification_channels
  (id, name, type, enabled, config, secret_ciphertext, secret_nonce, secret_version, created_by, created_at, updated_at)
VALUES
  ('chn-webhook','Ops Webhook','webhook',1,
     '{"url":"https://hooks.example.com/ops","method":"POST"}',NULL,NULL,NULL,'usr-docs',
     CAST(strftime('%s','2026-05-13 10:00:00') AS INTEGER)*1000000000,
     CAST(strftime('%s','2026-05-13 10:00:00') AS INTEGER)*1000000000),
  ('chn-email','Email — NOC','email',1,
     '{"smtpHost":"smtp.example.com","smtpPort":587,"from":"alerts@corp.example","to":["noc@corp.example"],"startTLS":true}',NULL,NULL,NULL,'usr-docs',
     CAST(strftime('%s','2026-05-13 10:05:00') AS INTEGER)*1000000000,
     CAST(strftime('%s','2026-05-13 10:05:00') AS INTEGER)*1000000000),
  ('chn-slack','Slack #alerts','slack',0,
     '{}',NULL,NULL,NULL,'usr-docs',
     CAST(strftime('%s','2026-05-13 10:10:00') AS INTEGER)*1000000000,
     CAST(strftime('%s','2026-05-13 10:10:00') AS INTEGER)*1000000000);

INSERT INTO notification_deliveries
  (id, channel_id, channel_name, channel_type, kind, rule_name, system_id, status, error, at, user_id)
VALUES
  ('dlv-1','chn-webhook','Ops Webhook','webhook','fired','Host unreachable','sys-db-03','success',NULL,
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-126000)*1000000000,''),
  ('dlv-2','chn-email','Email — NOC','email','fired','Host unreachable','sys-win-02','success',NULL,
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-90000)*1000000000,''),
  ('dlv-3','chn-webhook','Ops Webhook','webhook','fired','Disk almost full','sys-db-01','success',NULL,
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-7200)*1000000000,''),
  ('dlv-4','chn-email','Email — NOC','email','fired','Disk almost full','sys-db-01','failed','smtp: connection timed out',
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-7200)*1000000000,''),
  ('dlv-5','chn-webhook','Ops Webhook','webhook','resolved','Disk almost full','sys-db-01','success',NULL,
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-3600)*1000000000,''),
  ('dlv-6','','','webhook','fired','High memory usage','sys-web-01','suppressed',NULL,
     (CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-1800)*1000000000,'');

-- ---------------------------------------------------------------------------
-- Schedules — authored not-due (next_run far ahead), with a prior run for the
-- "last run" columns. The schedule ticker won't fire any during a session.
-- ---------------------------------------------------------------------------
INSERT INTO schedules
  (id, name, cron_expr, timezone, run_check, run_apply, reboot_after_apply,
   target_kind, target_value, enabled, next_run_at, last_run_at, last_status, created_by, created_at, updated_at)
VALUES
  ('sch-nightly','Nightly check — all systems','0 3 * * *','America/New_York',1,0,0,
     'global','',1,
     (CAST(strftime('%s','2026-06-04 07:00:00') AS INTEGER))*1000000000,
     (CAST(strftime('%s','2026-06-03 07:00:00') AS INTEGER))*1000000000,'success','usr-docs',
     CAST(strftime('%s','2026-05-14 11:00:00') AS INTEGER)*1000000000,
     CAST(strftime('%s','2026-05-14 11:00:00') AS INTEGER)*1000000000),
  ('sch-web-patch','Weekly patch — Web Tier','0 4 * * 0','America/New_York',1,1,1,
     'group','grp-web',1,
     (CAST(strftime('%s','2026-06-08 08:00:00') AS INTEGER))*1000000000,
     (CAST(strftime('%s','2026-06-01 08:00:00') AS INTEGER))*1000000000,'success','usr-gail',
     CAST(strftime('%s','2026-05-14 11:05:00') AS INTEGER)*1000000000,
     CAST(strftime('%s','2026-05-14 11:05:00') AS INTEGER)*1000000000),
  ('sch-db-patch','Monthly patch — Database Tier','0 5 1 * *','America/New_York',1,1,0,
     'group','grp-db',0,
     NULL,
     (CAST(strftime('%s','2026-05-01 09:00:00') AS INTEGER))*1000000000,'failed','usr-docs',
     CAST(strftime('%s','2026-05-14 11:10:00') AS INTEGER)*1000000000,
     CAST(strftime('%s','2026-05-14 11:10:00') AS INTEGER)*1000000000);

-- ---------------------------------------------------------------------------
-- Package exclusions (global + group + system scope)
-- ---------------------------------------------------------------------------
INSERT INTO package_exclusions (id, scope, target_id, updater, pattern, reason, created_at, created_by) VALUES
  ('exc-1','global','',         'dnf','kernel*',  'Kernels are rolled by the platform team.', CAST(strftime('%s','2026-05-15 10:00:00') AS INTEGER)*1000000000,'usr-docs'),
  ('exc-2','global','',         'apt','linux-image-*','Pin kernel image on Debian/Ubuntu.',   CAST(strftime('%s','2026-05-15 10:01:00') AS INTEGER)*1000000000,'usr-docs'),
  ('exc-3','group', 'grp-db',   'dnf','postgresql*','DB upgrades are coordinated manually.',  CAST(strftime('%s','2026-05-15 10:02:00') AS INTEGER)*1000000000,'usr-glenn'),
  ('exc-4','system','sys-web-01','apt','nginx',   'Pinned to the vendor build on web-01.',    CAST(strftime('%s','2026-05-15 10:03:00') AS INTEGER)*1000000000,'usr-gail');

-- ---------------------------------------------------------------------------
-- Audit log (occurred_at is UnixMilli). A mix of logins, system + config
-- changes, and an update apply.
-- ---------------------------------------------------------------------------
INSERT INTO audit_log
  (id, occurred_at, actor_kind, actor_id, actor_label, action, target_kind, target_id, target_label, outcome, detail, request_ip, request_id)
VALUES
  ('aud-01',(CAST(strftime('%s','2026-06-03 09:02:00') AS INTEGER))*1000,'user','usr-docs','docs','user.login',NULL,NULL,NULL,'success',NULL,'10.0.0.5','req-01'),
  ('aud-02',(CAST(strftime('%s','2026-06-03 09:15:00') AS INTEGER))*1000,'user','usr-docs','docs','system.create','system','sys-app-07','app-07','success',NULL,'10.0.0.5','req-02'),
  ('aud-03',(CAST(strftime('%s','2026-06-03 09:16:00') AS INTEGER))*1000,'user','usr-docs','docs','system.create','system','sys-app-08','app-08','success',NULL,'10.0.0.5','req-03'),
  ('aud-04',(CAST(strftime('%s','2026-06-03 10:30:00') AS INTEGER))*1000,'user','usr-gail','gail','updater.apply','system','sys-web-01','web-01','success','{"updater":"apt","packages":12}','10.0.0.8','req-04'),
  ('aud-05',(CAST(strftime('%s','2026-06-03 10:31:00') AS INTEGER))*1000,'user','usr-gail','gail','updater.apply','system','sys-web-02','web-02','success','{"updater":"apt","packages":12}','10.0.0.8','req-05'),
  ('aud-06',(CAST(strftime('%s','2026-06-03 11:05:00') AS INTEGER))*1000,'user','usr-glenn','glenn','exclusion.create','exclusion','exc-3','postgresql*','success',NULL,'10.0.0.9','req-06'),
  ('aud-07',(CAST(strftime('%s','2026-06-03 11:40:00') AS INTEGER))*1000,'user','usr-opal','opal','user.login',NULL,NULL,NULL,'failure','{"reason":"bad password"}','10.0.0.7','req-07'),
  ('aud-08',(CAST(strftime('%s','2026-06-03 11:41:00') AS INTEGER))*1000,'user','usr-opal','opal','user.login',NULL,NULL,NULL,'success',NULL,'10.0.0.7','req-08'),
  ('aud-09',(CAST(strftime('%s','2026-06-03 12:00:00') AS INTEGER))*1000,'user','usr-docs','docs','alert_rule.create','alert_rule','alr-cpu','Web tier CPU saturated','success',NULL,'10.0.0.5','req-09'),
  ('aud-10',(CAST(strftime('%s','2026-06-03 13:20:00') AS INTEGER))*1000,'user','usr-docs','docs','notification_channel.create','notification_channel','chn-webhook','Ops Webhook','success',NULL,'10.0.0.5','req-10'),
  ('aud-11',(CAST(strftime('%s','2026-06-03 14:10:00') AS INTEGER))*1000,'user','usr-gail','gail','schedule.create','schedule','sch-web-patch','Weekly patch — Web Tier','success',NULL,'10.0.0.8','req-11'),
  ('aud-12',(CAST(strftime('%s','2026-06-03 16:45:00') AS INTEGER))*1000,'user','usr-docs','docs','setting.set','setting','probe_interval_seconds','probe_interval_seconds','success','{"value_before":"30","value_after":"3600"}','10.0.0.5','req-12');

-- ---------------------------------------------------------------------------
-- Updater availability (drives Inventory "Updates" + "Last checked") and a
-- little run history (the System detail → Updaters tab). last_seen_at is the
-- last check time; pending_packages is the JSON the check produced.
-- ---------------------------------------------------------------------------
INSERT INTO system_updaters (system_id, updater_id, last_seen_at, enabled, pending_packages) VALUES
  ('sys-web-01','builtin.apt',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-7200)*1000000000,1,
     '[{"name":"openssl","oldVersion":"3.0.13-0ubuntu3.4","newVersion":"3.0.13-0ubuntu3.5"},{"name":"libc6","oldVersion":"2.39-0ubuntu8.2","newVersion":"2.39-0ubuntu8.3"},{"name":"curl","oldVersion":"8.5.0-2ubuntu10.5","newVersion":"8.5.0-2ubuntu10.6"}]'),
  ('sys-web-02','builtin.apt',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-7000)*1000000000,1,'[]'),
  ('sys-web-03','builtin.apt',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-9000)*1000000000,1,
     '[{"name":"linux-image-amd64","oldVersion":"6.1.0-21","newVersion":"6.1.0-22"}]'),
  ('sys-cache-01','builtin.apk',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-3600)*1000000000,1,
     '[{"name":"musl","oldVersion":"1.2.5-r0","newVersion":"1.2.5-r1"}]'),
  ('sys-db-01','builtin.dnf',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-10800)*1000000000,1,
     '[{"name":"postgresql-server","oldVersion":"16.2-1.fc40","newVersion":"16.3-1.fc40"},{"name":"kernel","oldVersion":"6.8.9-300.fc40","newVersion":"6.8.11-300.fc40"},{"name":"systemd","oldVersion":"255.6-1.fc40","newVersion":"255.7-1.fc40"},{"name":"openssl","oldVersion":"3.2.1-2.fc40","newVersion":"3.2.2-1.fc40"},{"name":"glibc","oldVersion":"2.39-13.fc40","newVersion":"2.39-17.fc40"}]'),
  ('sys-db-02','builtin.dnf',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-11000)*1000000000,1,'[]'),
  ('sys-bsd-01','builtin.pkg',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-18000)*1000000000,1,
     '[{"name":"nginx","oldVersion":"1.26.0","newVersion":"1.26.1"},{"name":"python311","oldVersion":"3.11.9","newVersion":"3.11.10"}]'),
  ('sys-mac-01','builtin.brew',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-21600)*1000000000,1,'[]'),
  ('sys-win-01','builtin.winget',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-14400)*1000000000,1,
     '[{"name":"Microsoft.PowerShell","oldVersion":"7.4.2","newVersion":"7.4.3"},{"name":"Git.Git","oldVersion":"2.45.1","newVersion":"2.45.2"},{"name":"Mozilla.Firefox","oldVersion":"126.0","newVersion":"127.0"},{"name":"7zip.7zip","oldVersion":"23.01","newVersion":"24.05"}]'),
  ('sys-edge-nyc-01','builtin.apk',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-5400)*1000000000,1,'[]');

-- One "check" run per availability host sets its Last-checked time; the
-- pending count comes from system_updaters above. Plus a web-01 apply and a
-- failed win-02 check for variety in the run history.
INSERT INTO updater_runs
  (id, system_id, updater_id, kind, started_at, finished_at, exit_code, affected_count, actor_id, playbook_sha, log_tail)
VALUES
  ('run-web01-c','sys-web-01','builtin.apt','check',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-7200)*1000000000,(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-7188)*1000000000,0,3,'usr-gail','a1b2c3d','3 packages can be upgraded.'),
  ('run-web01-a','sys-web-01','builtin.apt','apply',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-27000)*1000000000,(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-26940)*1000000000,0,12,'usr-gail','a1b2c3d','12 upgraded, 0 newly installed.'),
  ('run-web02-c','sys-web-02','builtin.apt','check',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-7000)*1000000000,(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-6988)*1000000000,0,0,'usr-gail','a1b2c3d','0 packages can be upgraded.'),
  ('run-web03-c','sys-web-03','builtin.apt','check',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-9000)*1000000000,(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-8985)*1000000000,0,1,'usr-gail','a1b2c3d','1 package can be upgraded.'),
  ('run-cache-c','sys-cache-01','builtin.apk','check',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-3600)*1000000000,(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-3592)*1000000000,0,1,'usr-gail','b2c3d4e','1 package can be upgraded.'),
  ('run-db01-c','sys-db-01','builtin.dnf','check',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-10800)*1000000000,(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-10780)*1000000000,0,5,'usr-docs','e4f5a6b','5 packages available for update.'),
  ('run-db02-c','sys-db-02','builtin.dnf','check',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-11000)*1000000000,(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-10980)*1000000000,0,0,'usr-docs','e4f5a6b','0 packages available for update.'),
  ('run-bsd-c','sys-bsd-01','builtin.pkg','check',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-18000)*1000000000,(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-17985)*1000000000,0,2,'usr-docs','f5a6b7c','2 packages available for update.'),
  ('run-mac-c','sys-mac-01','builtin.brew','check',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-21600)*1000000000,(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-21580)*1000000000,0,0,'usr-docs','a6b7c8d','0 outdated formulae.'),
  ('run-win01-c','sys-win-01','builtin.winget','check',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-14400)*1000000000,(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-14370)*1000000000,0,4,'usr-docs','c7d8e9f','4 upgrades available.'),
  ('run-edge-c','sys-edge-nyc-01','builtin.apk','check',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-5400)*1000000000,(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-5392)*1000000000,0,0,'usr-glenn','b2c3d4e','0 packages can be upgraded.'),
  ('run-win02-c','sys-win-02','builtin.winget','check',(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-90000)*1000000000,(CAST(strftime('%s','2026-06-03 18:00:00') AS INTEGER)-89970)*1000000000,1,0,'usr-docs','c7d8e9f','connection to host failed.');

-- ---------------------------------------------------------------------------
-- Personal notification preferences for the demo user (docs) so the Profile
-- page shows populated channels / subscription / quiet-hours instead of the
-- empty state. Config JSON matches the notifications package shapes.
-- ---------------------------------------------------------------------------
INSERT INTO user_notification_channels
  (id, user_id, name, type, enabled, config, secret_ciphertext, secret_nonce, secret_version, created_by, created_at, updated_at)
VALUES
  ('ucn-docs-email','usr-docs','My Email','email',1,
     '{"smtpHost":"smtp.example.com","smtpPort":587,"from":"alerts@corp.example","to":["docs@corp.example"],"startTLS":true}',NULL,NULL,NULL,'usr-docs',
     CAST(strftime('%s','2026-05-20 09:00:00') AS INTEGER)*1000000000,
     CAST(strftime('%s','2026-05-20 09:00:00') AS INTEGER)*1000000000),
  ('ucn-docs-hook','usr-docs','My Pager Webhook','webhook',1,
     '{"url":"https://hooks.example.com/docs","method":"POST"}',NULL,NULL,NULL,'usr-docs',
     CAST(strftime('%s','2026-05-20 09:05:00') AS INTEGER)*1000000000,
     CAST(strftime('%s','2026-05-20 09:05:00') AS INTEGER)*1000000000);

-- Subscribe docs to Database Tier criticals only.
INSERT INTO user_alert_subscription (user_id, config) VALUES
  ('usr-docs','{"enabled":true,"groups":["grp-db"],"severities":["critical"]}');

-- Personal policy: weekends fully quiet + weeknights 22:00–08:00; info to the
-- dashboard, warnings deferred in quiet hours, criticals always page.
INSERT INTO user_notification_policy (user_id, config) VALUES
  ('usr-docs','{"timezone":"America/New_York","windows":[{"days":[0,6],"start":"00:00","end":"24:00"},{"days":[1,2,3,4,5],"start":"22:00","end":"08:00"}],"severities":{"info":"dashboard","warning":"quiet","critical":"always"}}');

COMMIT;
