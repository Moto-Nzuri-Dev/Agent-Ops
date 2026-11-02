const express = require("express");
const helmet = require("helmet");
const compression = require("compression");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const pino = require("pino");
const pinoHttp = require("pino-http");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const log = pino({ level: process.env.LOG_LEVEL || "info" });
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PATH = process.env.ADMIN_PATH || "/ops-7f3a9c-control";
const DRIVER_PATH = process.env.DRIVER_PATH || "/driver";
const REPRESENTATIVE_PATH = process.env.REPRESENTATIVE_PATH || "/representative";
const TECHNICIAN_PATH = process.env.TECHNICIAN_PATH || "/technician";
const CUSTOMER_CARE_PATH = process.env.CUSTOMER_CARE_PATH || "/customer-care";
const MAX_MB = Number(process.env.MAX_PHOTO_MB || 5);
const RATE_LIMIT = Number(process.env.RATE_LIMIT_PER_MINUTE || 60);

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY || !process.env.SUPABASE_PUBLISHABLE_KEY) {
  log.warn("Supabase environment variables are incomplete");
}

const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});
const supabasePublic = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_PUBLISHABLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"], baseUri: ["'self'"], formAction: ["'self'"], frameAncestors: ["'self'"],
      objectSrc: ["'none'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'", "blob:", "data:"],
      connectSrc: ["'self'"], fontSrc: ["'self'"], mediaSrc: ["'self'"], workerSrc: ["'self'", "blob:"]
    }
  },
  crossOriginResourcePolicy: { policy: "same-origin" }
}));
app.use(compression());
app.use(express.json({ limit: `${Math.max(8, MAX_MB * 2)}mb` }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));
app.use(pinoHttp({
  logger: log,
  genReqId: req => req.headers["x-request-id"] || crypto.randomUUID(),
  redact: ["req.headers.authorization", "req.headers.cookie", "req.body.password", "req.body.data"]
}));

const rateBuckets = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of rateBuckets) if (now - value.start > 120000) rateBuckets.delete(key);
}, 60000).unref();
app.use("/api", (req, res, next) => {
  const ip = req.ip || "unknown", now = Date.now();
  let item = rateBuckets.get(ip);
  if (!item || now - item.start > 60000) item = { start: now, count: 0 };
  item.count += 1; rateBuckets.set(ip, item);
  if (item.count > RATE_LIMIT) return res.status(429).json({ ok: false, error: "Too many requests. Try again later." });
  next();
});

const publicDir = path.join(__dirname, "public");
const masterSeedPath = path.join(__dirname, "data", "mn-master-seed.json");
let masterSeed = [];
try { masterSeed = JSON.parse(fs.readFileSync(masterSeedPath, "utf8")); } catch (error) { log.warn({ err: error }, "Master seed file could not be loaded"); }
app.use(express.static(publicDir, { etag: true, setHeaders: (res, filePath) => {
  if (filePath.endsWith(".html") || /[\\/]admin\.(js|css)$/.test(filePath) || /[\\/]driver\.(js|css)$/.test(filePath) || /[\\/]representative\.(js|css)$/.test(filePath)) {
    res.setHeader("Cache-Control", "no-store, max-age=0");
  } else {
    res.setHeader("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400");
  }
}}));
app.get(ADMIN_PATH, (req, res) => { res.setHeader("Cache-Control", "no-store"); res.sendFile(path.join(publicDir, "admin.html")); });
app.get(DRIVER_PATH, (req, res) => { res.setHeader("Cache-Control", "no-store"); res.sendFile(path.join(publicDir, "driver.html")); });
app.get(REPRESENTATIVE_PATH, (req, res) => { res.setHeader("Cache-Control", "no-store"); res.sendFile(path.join(publicDir, "representative.html")); });
app.get(TECHNICIAN_PATH, (req, res) => { res.setHeader("Cache-Control", "no-store"); res.sendFile(path.join(publicDir, "technician.html")); });
app.get(CUSTOMER_CARE_PATH, (req, res) => { res.setHeader("Cache-Control", "no-store"); res.sendFile(path.join(publicDir, "customer-care.html")); });

function deviceInfo(req) {
  const ua = req.get("user-agent") || "", ip = req.ip || null;
  return { user_agent: ua.slice(0, 1000), ip, ip_hash: crypto.createHash("sha256").update(`${ip || ""}${process.env.SUPABASE_SECRET_KEY || ""}`).digest("hex") };
}
async function getUser(req) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const { data, error } = await supabasePublic.auth.getUser(token);
  return error || !data.user ? null : data.user;
}
async function requireAdmin(req, res, next) {
  try {
    const user = await getUser(req); if (!user) return res.status(401).json({ error: "Unauthorized" });
    const { data: allow, error } = await supabaseAdmin.from("admin_allowlist").select("user_id,email").eq("user_id", user.id).maybeSingle();
    if (!allow || error) return res.status(403).json({ error: "Forbidden" });
    const { data: authRecord } = await supabaseAdmin.auth.admin.getUserById(user.id);
    const bannedUntil = authRecord?.user?.banned_until ? Date.parse(authRecord.user.banned_until) : 0;
    if (bannedUntil && bannedUntil > Date.now()) return res.status(403).json({ error: "Administrator account is disabled" });
    req.user = user; return next();
  } catch (error) { req.log.error({ err: error }, "admin auth error"); return res.status(401).json({ error: "Unauthorized" }); }
}
async function requireCustomerCare(req, res, next) {
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    const { data: admin } = await supabaseAdmin.from("admin_allowlist").select("user_id").eq("user_id", user.id).maybeSingle();
    if (admin) { req.user = user; req.customerCare = { user_id: user.id, full_name: user.email, role: "Administrator" }; return next(); }
    const { data: profile, error } = await supabaseAdmin.from("customer_care_profiles").select("*").eq("user_id", user.id).eq("active", true).maybeSingle();
    if (error || !profile) return res.status(403).json({ error: "This account is not an active customer care account." });
    req.user = user; req.customerCare = profile; return next();
  } catch (error) { req.log.error({ err: error }, "customer care auth error"); return res.status(401).json({ error: "Unauthorized" }); }
}

async function requireDriver(req, res, next) {
  try {
    const user = await getUser(req); if (!user) return res.status(401).json({ error: "Unauthorized" });
    const { data: driver, error } = await supabaseAdmin.from("driver_profiles").select("*").eq("user_id", user.id).eq("active", true).maybeSingle();
    if (error || !driver) return res.status(403).json({ error: "Driver account is not active" });
    req.user = user; req.driver = driver; return next();
  } catch (error) { req.log.error({ err: error }, "driver auth error"); return res.status(401).json({ error: "Unauthorized" }); }
}

async function requireRepresentative(req, res, next) {
  try {
    const user = await getUser(req); if (!user) return res.status(401).json({ error: "Unauthorized" });
    const { data: profile, error } = await supabaseAdmin.from("agent_representative_profiles").select("*").eq("user_id", user.id).eq("active", true).maybeSingle();
    if (error || !profile) return res.status(403).json({ error: "Representative account is not active" });
    req.user = user; req.representative = profile; return next();
  } catch (error) { req.log.error({ err: error }, "representative auth error"); return res.status(401).json({ error: "Unauthorized" }); }
}

async function requireTechnician(req, res, next) {
  try {
    const user = await getUser(req); if (!user) return res.status(401).json({ error: "Unauthorized" });
    const { data: profile, error } = await supabaseAdmin.from("technician_profiles").select("*").eq("user_id", user.id).eq("active", true).maybeSingle();
    if (error || !profile) return res.status(403).json({ error: "Technician account is not active" });
    req.user = user; req.technician = profile; return next();
  } catch (error) { req.log.error({ err: error }, "technician auth error"); return res.status(401).json({ error: "Unauthorized" }); }
}

async function writeSecurity(event_type, req, user_id, metadata = {}) {
  const d = deviceInfo(req);
  await supabaseAdmin.from("security_events").insert({ event_type, user_id, ip: d.ip, ip_hash: d.ip_hash, user_agent: d.user_agent, metadata });
}

// Phase 2: in-app notifications. Notification delivery is best-effort; operational writes must still succeed.
async function createNotification(recipient_id, title, body, related_type = null, related_id = null) {
  if (!recipient_id) return;
  const { error } = await supabaseAdmin.from("ops_notifications").insert({
    recipient_id, title: String(title || "Moto Nzuri update").slice(0, 160),
    body: String(body || "").slice(0, 1000), related_type, related_id
  });
  if (error) log.warn({ err: error, recipient_id, related_type }, "Could not create in-app notification");
}
async function notifyAdmins(title, body, related_type = null, related_id = null) {
  const { data, error } = await supabaseAdmin.from("admin_allowlist").select("user_id");
  if (error) { log.warn({ err: error }, "Could not load administrators for notification"); return; }
  await Promise.all((data || []).map(x => createNotification(x.user_id, title, body, related_type, related_id)));
}

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== "string" || typeof password !== "string") return res.status(400).json({ error: "Invalid credentials" });
  const { data, error } = await supabasePublic.auth.signInWithPassword({ email, password });
  if (error || !data.session) { await writeSecurity("admin_login_failed", req, null, { email: String(email).slice(0, 180) }); return res.status(401).json({ error: "Invalid credentials" }); }
  const { data: allow } = await supabaseAdmin.from("admin_allowlist").select("user_id").eq("user_id", data.user.id).maybeSingle();
  if (!allow) return res.status(403).json({ error: "Account is not authorized for operations" });
  await writeSecurity("admin_login", req, data.user.id);
  res.json({ access_token: data.session.access_token, user: { id: data.user.id, email: data.user.email } });
});

app.post("/api/customer-care/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== "string" || typeof password !== "string") return res.status(400).json({ error: "Enter your email and password." });
  const { data, error } = await supabasePublic.auth.signInWithPassword({ email, password });
  if (error || !data.session) { await writeSecurity("customer_care_login_failed", req, null, { email: String(email).slice(0,180) }); return res.status(401).json({ error: "Invalid email or password." }); }
  const { data: admin } = await supabaseAdmin.from("admin_allowlist").select("user_id").eq("user_id", data.user.id).maybeSingle();
  const { data: profile } = await supabaseAdmin.from("customer_care_profiles").select("user_id,full_name,email,active").eq("user_id", data.user.id).eq("active", true).maybeSingle();
  if (!admin && !profile) return res.status(403).json({ error: "Your account is not authorized for the Customer Care portal." });
  await writeSecurity("customer_care_login", req, data.user.id);
  res.json({ access_token: data.session.access_token, user: { id: data.user.id, email: data.user.email }, profile: profile || { full_name: data.user.email, role: "Administrator" } });
});

app.post("/api/driver/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== "string" || typeof password !== "string") return res.status(400).json({ error: "Invalid credentials" });
  const { data, error } = await supabasePublic.auth.signInWithPassword({ email, password });
  if (error || !data.session) { await writeSecurity("driver_login_failed", req, null, { email: String(email).slice(0, 180) }); return res.status(401).json({ error: "Invalid credentials" }); }
  const { data: driver } = await supabaseAdmin.from("driver_profiles").select("*").eq("user_id", data.user.id).eq("active", true).maybeSingle();
  if (!driver) return res.status(403).json({ error: "This account is not an active driver account" });
  await writeSecurity("driver_login", req, data.user.id);
  res.json({ access_token: data.session.access_token, user: { id: data.user.id, email: data.user.email }, driver });
});

app.post("/api/representative/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== "string" || typeof password !== "string") return res.status(400).json({ error: "Invalid credentials" });
  const { data, error } = await supabasePublic.auth.signInWithPassword({ email, password });
  if (error || !data.session) { await writeSecurity("representative_login_failed", req, null, { email: String(email).slice(0, 180) }); return res.status(401).json({ error: "Invalid credentials" }); }
  const { data: profile } = await supabaseAdmin.from("agent_representative_profiles").select("*").eq("user_id", data.user.id).eq("active", true).maybeSingle();
  if (!profile) return res.status(403).json({ error: "This account is not an active agent representative account" });
  await writeSecurity("representative_login", req, data.user.id);
  res.json({ access_token: data.session.access_token, user: { id: data.user.id, email: data.user.email }, representative: profile });
});

app.get("/api/representative/me", requireRepresentative, (req, res) => res.json({ representative: req.representative, email: req.user.email }));
app.get("/api/representative/submissions", requireRepresentative, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("agent_representative_submissions").select("*").eq("representative_id", req.user.id).order("created_at", { ascending: false }).limit(10000);
  if (error) return res.status(400).json({ error: error.message }); res.json({ data: data || [] });
});
app.get("/api/representative/shops", requireRepresentative, async (req, res) => {
  const q = String(req.query.q || "").trim().slice(0, 120).toLowerCase();
  const { data, error } = await supabaseAdmin.from("agent_representative_submissions").select("*").order("created_at", { ascending: false }).limit(10000);
  if (error) return res.status(400).json({ error: error.message });
  const submissions = data || [];
  const latestBySeed = new Map();
  for (const row of submissions) if (row.master_seed_no && !latestBySeed.has(String(row.master_seed_no))) latestBySeed.set(String(row.master_seed_no), row);
  const seeded = masterSeed.map(seed => {
    const updated = latestBySeed.get(String(seed.master_seed_no));
    const base = updated ? { ...seed, ...updated, id: updated.id, master_seed_no: seed.master_seed_no, seed_record: true, source: "daily_planning_seed", master_status: seed.master_status } : seed;
    return { ...base, can_edit: !!updated && updated.representative_id === req.user.id, is_seed_master: true };
  });
  const linkedIds = new Set([...latestBySeed.values()].map(x => String(x.id)));
  const standalone = submissions.filter(x => !x.master_seed_no && !linkedIds.has(String(x.id))).map(x => ({ ...x, source: "representative_submission", seed_record: false, is_seed_master: false, master_status: x.is_selling ? "Selling" : "Not selling", can_edit: x.representative_id === req.user.id }));
  let merged = [...seeded, ...standalone];
  if (q) merged = merged.filter(x => [x.shop_name,x.location,x.kp_number,x.till_number,x.account_mn_number,x.bank_account,x.agent_name,x.mpesa_number,x.representative_email,x.latitude,x.longitude,x.master_status,...Object.values(x.master_data || {})].some(v => String(v ?? "").toLowerCase().includes(q)));
  await writeSecurity("master_directory_view", req, req.user.id, { query: q || null, result_count: merged.length });
  res.json({ data: merged });
});
// Phase 1: visit history and follow-ups. Server-side writes use the Supabase service role.
async function recordRepresentativeVisit(req, submission, action) {
  const payload = {
    submission_id: submission.id,
    representative_id: req.user.id,
    representative_email: req.user.email,
    action,
    shop_name: submission.shop_name,
    location: submission.location,
    kp_number: submission.kp_number || null,
    master_seed_no: submission.master_seed_no || null,
    is_selling: !!submission.is_selling,
    is_branded: !!submission.is_branded,
    has_network: !!submission.has_network,
    has_paybill: !!submission.has_paybill,
    latitude: submission.latitude,
    longitude: submission.longitude,
    visit_notes: action === "created" ? "Initial shop checklist submitted" : "Shop checklist/status updated"
  };
  const { error } = await supabaseAdmin.from("representative_shop_visits").insert(payload);
  if (error) req.log.warn({ err: error, submission_id: submission.id }, "Could not record representative shop visit");
}
app.get("/api/representative/visits", requireRepresentative, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("representative_shop_visits").select("*").eq("representative_id", req.user.id).order("visited_at", { ascending: false }).limit(1000);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ data: data || [] });
});
app.get("/api/representative/followups", requireRepresentative, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("representative_shop_followups").select("*").eq("representative_id", req.user.id).order("due_date", { ascending: true, nullsFirst: false }).order("created_at", { ascending: false }).limit(1000);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ data: data || [] });
});
app.post("/api/representative/followups", requireRepresentative, async (req, res) => {
  const b = req.body || {};
  const shop_name = String(b.shop_name || "").trim().slice(0, 120);
  const location = String(b.location || "").trim().slice(0, 120);
  const followup_type = String(b.followup_type || "").trim();
  const notes = String(b.notes || "").trim().slice(0, 2000);
  const due_date = b.due_date ? String(b.due_date).slice(0, 10) : null;
  const priority = String(b.priority || "Normal");
  const allowedTypes = ["Revisit shop", "Machine not selling", "Machine needed", "Network issue", "Payment / Paybill issue", "Shop information verification", "Customer complaint", "Other"];
  if (shop_name.length < 2 || location.length < 2) return res.status(400).json({ error: "Shop name and location are required." });
  if (!allowedTypes.includes(followup_type)) return res.status(400).json({ error: "Select a valid follow-up type." });
  if (! ["Low", "Normal", "High", "Urgent"].includes(priority)) return res.status(400).json({ error: "Select a valid priority." });
  if (due_date && !/^\d{4}-\d{2}-\d{2}$/.test(due_date)) return res.status(400).json({ error: "Enter a valid due date." });
  const submission_id = b.submission_id ? String(b.submission_id) : null;
  if (submission_id) {
    const { data: owned, error: ownErr } = await supabaseAdmin.from("agent_representative_submissions").select("id").eq("id", submission_id).eq("representative_id", req.user.id).maybeSingle();
    if (ownErr) return res.status(400).json({ error: ownErr.message });
    if (!owned) return res.status(403).json({ error: "You can only link follow-ups to submissions from your account." });
  }
  const { data, error } = await supabaseAdmin.from("representative_shop_followups").insert({
    representative_id: req.user.id, representative_email: req.user.email, submission_id,
    master_seed_no: String(b.master_seed_no || "").trim() || null, shop_name, location,
    followup_type, priority, notes: notes || null, due_date, status: "Open"
  }).select().single();
  if (error) return res.status(400).json({ error: error.message });
  await writeSecurity("representative_followup_created", req, req.user.id, { followup_id: data.id, shop_name, followup_type, due_date });
  res.status(201).json({ data });
});
app.patch("/api/representative/followups/:id", requireRepresentative, async (req, res) => {
  const b = req.body || {};
  const allowedStatuses = ["Open", "In Progress", "Completed", "Cancelled"];
  const status = String(b.status || "");
  if (!allowedStatuses.includes(status)) return res.status(400).json({ error: "Select a valid follow-up status." });
  const patch = { status, updated_at: new Date().toISOString() };
  if (b.resolution_notes !== undefined) patch.resolution_notes = String(b.resolution_notes || "").trim().slice(0, 2000) || null;
  if (status === "Completed") patch.completed_at = new Date().toISOString();
  else patch.completed_at = null;
  const { data, error } = await supabaseAdmin.from("representative_shop_followups").update(patch).eq("id", req.params.id).eq("representative_id", req.user.id).select().maybeSingle();
  if (error) return res.status(400).json({ error: error.message });
  if (!data) return res.status(404).json({ error: "Follow-up not found under your account." });
  await writeSecurity("representative_followup_updated", req, req.user.id, { followup_id: data.id, status });
  res.json({ data });
});

// Phase 2: notifications are always scoped to the signed-in user.
app.get("/api/representative/notifications", requireRepresentative, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("ops_notifications").select("*").eq("recipient_id", req.user.id).order("created_at", { ascending: false }).limit(100);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ data: data || [] });
});
app.patch("/api/representative/notifications/:id/read", requireRepresentative, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("ops_notifications").update({ read_at: new Date().toISOString() }).eq("id", req.params.id).eq("recipient_id", req.user.id).select("id,read_at").maybeSingle();
  if (error) return res.status(400).json({ error: error.message });
  if (!data) return res.status(404).json({ error: "Notification not found." });
  res.json({ data });
});
app.post("/api/representative/tickets", requireRepresentative, async (req, res) => {
  const b = req.body || {};
  const shop_name = String(b.shop_name || "").trim().slice(0, 120);
  const location = String(b.location || "").trim().slice(0, 120);
  const issue_category = String(b.issue_category || "").trim().slice(0, 100);
  const issue_description = String(b.issue_description || "").trim().slice(0, 3000);
  const priority = String(b.priority || "Medium");
  const categories = ["Machine broken / out of service", "No fuel", "Network / connectivity", "Payment / Paybill", "Display frozen / error", "Customer complaint", "Shop information correction", "Relocation", "Other"];
  if (shop_name.length < 2 || location.length < 2) return res.status(400).json({ error: "Shop name and location are required." });
  if (!categories.includes(issue_category)) return res.status(400).json({ error: "Select a valid issue category." });
  if (issue_description.length < 5) return res.status(400).json({ error: "Describe the issue in at least 5 characters." });
  if (!["Urgent", "High", "Medium", "Low"].includes(priority)) return res.status(400).json({ error: "Select a valid priority." });
  const today = new Date().toISOString().slice(0, 10);
  const payload = { ticket_date: today, issue_source: "Agent", reported_by: req.user.email, shop_name, location, issue_category, issue_description, priority, status: "Not resolved", assigned_representative_id: req.user.id, created_by: req.user.id };
  const { data, error } = await supabaseAdmin.from("customer_care_tickets").insert(payload).select().single();
  if (error) return res.status(400).json({ error: error.message });
  await notifyAdmins(`New ${priority.toLowerCase()} field issue`, `Ticket #${data.ticket_no}: ${shop_name} (${location}) — ${issue_category}. Reported by ${req.user.email}.`, "ticket", data.id);
  await writeSecurity("representative_ticket_created", req, req.user.id, { ticket_id: data.id, ticket_no: data.ticket_no, issue_category, priority });
  res.status(201).json({ data });
});

app.get("/api/representative/tickets", requireRepresentative, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("customer_care_tickets").select("*").eq("assigned_representative_id", req.user.id).order("created_at", { ascending: false }).limit(500);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ data: data || [] });
});

function normalizeOptionalTill(value) {
  const till = String(value || "").replace(/\s/g, "");
  if (!till) return "";
  if (!/^\d{1,15}$/.test(till)) throw new Error("Till number must contain digits only, or be left blank if unavailable.");
  if (/^0+$/.test(till)) throw new Error("Till number is optional. Leave it blank when unavailable; do not use zeros as a placeholder.");
  return till;
}
function checklistPayload(b) {
  const shop_name = String(b.shop_name || "").trim(), location = String(b.location || "").trim(), agent_name = String(b.agent_name || "").trim(), mpesa_number = String(b.mpesa_number || "").trim();
  let till_number; try { till_number = normalizeOptionalTill(b.till_number); } catch (e) { throw e; }
  const canisters_delivered = Number(b.canisters_delivered ?? 0), latitude = Number(b.latitude), longitude = Number(b.longitude);
  if (shop_name.length < 2 || location.length < 2 || agent_name.length < 2 || !mpesa_number) throw new Error("Shop name, location, agent name and M-Pesa number are required.");
  if (!Number.isInteger(canisters_delivered) || canisters_delivered < 0 || canisters_delivered > 100000) throw new Error("Canisters delivered must be a whole number from 0 to 100000.");
  if (!/^(?:\+?254|0)?[17]\d{8}$/.test(mpesa_number.replace(/[\s-]/g, ""))) throw new Error("Enter a valid Kenyan M-Pesa number.");
  if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90 || !Number.isFinite(longitude) || longitude < -180 || longitude > 180) throw new Error("Capture valid shop coordinates before submitting.");
  return { shop_name, location, agent_name, mpesa_number: mpesa_number.replace(/[\s-]/g, ""), till_number: till_number || null, kp_number: String(b.kp_number || "").trim() || null, account_mn_number: String(b.account_mn_number || "").trim() || null, bank_account: String(b.bank_account || "").trim() || null, is_branded: b.is_branded === true, has_network: b.has_network === true, has_paybill: b.has_paybill === true, is_selling: b.is_selling === true, canisters_delivered, latitude, longitude, master_seed_no: String(b.master_seed_no || "").trim() || null };
}
const EDITABLE_SHOP_FIELDS = ["shop_name","location","agent_name","mpesa_number","till_number","kp_number","account_mn_number","bank_account","is_branded","has_network","has_paybill","is_selling","canisters_delivered","latitude","longitude","master_seed_no"];
function historySnapshot(row) { const out = {}; for (const key of EDITABLE_SHOP_FIELDS) out[key] = row?.[key] ?? null; return out; }
app.post("/api/representative/submissions", requireRepresentative, async (req, res) => {
  let payload; try { payload = checklistPayload(req.body || {}); } catch (e) { return res.status(400).json({ error: e.message }); }
  // A representative cannot submit the same master shop twice from their account; update their existing record instead.
  if (payload.master_seed_no) {
    const { data: existing } = await supabaseAdmin.from("agent_representative_submissions").select("id,shop_name").eq("representative_id", req.user.id).eq("master_seed_no", payload.master_seed_no).limit(1).maybeSingle();
    if (existing) { await writeSecurity("duplicate_master_shop_submission_blocked", req, req.user.id, { submission_id: existing.id, master_seed_no: payload.master_seed_no }); return res.status(409).json({ error: `You have already submitted an update for ${existing.shop_name}. Use Update shop status from My Submissions or the Master Directory.` }); }
  }
  const insert = { ...payload, representative_id: req.user.id, representative_email: req.user.email };
  const { data, error } = await supabaseAdmin.from("agent_representative_submissions").insert(insert).select().single();
  if (error) { if (error.code === "23505") return res.status(409).json({ error: "This record already exists. Open the Master Directory or My Submissions and update your existing record." }); return res.status(400).json({ error: error.message }); }
  const { error: histError } = await supabaseAdmin.from("representative_shop_edit_history").insert({ submission_id: data.id, representative_id: req.user.id, action: "created", old_values: null, new_values: historySnapshot(data) });
  if (histError) req.log.warn({ err: histError }, "Could not create initial shop edit history");
  await recordRepresentativeVisit(req, data, "created");
  await writeSecurity("representative_submission", req, req.user.id, { submission_id: data.id, shop_name: payload.shop_name, master_seed_no: payload.master_seed_no, is_selling: payload.is_selling });
  res.status(201).json({ data });
});
app.patch("/api/representative/submissions/:id", requireRepresentative, async (req, res) => {
  let payload; try { payload = checklistPayload(req.body || {}); } catch (e) { return res.status(400).json({ error: e.message }); }
  const { data: current, error: readError } = await supabaseAdmin.from("agent_representative_submissions").select("*").eq("id", req.params.id).eq("representative_id", req.user.id).maybeSingle();
  if (readError) return res.status(400).json({ error: readError.message });
  if (!current) { await writeSecurity("representative_shop_update_denied", req, req.user.id, { submission_id: req.params.id }); return res.status(404).json({ error: "Shop submission not found under your account. You can only edit shops you submitted using this registered representative account." }); }
  const updated = { ...payload, representative_id: req.user.id, representative_email: req.user.email, last_edited_at: new Date().toISOString(), last_edited_by: req.user.id, edit_count: Number(current.edit_count || 0) + 1 };
  const { data, error } = await supabaseAdmin.from("agent_representative_submissions").update(updated).eq("id", current.id).eq("representative_id", req.user.id).select().single();
  if (error) return res.status(400).json({ error: error.message });
  const { error: histError } = await supabaseAdmin.from("representative_shop_edit_history").insert({ submission_id: data.id, representative_id: req.user.id, action: "updated", old_values: historySnapshot(current), new_values: historySnapshot(data) });
  if (histError) req.log.warn({ err: histError }, "Could not write shop edit history");
  await recordRepresentativeVisit(req, data, "updated");
  await writeSecurity("representative_shop_updated", req, req.user.id, { submission_id: data.id, shop_name: data.shop_name, is_selling: data.is_selling, edit_count: data.edit_count });
  res.json({ data });
});
app.get("/api/representative/submissions/:id/history", requireRepresentative, async (req, res) => {
  const { data: owned, error: ownedError } = await supabaseAdmin.from("agent_representative_submissions").select("id").eq("id", req.params.id).eq("representative_id", req.user.id).maybeSingle();
  if (ownedError) return res.status(400).json({ error: ownedError.message });
  if (!owned) return res.status(404).json({ error: "Shop submission not found under your account." });
  const { data, error } = await supabaseAdmin.from("representative_shop_edit_history").select("id,action,old_values,new_values,edited_at,representative_id").eq("submission_id", req.params.id).eq("representative_id", req.user.id).order("edited_at", { ascending: false }).limit(100);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ data: data || [] });
});

app.post("/api/technician/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== "string" || typeof password !== "string") return res.status(400).json({ error: "Invalid credentials" });
  const { data, error } = await supabasePublic.auth.signInWithPassword({ email, password });
  if (error || !data.session) { await writeSecurity("technician_login_failed", req, null, { email: String(email).slice(0, 180) }); return res.status(401).json({ error: "Invalid credentials" }); }
  const { data: profile } = await supabaseAdmin.from("technician_profiles").select("*").eq("user_id", data.user.id).eq("active", true).maybeSingle();
  if (!profile) return res.status(403).json({ error: "This account is not an active technician account" });
  await writeSecurity("technician_login", req, data.user.id);
  res.json({ access_token: data.session.access_token, user: { id: data.user.id, email: data.user.email }, technician: profile });
});
app.get("/api/technician/shops", requireTechnician, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("agent_representative_submissions").select("*").order("created_at", { ascending: false }).limit(5000);
  if (error) return res.status(400).json({ error: error.message });
  const q = String(req.query.q || "").trim().toLowerCase();
  const submissions = data || [], latestBySeed = new Map();
  for (const row of submissions) if (row.master_seed_no && !latestBySeed.has(String(row.master_seed_no))) latestBySeed.set(String(row.master_seed_no), row);
  let merged = [...masterSeed.map(seed => ({ ...seed, ...(latestBySeed.get(String(seed.master_seed_no)) || {}), master_seed_no: seed.master_seed_no, seed_record: true, master_status: seed.master_status })), ...submissions.filter(x => !x.master_seed_no).map(x => ({ ...x, seed_record: false }))];
  if (q) merged = merged.filter(x => [x.shop_name,x.location,x.kp_number,x.till_number,x.account_mn_number,x.bank_account,x.agent_name,x.mpesa_number,x.representative_email,x.latitude,x.longitude,x.master_status,...Object.values(x.master_data || {})].some(v => String(v ?? "").toLowerCase().includes(q)));
  await writeSecurity("technician_master_directory_view", req, req.user.id, { query: q || null, result_count: merged.length });
  res.json({ data: merged });
});
app.get("/api/technician/tickets", requireTechnician, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("customer_care_tickets").select("*").eq("assigned_technician_id", req.user.id).order("ticket_date", { ascending: false }).limit(1000);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ data: data || [] });
});
app.patch("/api/technician/tickets/:id", requireTechnician, async (req, res) => {
  const b = req.body || {};
  const { data: current, error: readError } = await supabaseAdmin.from("customer_care_tickets").select("*").eq("id", req.params.id).eq("assigned_technician_id", req.user.id).maybeSingle();
  if (readError) return res.status(400).json({ error: readError.message });
  if (!current) return res.status(404).json({ error: "Assigned ticket not found." });
  const allowed = ["In progress", "Resolved", "On hold"];
  if (!allowed.includes(b.status)) return res.status(400).json({ error: "Choose In progress, On hold, or Resolved." });
  const resolution = String(b.resolution || "").trim();
  if (b.status === "Resolved" && resolution.length < 3) return res.status(400).json({ error: "Add resolution notes before marking a ticket resolved." });
  const patch = { status: b.status, resolution: resolution || null, updated_at: new Date().toISOString(), last_updated_by: req.user.id };
  if (b.status === "Resolved") patch.resolution_date = new Date().toISOString().slice(0, 10);
  const { data, error } = await supabaseAdmin.from("customer_care_tickets").update(patch).eq("id", req.params.id).select().single();
  if (error) return res.status(400).json({ error: error.message });
  if (current.assigned_representative_id) await createNotification(current.assigned_representative_id, `Ticket #${data.ticket_no} updated`, `Status: ${data.status}${data.resolution ? ` — ${data.resolution}` : ""}`, "ticket", data.id);
  await writeSecurity("technician_ticket_updated", req, req.user.id, { ticket_id: data.id, ticket_no: data.ticket_no, from_status: current.status, to_status: data.status });
  res.json({ data });
});

app.post("/api/photo", async (req, res) => {
  try {
    const { filename, contentType, data } = req.body || {};
    if (!/^image\/(jpeg|png|webp)$/.test(contentType || "")) return res.status(400).json({ error: "Only JPG, PNG and WEBP are allowed." });
    const encoded = String(data || "");
    if (!encoded || encoded.length > Math.ceil(MAX_MB * 1024 * 1024 * 1.4)) return res.status(413).json({ error: `Photo exceeds ${MAX_MB} MB limit.` });
    const raw = Buffer.from(encoded, "base64");
    if (!raw.length || raw.length > MAX_MB * 1024 * 1024) return res.status(413).json({ error: `Photo exceeds ${MAX_MB} MB limit.` });
    const safe = String(filename || "photo.jpg").replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 80);
    const objectPath = `uploads/${new Date().toISOString().slice(0, 10)}/${crypto.randomUUID()}-${safe}`;
    const { error } = await supabaseAdmin.storage.from("shop-photos").upload(objectPath, raw, { contentType, cacheControl: "3600", upsert: false });
    if (error) throw error;
    res.json({ ok: true, path: objectPath });
  } catch (error) { req.log.error({ err: error }, "photo upload failed"); res.status(400).json({ error: "Photo upload failed." }); }
});

app.post("/api/submit", async (req, res) => {
  try {
    const b = req.body || {};
    const required = ["shop_name", "location", "latitude", "longitude", "agent_name", "phone_number", "visit_date", "is_selling", "needs_machine"];
    for (const key of required) if (b[key] === undefined || b[key] === null || String(b[key]).trim() === "") return res.status(400).json({ ok: false, error: `Missing ${key.replaceAll("_", " ")}.` });
    const shopName = String(b.shop_name).trim(), kp = String(b.kp || "").trim(), location = String(b.location).trim();
    const { data: duplicate } = kp ? await supabaseAdmin.from("shop_submissions").select("id").ilike("kp", kp).ilike("shop_name", shopName).maybeSingle() : { data: null };
    if (duplicate) return res.status(409).json({ ok: false, error: "A shop with this KP and shop name already exists." });
    const { data, error } = await supabaseAdmin.rpc("submit_shop_secure", {
      p_shop_name: shopName, p_kp: kp, p_location: location, p_latitude: Number(b.latitude), p_longitude: Number(b.longitude),
      p_agent_name: String(b.agent_name).trim(), p_phone: String(b.phone_number).trim(), p_whatsapp: String(b.whatsapp_number || "").trim(),
      p_alternative: String(b.alternative_number || "").trim(), p_visit_date: String(b.visit_date), p_is_selling: b.is_selling === true || b.is_selling === "true",
      p_needs_machine: b.needs_machine === true || b.needs_machine === "true", p_photo1: b.photo1_path ? String(b.photo1_path) : null,
      p_photo2: b.photo2_path ? String(b.photo2_path) : null, p_device_info: deviceInfo(req)
    });
    if (error) return res.status(error.code === "23505" ? 409 : 400).json({ ok: false, error: error.message });
    res.status(201).json({ ok: true, id: data });
  } catch (error) { req.log.error({ err: error }, "submit failed"); res.status(500).json({ ok: false, error: "Submission failed. Please try again." }); }
});

app.get("/api/admin/submissions", requireAdmin, async (req, res) => {
  const q = String(req.query.q || "").trim(), location = String(req.query.location || "").trim(), selling = req.query.selling, machine = req.query.machine;
  let query = supabaseAdmin.from("shop_submissions").select("*").order("created_at", { ascending: false }).limit(10000);
  if (location) query = query.eq("location", location); if (selling === "true" || selling === "false") query = query.eq("is_selling", selling === "true");
  if (machine === "true" || machine === "false") query = query.eq("needs_machine", machine === "true");
  if (q) query = query.textSearch("search_document", q, { type: "websearch", config: "simple" });
  const { data, error } = await query; if (error) return res.status(400).json({ error: error.message }); res.json({ data: data || [] });
});
app.get("/api/admin/analytics", requireAdmin, async (req, res) => {
  const [{ data: locations, error: locationError }, { count }] = await Promise.all([
    supabaseAdmin.from("shop_location_analysis").select("*"),
    supabaseAdmin.from("security_events").select("*", { count: "exact", head: true })
  ]);
  if (locationError) return res.status(400).json({ error: locationError.message });
  res.json({ locations: locations || [], security_events: count || 0 });
});
app.get("/api/admin/security", requireAdmin, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("security_events").select("id,event_type,user_id,ip,ip_hash,user_agent,created_at,metadata").order("created_at", { ascending: false }).limit(500);
  if (error) return res.status(400).json({ error: error.message }); res.json({ data: data || [] });
});

app.get("/api/admin/drivers", requireAdmin, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("driver_profiles").select("*, driver_vehicle_assignments(vehicle_id, assigned_at, vehicles(id,registration_number,vehicle_name,active))").order("created_at", { ascending: false });
  if (error) return res.status(400).json({ error: error.message }); res.json({ data: data || [] });
});
app.post("/api/admin/drivers", requireAdmin, async (req, res) => {
  try {
    const { email, password, full_name, phone, vehicle_id } = req.body || {};
    if (!email || !password || !full_name) return res.status(400).json({ error: "Email, password and full name are required." });
    if (String(password).length < 8) return res.status(400).json({ error: "Temporary password must be at least 8 characters." });
    const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({ email: String(email).trim(), password: String(password), email_confirm: true });
    if (authError) return res.status(400).json({ error: authError.message });
    const { error: profileError } = await supabaseAdmin.from("driver_profiles").insert({ user_id: authData.user.id, email: authData.user.email, full_name: String(full_name).trim(), phone: String(phone || "").trim(), active: true });
    if (profileError) { await supabaseAdmin.auth.admin.deleteUser(authData.user.id); return res.status(400).json({ error: profileError.message }); }
    if (vehicle_id) await supabaseAdmin.from("driver_vehicle_assignments").upsert({ driver_id: authData.user.id, vehicle_id });
    await writeSecurity("driver_created", req, req.user.id, { driver_id: authData.user.id, email: authData.user.email });
    res.status(201).json({ ok: true, id: authData.user.id });
  } catch (error) { req.log.error({ err: error }, "driver create failed"); res.status(500).json({ error: "Could not create driver." }); }
});
app.patch("/api/admin/drivers/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id, { full_name, phone, active, password, vehicle_id } = req.body || {};
    const patch = {};
    if (full_name !== undefined) patch.full_name = String(full_name).trim();
    if (phone !== undefined) patch.phone = String(phone).trim();
    if (active !== undefined) patch.active = Boolean(active);
    patch.updated_at = new Date().toISOString();
    const { error } = await supabaseAdmin.from("driver_profiles").update(patch).eq("user_id", id);
    if (error) return res.status(400).json({ error: error.message });
    if (password) { if (String(password).length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." }); const { error: pwError } = await supabaseAdmin.auth.admin.updateUserById(id, { password: String(password) }); if (pwError) return res.status(400).json({ error: pwError.message }); }
    if (vehicle_id === null || vehicle_id === "") await supabaseAdmin.from("driver_vehicle_assignments").delete().eq("driver_id", id);
    else if (vehicle_id) await supabaseAdmin.from("driver_vehicle_assignments").upsert({ driver_id: id, vehicle_id });
    await writeSecurity("driver_updated", req, req.user.id, { driver_id: id });
    res.json({ ok: true });
  } catch (error) { req.log.error({ err: error }, "driver update failed"); res.status(500).json({ error: "Could not update driver." }); }
});
app.delete("/api/admin/drivers/:id", requireAdmin, async (req, res) => {
  try { const { error } = await supabaseAdmin.auth.admin.deleteUser(req.params.id); if (error) return res.status(400).json({ error: error.message }); await writeSecurity("driver_deleted", req, req.user.id, { driver_id: req.params.id }); res.json({ ok: true }); }
  catch (error) { req.log.error({ err: error }, "driver delete failed"); res.status(500).json({ error: "Could not delete driver." }); }
});
// Admins can manage the three account types from one control panel.
app.get("/api/admin/admins", requireAdmin, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("admin_allowlist").select("user_id,email,created_at").order("created_at", { ascending: true });
  if (error) return res.status(400).json({ error: error.message });
  const rows = await Promise.all((data || []).map(async row => { const { data: auth } = await supabaseAdmin.auth.admin.getUserById(row.user_id); return { ...row, active: auth?.user?.banned_until ? new Date(auth.user.banned_until) < new Date() : true, last_sign_in_at: auth?.user?.last_sign_in_at || null }; }));
  res.json({ data: rows });
});
app.post("/api/admin/admins", requireAdmin, async (req, res) => {
  try {
    const email=String(req.body?.email||"").trim().toLowerCase(), password=String(req.body?.password||"");
    if (!email || password.length < 8) return res.status(400).json({ error: "A valid email and password of at least 8 characters are required." });
    const { data: created, error: createError } = await supabaseAdmin.auth.admin.createUser({ email, password, email_confirm: true });
    if (createError) return res.status(400).json({ error: createError.message });
    const { error } = await supabaseAdmin.from("admin_allowlist").insert({ user_id: created.user.id, email: created.user.email });
    if (error) { await supabaseAdmin.auth.admin.deleteUser(created.user.id); return res.status(400).json({ error: error.message }); }
    await writeSecurity("admin_created", req, req.user.id, { new_admin_id: created.user.id, email }); res.status(201).json({ ok: true, id: created.user.id });
  } catch (error) { req.log.error({ err: error }, "admin create failed"); res.status(500).json({ error: "Could not create administrator." }); }
});
app.patch("/api/admin/admins/:id", requireAdmin, async (req, res) => {
  const id=req.params.id, { password, active }=req.body||{};
  const { count, error: countError } = await supabaseAdmin.from("admin_allowlist").select("user_id", { count: "exact", head: true });
  if (countError) return res.status(400).json({ error: countError.message });
  if (active === false && id === req.user.id) return res.status(400).json({ error: "You cannot disable your own admin account." });
  if (active === false && count <= 1) return res.status(400).json({ error: "At least one administrator must remain." });
  if (password) { if (String(password).length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." }); const { error } = await supabaseAdmin.auth.admin.updateUserById(id, { password: String(password) }); if (error) return res.status(400).json({ error: error.message }); }
  if (active !== undefined) { const { error } = await supabaseAdmin.auth.admin.updateUserById(id, { ban_duration: active ? "none" : "876000h" }); if (error) return res.status(400).json({ error: error.message }); }
  await writeSecurity("admin_updated", req, req.user.id, { target_admin_id: id, active }); res.json({ ok: true });
});
app.delete("/api/admin/admins/:id", requireAdmin, async (req, res) => {
  const id=req.params.id; if (id === req.user.id) return res.status(400).json({ error: "You cannot delete your own admin account." });
  const { count, error: countError } = await supabaseAdmin.from("admin_allowlist").select("user_id", { count: "exact", head: true });
  if (countError) return res.status(400).json({ error: countError.message }); if (count <= 1) return res.status(400).json({ error: "At least one administrator must remain." });
  const { error } = await supabaseAdmin.auth.admin.deleteUser(id); if (error) return res.status(400).json({ error: error.message }); await writeSecurity("admin_deleted", req, req.user.id, { target_admin_id: id }); res.json({ ok: true });
});
app.get("/api/admin/representatives", requireAdmin, async (req, res) => { const { data, error } = await supabaseAdmin.from("agent_representative_profiles").select("*").order("created_at", { ascending: false }); if (error) return res.status(400).json({ error: error.message }); res.json({ data: data || [] }); });
app.post("/api/admin/representatives", requireAdmin, async (req, res) => {
  try { const email=String(req.body?.email||"").trim().toLowerCase(), password=String(req.body?.password||""), full_name=String(req.body?.full_name||"").trim(), phone=String(req.body?.phone||"").trim();
    if (!email || !full_name || password.length < 8) return res.status(400).json({ error: "Name, valid email and password (8+ characters) are required." });
    const { data: auth, error: ae } = await supabaseAdmin.auth.admin.createUser({ email, password, email_confirm: true }); if (ae) return res.status(400).json({ error: ae.message });
    const { error } = await supabaseAdmin.from("agent_representative_profiles").insert({ user_id: auth.user.id, email: auth.user.email, full_name, phone, active: true });
    if (error) { await supabaseAdmin.auth.admin.deleteUser(auth.user.id); return res.status(400).json({ error: error.message }); }
    await writeSecurity("representative_created", req, req.user.id, { representative_id: auth.user.id, email }); res.status(201).json({ ok: true, id: auth.user.id });
  } catch (error) { req.log.error({ err: error }, "representative create failed"); res.status(500).json({ error: "Could not create representative." }); }
});
app.patch("/api/admin/representatives/:id", requireAdmin, async (req, res) => {
  const id=req.params.id, b=req.body||{}, patch={ updated_at:new Date().toISOString() };
  if (b.full_name !== undefined) patch.full_name=String(b.full_name).trim(); if (b.phone !== undefined) patch.phone=String(b.phone).trim(); if (b.active !== undefined) patch.active=Boolean(b.active);
  const { error } = await supabaseAdmin.from("agent_representative_profiles").update(patch).eq("user_id",id); if (error) return res.status(400).json({ error:error.message });
  if (b.password) { if (String(b.password).length<8) return res.status(400).json({ error:"Password must be at least 8 characters." }); const { error: pe }=await supabaseAdmin.auth.admin.updateUserById(id,{password:String(b.password)}); if(pe)return res.status(400).json({error:pe.message}); }
  await writeSecurity("representative_updated",req,req.user.id,{representative_id:id}); res.json({ok:true});
});
app.delete("/api/admin/representatives/:id", requireAdmin, async (req,res)=>{ const {error}=await supabaseAdmin.auth.admin.deleteUser(req.params.id); if(error)return res.status(400).json({error:error.message}); await writeSecurity("representative_deleted",req,req.user.id,{representative_id:req.params.id}); res.json({ok:true}); });
app.get("/api/admin/representative-submissions", requireAdmin, async (req,res)=>{ const {data,error}=await supabaseAdmin.from("agent_representative_submissions").select("*").order("created_at",{ascending:false}).limit(10000); if(error)return res.status(400).json({error:error.message}); res.json({data:data||[]}); });

// Phase 2: management oversight for visits, follow-ups, verification, and representative performance.
app.get("/api/admin/field-activity", requireAdmin, async (req, res) => {
  const [visits, followups, reps, tickets] = await Promise.all([
    supabaseAdmin.from("representative_shop_visits").select("*").order("visited_at", { ascending: false }).limit(10000),
    supabaseAdmin.from("representative_shop_followups").select("*").order("created_at", { ascending: false }).limit(10000),
    supabaseAdmin.from("agent_representative_profiles").select("user_id,full_name,email,active"),
    supabaseAdmin.from("customer_care_tickets").select("id,ticket_no,assigned_representative_id,status,priority,created_at").not("assigned_representative_id", "is", null).limit(10000)
  ]);
  const failed = [visits, followups, reps, tickets].find(x => x.error);
  if (failed) return res.status(400).json({ error: failed.error.message });
  const v = visits.data || [], f = followups.data || [], r = reps.data || [], t = tickets.data || [];
  const today = new Date().toISOString().slice(0, 10);
  const performance = r.map(rep => {
    const rv = v.filter(x => x.representative_id === rep.user_id);
    const rf = f.filter(x => x.representative_id === rep.user_id);
    const rt = t.filter(x => x.assigned_representative_id === rep.user_id);
    return { user_id: rep.user_id, full_name: rep.full_name, email: rep.email, active: rep.active,
      visits_total: rv.length, visits_today: rv.filter(x => String(x.visited_at || "").slice(0,10) === today).length,
      followups_open: rf.filter(x => ["Open", "In Progress"].includes(x.status)).length,
      followups_overdue: rf.filter(x => ["Open", "In Progress"].includes(x.status) && x.due_date && x.due_date < today).length,
      followups_completed: rf.filter(x => x.status === "Completed").length,
      tickets_open: rt.filter(x => !["Resolved", "Verified", "Closed"].includes(x.status)).length };
  });
  res.json({ visits: v, followups: f, performance, summary: { visits: v.length, followups_open: f.filter(x => ["Open", "In Progress"].includes(x.status)).length, followups_overdue: f.filter(x => ["Open", "In Progress"].includes(x.status) && x.due_date && x.due_date < today).length, verification_pending: f.filter(x => x.verification_status === "Pending").length, tickets_open: t.filter(x => !["Resolved", "Verified", "Closed"].includes(x.status)).length } });
});
app.patch("/api/admin/field-followups/:id/verification", requireAdmin, async (req, res) => {
  const b = req.body || {}, status = String(b.verification_status || "");
  if (!["Pending", "Approved", "Rejected"].includes(status)) return res.status(400).json({ error: "Choose Pending, Approved, or Rejected." });
  const notes = String(b.verification_notes || "").trim().slice(0, 2000);
  if (status === "Rejected" && notes.length < 3) return res.status(400).json({ error: "Add a short note explaining why verification was rejected." });
  const { data: current, error: readError } = await supabaseAdmin.from("representative_shop_followups").select("id,representative_id,shop_name,location,followup_type").eq("id", req.params.id).maybeSingle();
  if (readError) return res.status(400).json({ error: readError.message });
  if (!current) return res.status(404).json({ error: "Follow-up not found." });
  const patch = { verification_status: status, verification_notes: notes || null, verified_by: req.user.id, verified_at: new Date().toISOString(), updated_at: new Date().toISOString() };
  const { data, error } = await supabaseAdmin.from("representative_shop_followups").update(patch).eq("id", req.params.id).select().single();
  if (error) return res.status(400).json({ error: error.message });
  await createNotification(current.representative_id, `Follow-up ${status.toLowerCase()}`, `${current.shop_name} (${current.location}) — ${current.followup_type}. ${notes}`.trim(), "followup", current.id);
  await writeSecurity("followup_verification_updated", req, req.user.id, { followup_id: current.id, verification_status: status });
  res.json({ data });
});

// Customer care ticketing: admin-only CRUD with server-derived month/quarter metadata.
function ticketPayload(body, existing={}) {
  const b=body||{}, out={};
  const fields=['ticket_date','issue_source','reported_by','shop_name','location','issue_category','issue_description','priority','status','resolution','resolution_date','csr_name','assigned_representative_id','assigned_technician_id'];
  for(const key of fields) if(b[key]!==undefined) out[key]=String(b[key]??'').trim()||null;
  const d=out.ticket_date||existing.ticket_date||new Date().toISOString().slice(0,10);
  if(!/^\d{4}-\d{2}-\d{2}$/.test(d)||Number.isNaN(Date.parse(d))) throw new Error('Enter a valid ticket date.');
  out.month=new Date(`${d}T12:00:00Z`).toLocaleString('en-US',{month:'short',timeZone:'UTC'});
  out.quarter=`Q${Math.floor((Number(d.slice(5,7))-1)/3)+1}`;
  if(out.issue_source!==undefined && out.issue_source && !['Agent','Driver','Customer','Internal','Other'].includes(out.issue_source)) throw new Error('Select a valid issue source.');
  if(out.priority!==undefined && out.priority && !['Urgent','High','Medium','Low'].includes(out.priority)) throw new Error('Select a valid priority.');
  if(out.status!==undefined && out.status && !['Not resolved','Assigned','In progress','Resolved','Verified','Closed','On hold','Reopened'].includes(out.status)) throw new Error('Select a valid ticket status.');
  if(out.status==='Resolved' && !out.resolution_date) out.resolution_date=new Date().toISOString().slice(0,10);
  if(out.status && out.status!=='Resolved' && out.resolution_date===null) out.resolution_date=null;
  return out;
}
app.get('/api/admin/customer-care', requireAdmin, async (req,res)=>{
  const {data,error}=await supabaseAdmin.from('customer_care_tickets').select('*').order('ticket_date',{ascending:false}).order('ticket_no',{ascending:false}).limit(10000);
  if(error)return res.status(400).json({error:error.message});res.json({data:data||[]});
});
app.post('/api/admin/customer-care', requireAdmin, async (req,res)=>{
  try{const b=req.body||{};if(!String(b.issue_description||'').trim())return res.status(400).json({error:'Issue description is required.'});const payload=ticketPayload(b);payload.issue_description=String(b.issue_description).trim();payload.created_by=req.user.id;payload.csr_profile_id=req.customerCare.role==="Administrator"?null:req.user.id;if(payload.assigned_representative_id||payload.assigned_technician_id){payload.assigned_by=req.user.id;payload.assigned_at=new Date().toISOString();if(!payload.status||payload.status==='Not resolved')payload.status='Assigned';}
    const {data,error}=await supabaseAdmin.from('customer_care_tickets').insert(payload).select().single();if(error)return res.status(400).json({error:error.message});await writeSecurity('customer_care_ticket_created',req,req.user.id,{ticket_no:data.ticket_no});res.status(201).json({data});
  }catch(e){res.status(400).json({error:e.message||'Could not create ticket.'});}
});
app.patch('/api/admin/customer-care/:id', requireAdmin, async (req,res)=>{
  try{const {data:current,error:readError}=await supabaseAdmin.from('customer_care_tickets').select('*').eq('id',req.params.id).maybeSingle();if(readError)return res.status(400).json({error:readError.message});if(!current)return res.status(404).json({error:'Ticket not found.'});const payload=ticketPayload(req.body,current);if(req.body?.issue_description!==undefined){payload.issue_description=String(req.body.issue_description||'').trim();if(!payload.issue_description)return res.status(400).json({error:'Issue description is required.'});}payload.updated_at=new Date().toISOString();payload.last_updated_by=req.user.id;if(payload.assigned_representative_id!==undefined||payload.assigned_technician_id!==undefined){payload.assigned_by=req.user.id;payload.assigned_at=new Date().toISOString();if((payload.assigned_representative_id||payload.assigned_technician_id)&&(!payload.status||payload.status==='Not resolved'))payload.status='Assigned';}const {error}=await supabaseAdmin.from('customer_care_tickets').update(payload).eq('id',req.params.id);if(error)return res.status(400).json({error:error.message});const recipient=payload.assigned_representative_id||current.assigned_representative_id;if(recipient)await createNotification(recipient,`Ticket #${current.ticket_no} updated`,`Status: ${payload.status||current.status}${payload.resolution?` — ${payload.resolution}`:''}`,'ticket',req.params.id);await writeSecurity('customer_care_ticket_updated',req,req.user.id,{ticket_id:req.params.id,ticket_no:current.ticket_no});res.json({ok:true});
  }catch(e){res.status(400).json({error:e.message||'Could not update ticket.'});}
});
app.delete('/api/admin/customer-care/:id', requireAdmin, async (req,res)=>{const {data:current}=await supabaseAdmin.from('customer_care_tickets').select('ticket_no').eq('id',req.params.id).maybeSingle();const {error}=await supabaseAdmin.from('customer_care_tickets').delete().eq('id',req.params.id);if(error)return res.status(400).json({error:error.message});await writeSecurity('customer_care_ticket_deleted',req,req.user.id,{ticket_id:req.params.id,ticket_no:current?.ticket_no});res.json({ok:true});});

// Dedicated Customer Care portal APIs. Directory responses are cached briefly and invalidated after onboarding writes.
const csrDirectoryCache = new Map();
function clearCsrCache() { csrDirectoryCache.clear(); }
function norm(v) { return String(v ?? "").trim().toLowerCase().replace(/\s+/g, " "); }
app.get("/api/csr/me", requireCustomerCare, (req,res) => res.json({ profile: req.customerCare, email: req.user.email }));
app.get("/api/csr/team", requireCustomerCare, async (req,res) => {
  const [reps,techs,drivers,care,admins] = await Promise.all([
    supabaseAdmin.from("agent_representative_profiles").select("user_id,full_name,email,phone,active,created_at").order("full_name").limit(5000),
    supabaseAdmin.from("technician_profiles").select("user_id,full_name,email,phone,active,created_at").order("full_name").limit(5000),
    supabaseAdmin.from("driver_profiles").select("user_id,full_name,email,phone,active,created_at").order("full_name").limit(5000),
    supabaseAdmin.from("customer_care_profiles").select("user_id,full_name,email,phone,active,created_at").order("full_name").limit(5000),
    supabaseAdmin.from("admin_allowlist").select("user_id,email").limit(5000)
  ]);
  const failed=[reps,techs,drivers,care,admins].find(x=>x.error); if(failed)return res.status(400).json({error:failed.error.message});
  res.json({ representatives:reps.data||[], technicians:techs.data||[], drivers:drivers.data||[], customerCare:care.data||[], administrators:admins.data||[] });
});
app.get("/api/csr/shops", requireCustomerCare, async (req,res) => {
  const q=String(req.query.q||"").trim().slice(0,120), key=norm(q), cached=csrDirectoryCache.get(key);
  if(cached && cached.expires>Date.now()) return res.json({data:cached.data,cached:true});
  const [reps,shops,onboarded] = await Promise.all([
    supabaseAdmin.from("agent_representative_submissions").select("id,shop_name,location,agent_name,mpesa_number,latitude,longitude,kp_number,till_number,account_mn_number,representative_email,created_at,is_selling,canisters_delivered").order("created_at",{ascending:false}).limit(10000),
    supabaseAdmin.from("shop_submissions").select("id,shop_name,location,agent_name,phone_number,latitude,longitude,kp,visit_date,created_at,is_selling,needs_machine").order("created_at",{ascending:false}).limit(10000),
    supabaseAdmin.from("csr_shop_onboarding").select("*").order("created_at",{ascending:false}).limit(10000)
  ]);
  const failed=[reps,shops,onboarded].find(x=>x.error); if(failed)return res.status(400).json({error:failed.error.message});
  const all=[...(reps.data||[]).map(x=>({...x,source:"Representative onboarding",kp_number:x.kp_number||x.account_mn_number||"",phone:x.mpesa_number||""})),...(shops.data||[]).map(x=>({...x,source:"Agent form",kp_number:x.kp||"",phone:x.phone_number||""})),...(onboarded.data||[]).map(x=>({...x,source:"Customer Care onboarding",location:x.physical_address,agent_name:x.agent_full_name,kp_number:x.kp_number,phone:x.personal_phone_number}))];
  const filtered=key?all.filter(x=>[x.shop_name,x.location,x.agent_name,x.phone,x.kp_number,x.till_number,x.mn_atr_number].some(v=>norm(v).includes(key))):all;
  const seen=new Set(), data=[]; for(const x of filtered){const signature=[norm(x.shop_name),norm(x.location),norm(x.kp_number||x.kp),norm(x.phone||x.mpesa_number)].join("|"); if(!seen.has(signature)){seen.add(signature);data.push(x);}}
  csrDirectoryCache.set(key,{data:data.slice(0,300),expires:Date.now()+15000}); res.set("Cache-Control","private, max-age=15, stale-while-revalidate=10"); res.json({data:data.slice(0,300),cached:false});
});
app.post("/api/csr/shops", requireCustomerCare, async (req,res) => {
  const b=req.body||{}, shop_name=String(b.shop_name||"").trim(), physical_address=String(b.physical_address||"").trim(), agent_full_name=String(b.agent_full_name||"").trim(), kp_number=String(b.kp_number||"").trim(), phone=String(b.personal_phone_number||"").trim(), mn=String(b.mn_atr_number||"").trim();
  if(shop_name.length<2||physical_address.length<2||agent_full_name.length<2||kp_number.length<1||!['Yes','No'].includes(String(b.machine_at_outlet||''))) return res.status(400).json({error:"Shop name, physical address, agent name, KP number, and machine status are required."});
  const [a,c,d] = await Promise.all([
    supabaseAdmin.from("agent_representative_submissions").select("id,shop_name,location,kp_number,account_mn_number,mpesa_number").limit(10000),
    supabaseAdmin.from("shop_submissions").select("id,shop_name,location,kp,phone_number").limit(10000),
    supabaseAdmin.from("csr_shop_onboarding").select("id,shop_name,physical_address,kp_number,mn_atr_number,personal_phone_number").limit(10000)
  ]);
  const failed=[a,c,d].find(x=>x.error);if(failed)return res.status(400).json({error:failed.error.message});
  const candidates=[...(a.data||[]).map(x=>({id:x.id,name:x.shop_name,location:x.location,kp:x.kp_number||x.account_mn_number,phone:x.mpesa_number,source:"Representative onboarding"})),...(c.data||[]).map(x=>({id:x.id,name:x.shop_name,location:x.location,kp:x.kp,phone:x.phone_number,source:"Agent form"})),...(d.data||[]).map(x=>({id:x.id,name:x.shop_name,location:x.physical_address,kp:x.kp_number,phone:x.personal_phone_number,source:"Customer Care onboarding"}))];
  const duplicate=candidates.find(x=>(norm(kp_number)&&norm(x.kp)===norm(kp_number))||(norm(mn)&&norm(x.mn_atr_number)===norm(mn))||(norm(x.name)===norm(shop_name)&&norm(x.location)===norm(physical_address))||(norm(phone)&&norm(x.phone)===norm(phone)&&norm(x.name)===norm(shop_name)));
  if(duplicate){await writeSecurity("csr_shop_duplicate_blocked",req,req.user.id,{shop_name,matched_id:duplicate.id,source:duplicate.source});return res.status(409).json({error:`Possible duplicate found in ${duplicate.source}: ${duplicate.name} (${duplicate.location||"location not recorded"}). Search and select the existing shop instead.`,duplicate});}
  const row={shop_name,physical_address,agent_full_name,personal_phone_number:phone||null,alternative_number:String(b.alternative_number||"").trim()||null,national_id:String(b.national_id||"").trim()||null,kra_pin:String(b.kra_pin||"").trim()||null,gps_latitude:b.gps_latitude===""||b.gps_latitude==null?null:Number(b.gps_latitude),gps_longitude:b.gps_longitude===""||b.gps_longitude==null?null:Number(b.gps_longitude),landmark:String(b.landmark||"").trim()||null,kp_number, machine_at_outlet:String(b.machine_at_outlet),agent_commission:b.agent_commission===""||b.agent_commission==null?10:Number(b.agent_commission),entry_date:String(b.entry_date||"").trim()||null,mn_atr_number:mn||null,created_by:req.user.id,source:"customer-care"};
  if((row.gps_latitude!=null&&(!Number.isFinite(row.gps_latitude)||row.gps_latitude < -90||row.gps_latitude>90))||(row.gps_longitude!=null&&(!Number.isFinite(row.gps_longitude)||row.gps_longitude < -180||row.gps_longitude>180)))return res.status(400).json({error:"GPS coordinates are invalid."});
  const {data,error}=await supabaseAdmin.from("csr_shop_onboarding").insert(row).select().single();if(error)return res.status(400).json({error:error.message});clearCsrCache();await writeSecurity("csr_shop_onboarded",req,req.user.id,{shop_id:data.id,shop_name});res.status(201).json({data});
});
app.post("/api/csr/shops/import", requireCustomerCare, async (req,res)=>{
  const rows=Array.isArray(req.body?.rows)?req.body.rows:[];if(!rows.length||rows.length>1000)return res.status(400).json({error:"Upload between 1 and 1,000 CSV rows."});
  const [a,c,d]=await Promise.all([supabaseAdmin.from("agent_representative_submissions").select("shop_name,location,kp_number,account_mn_number,mpesa_number").limit(10000),supabaseAdmin.from("shop_submissions").select("shop_name,location,kp,phone_number").limit(10000),supabaseAdmin.from("csr_shop_onboarding").select("shop_name,physical_address,kp_number,mn_atr_number,personal_phone_number").limit(10000)]);
  const failed=[a,c,d].find(x=>x.error);if(failed)return res.status(400).json({error:failed.error.message});
  const known=[...(a.data||[]).map(x=>({name:x.shop_name,location:x.location,kp:x.kp_number||x.account_mn_number,phone:x.mpesa_number,mn:x.account_mn_number})),...(c.data||[]).map(x=>({name:x.shop_name,location:x.location,kp:x.kp,phone:x.phone_number})),...(d.data||[]).map(x=>({name:x.shop_name,location:x.physical_address,kp:x.kp_number,phone:x.personal_phone_number,mn:x.mn_atr_number}))];
  const results={inserted:0,duplicates:0,invalid:0,errors:[]};
  for(let i=0;i<rows.length;i++){const r=rows[i]||{},name=String(r.shop_name||r["Shop Name"]||"").trim();if(!name){results.invalid++;results.errors.push({row:i+2,error:"Shop Name is required."});continue;}
    const payload={shop_name:name,physical_address:String(r.physical_address||r["Physical Address"]||r.location||"").trim(),agent_full_name:String(r.agent_full_name||r["Agent Full Name"]||r.agent_name||"").trim(),personal_phone_number:String(r.personal_phone_number||r["Personal Phone Number"]||r.phone||"").trim()||null,alternative_number:String(r.alternative_number||r["Alternative Number"]||"").trim()||null,national_id:String(r.national_id||r["National ID"]||"").trim()||null,kra_pin:String(r.kra_pin||r["KRA PIN"]||"").trim()||null,gps_latitude:r.gps_latitude||r["GPS Latitude"]?Number(r.gps_latitude||r["GPS Latitude"]):null,gps_longitude:r.gps_longitude||r["GPS Longitude"]?Number(r.gps_longitude||r["GPS Longitude"]):null,landmark:String(r.landmark||r.Landmark||"").trim()||null,kp_number:String(r.kp_number||r["KP Number"]||r.kp||"").trim(),machine_at_outlet:String(r.machine_at_outlet||r["Machine Currently at Outlet"]||"No"),agent_commission:Number(r.agent_commission||r["Agreed Agent Commission (ksh/litre)"]||10),entry_date:String(r.entry_date||r.Date||"").trim()||null,mn_atr_number:String(r.mn_atr_number||r["MN-ATR Number"]||"").trim()||null,created_by:req.user.id,source:"csv-import"};
    if(payload.physical_address.length<2||payload.agent_full_name.length<2||!payload.kp_number||!['Yes','No'].includes(payload.machine_at_outlet)|| (payload.gps_latitude!=null&&(!Number.isFinite(payload.gps_latitude)||Math.abs(payload.gps_latitude)>90)) || (payload.gps_longitude!=null&&(!Number.isFinite(payload.gps_longitude)||Math.abs(payload.gps_longitude)>180))){results.invalid++;results.errors.push({row:i+2,error:"Missing required fields or invalid GPS/machine status."});continue;}
    const duplicate=known.find(x=>(norm(payload.kp_number)&&norm(x.kp)===norm(payload.kp_number))||(norm(payload.mn_atr_number)&&norm(x.mn)===norm(payload.mn_atr_number))||(norm(x.name)===norm(name)&&norm(x.location)===norm(payload.physical_address))||(norm(payload.personal_phone_number)&&norm(x.phone)===norm(payload.personal_phone_number)&&norm(x.name)===norm(name)));
    if(duplicate){results.duplicates++;continue;}const {error}=await supabaseAdmin.from("csr_shop_onboarding").insert(payload);if(error){results.invalid++;results.errors.push({row:i+2,error:error.message});}else{results.inserted++;known.push({name,location:payload.physical_address,kp:payload.kp_number,phone:payload.personal_phone_number,mn:payload.mn_atr_number});}
  }
  clearCsrCache();await writeSecurity("csr_csv_import",req,req.user.id,results);res.json(results);
});
app.get("/api/csr/tickets", requireCustomerCare, async (req,res)=>{const {data,error}=await supabaseAdmin.from("customer_care_tickets").select("*").order("ticket_date",{ascending:false}).order("ticket_no",{ascending:false}).limit(10000);if(error)return res.status(400).json({error:error.message});res.json({data:data||[]});});
app.post("/api/csr/tickets", requireCustomerCare, async (req,res)=>{try{const b=req.body||{};if(!String(b.issue_description||"").trim())return res.status(400).json({error:"Issue description is required."});const payload=ticketPayload({...b,csr_name:req.customerCare.full_name||req.user.email});payload.issue_description=String(b.issue_description).trim();payload.created_by=req.user.id;payload.csr_profile_id=req.customerCare.role==="Administrator"?null:req.user.id;if(payload.assigned_representative_id||payload.assigned_technician_id){payload.assigned_by=req.user.id;payload.assigned_at=new Date().toISOString();if(!payload.status||payload.status==="Not resolved")payload.status="Assigned";}const {data,error}=await supabaseAdmin.from("customer_care_tickets").insert(payload).select().single();if(error)return res.status(400).json({error:error.message});if(payload.assigned_representative_id)await createNotification(payload.assigned_representative_id,`New ticket #${data.ticket_no}`,`${data.shop_name||"Shop not specified"}: ${data.issue_category||"Issue"} — ${data.priority}`,"ticket",data.id);if(payload.assigned_technician_id)await createNotification(payload.assigned_technician_id,`New ticket #${data.ticket_no}`,`${data.shop_name||"Shop not specified"}: ${data.issue_category||"Issue"} — ${data.priority}`,"ticket",data.id);await writeSecurity("csr_ticket_created",req,req.user.id,{ticket_id:data.id,ticket_no:data.ticket_no});res.status(201).json({data});}catch(e){res.status(400).json({error:e.message||"Could not create ticket."});}});
app.patch("/api/csr/tickets/:id", requireCustomerCare, async (req,res)=>{try{const {data:current,error:re}=await supabaseAdmin.from("customer_care_tickets").select("*").eq("id",req.params.id).maybeSingle();if(re)return res.status(400).json({error:re.message});if(!current)return res.status(404).json({error:"Ticket not found."});const payload=ticketPayload(req.body,current);payload.updated_at=new Date().toISOString();payload.last_updated_by=req.user.id;const {error}=await supabaseAdmin.from("customer_care_tickets").update(payload).eq("id",req.params.id);if(error)return res.status(400).json({error:error.message});const rep=payload.assigned_representative_id||current.assigned_representative_id,tech=payload.assigned_technician_id||current.assigned_technician_id;for(const recipient of new Set([rep,tech].filter(Boolean)))await createNotification(recipient,`Ticket #${current.ticket_no} updated`,`Status: ${payload.status||current.status}`,"ticket",current.id);await writeSecurity("csr_ticket_updated",req,req.user.id,{ticket_id:current.id,ticket_no:current.ticket_no});res.json({ok:true});}catch(e){res.status(400).json({error:e.message||"Could not update ticket."});}});
app.get("/api/csr/field-activity", requireCustomerCare, async (req,res)=>{const [visits,followups]=await Promise.all([supabaseAdmin.from("representative_shop_visits").select("*").order("visited_at",{ascending:false}).limit(10000),supabaseAdmin.from("representative_shop_followups").select("*").order("created_at",{ascending:false}).limit(10000)]);const failed=[visits,followups].find(x=>x.error);if(failed)return res.status(400).json({error:failed.error.message});res.json({visits:visits.data||[],followups:followups.data||[]});});
app.get("/api/csr/dashboard", requireCustomerCare, async (req,res)=>{const [tickets,visits,followups,shops,reps,techs,drivers]=await Promise.all([supabaseAdmin.from("customer_care_tickets").select("id,status,priority,created_at,ticket_date").limit(10000),supabaseAdmin.from("representative_shop_visits").select("id,visited_at").limit(10000),supabaseAdmin.from("representative_shop_followups").select("id,status,due_date,created_at").limit(10000),supabaseAdmin.from("csr_shop_onboarding").select("id,created_at").limit(10000),supabaseAdmin.from("agent_representative_profiles").select("user_id").eq("active",true),supabaseAdmin.from("technician_profiles").select("user_id").eq("active",true),supabaseAdmin.from("driver_profiles").select("user_id").eq("active",true)]);const failed=[tickets,visits,followups,shops,reps,techs,drivers].find(x=>x.error);if(failed)return res.status(400).json({error:failed.error.message});const t=tickets.data||[],f=followups.data||[],today=new Date().toISOString().slice(0,10);const daily=Array.from({length:7},(_,i)=>{const d=new Date();d.setUTCDate(d.getUTCDate()-(6-i));const k=d.toISOString().slice(0,10);return {date:k,tickets:t.filter(x=>String(x.created_at||x.ticket_date).slice(0,10)===k).length,visits:(visits.data||[]).filter(x=>String(x.visited_at||"").slice(0,10)===k).length};});res.json({summary:{tickets:t.length,tickets_open:t.filter(x=>!['Resolved','Verified','Closed'].includes(x.status)).length,urgent:t.filter(x=>x.priority==='Urgent'&&!['Resolved','Verified','Closed'].includes(x.status)).length,visits:(visits.data||[]).length,followups_open:f.filter(x=>['Open','In Progress'].includes(x.status)).length,followups_overdue:f.filter(x=>['Open','In Progress'].includes(x.status)&&x.due_date&&x.due_date<today).length,shops_onboarded:(shops.data||[]).length,representatives:(reps.data||[]).length,technicians:(techs.data||[]).length,drivers:(drivers.data||[]).length},daily});});


app.get("/api/admin/customer-care-users", requireAdmin, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("customer_care_profiles").select("*").order("created_at", { ascending: false });
  if (error) return res.status(400).json({ error: error.message }); res.json({ data: data || [] });
});
app.post("/api/admin/customer-care-users", requireAdmin, async (req, res) => {
  try {
    const email=String(req.body?.email||"").trim().toLowerCase(), password=String(req.body?.password||""), full_name=String(req.body?.full_name||"").trim(), phone=String(req.body?.phone||"").trim();
    if (!email || !full_name || password.length < 8) return res.status(400).json({ error: "Name, valid email, and password (8+ characters) are required." });
    const { data: auth, error: authError } = await supabaseAdmin.auth.admin.createUser({ email, password, email_confirm: true });
    if (authError) return res.status(400).json({ error: authError.message });
    const { error } = await supabaseAdmin.from("customer_care_profiles").insert({ user_id: auth.user.id, email: auth.user.email, full_name, phone, active: true });
    if (error) { await supabaseAdmin.auth.admin.deleteUser(auth.user.id); return res.status(400).json({ error: error.message }); }
    await writeSecurity("customer_care_user_created", req, req.user.id, { customer_care_id: auth.user.id, email }); res.status(201).json({ ok: true, id: auth.user.id });
  } catch (e) { res.status(500).json({ error: "Could not create customer care account." }); }
});
app.patch("/api/admin/customer-care-users/:id", requireAdmin, async (req, res) => {
  const b=req.body||{}, patch={ updated_at:new Date().toISOString() };
  if (b.full_name !== undefined) patch.full_name=String(b.full_name).trim(); if (b.phone !== undefined) patch.phone=String(b.phone).trim(); if (b.active !== undefined) patch.active=Boolean(b.active);
  const { error }=await supabaseAdmin.from("customer_care_profiles").update(patch).eq("user_id",req.params.id); if(error)return res.status(400).json({error:error.message});
  if (b.password) { if(String(b.password).length<8)return res.status(400).json({error:"Password must be at least 8 characters."}); const {error:pe}=await supabaseAdmin.auth.admin.updateUserById(req.params.id,{password:String(b.password)}); if(pe)return res.status(400).json({error:pe.message}); }
  await writeSecurity("customer_care_user_updated",req,req.user.id,{customer_care_id:req.params.id,active:b.active}); res.json({ok:true});
});

app.get("/api/admin/technicians", requireAdmin, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("technician_profiles").select("*").order("created_at", { ascending: false });
  if (error) return res.status(400).json({ error: error.message }); res.json({ data: data || [] });
});
app.post("/api/admin/technicians", requireAdmin, async (req, res) => {
  try {
    const email=String(req.body?.email||"").trim().toLowerCase(), password=String(req.body?.password||""), full_name=String(req.body?.full_name||"").trim(), phone=String(req.body?.phone||"").trim();
    if (!email || !full_name || password.length < 8) return res.status(400).json({ error: "Name, valid email and password (8+ characters) are required." });
    const { data: auth, error: ae } = await supabaseAdmin.auth.admin.createUser({ email, password, email_confirm: true });
    if (ae) return res.status(400).json({ error: ae.message });
    const { error } = await supabaseAdmin.from("technician_profiles").insert({ user_id: auth.user.id, email: auth.user.email, full_name, phone, active: true });
    if (error) { await supabaseAdmin.auth.admin.deleteUser(auth.user.id); return res.status(400).json({ error: error.message }); }
    await writeSecurity("technician_created", req, req.user.id, { technician_id: auth.user.id, email }); res.status(201).json({ ok: true, id: auth.user.id });
  } catch (error) { req.log.error({ err: error }, "technician create failed"); res.status(500).json({ error: "Could not create technician." }); }
});
app.get("/api/admin/vehicles", requireAdmin, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("vehicles").select("*").order("registration_number"); if (error) return res.status(400).json({ error: error.message }); res.json({ data: data || [] });
});
app.post("/api/admin/vehicles", requireAdmin, async (req, res) => {
  const { registration_number, vehicle_name } = req.body || {};
  if (!registration_number) return res.status(400).json({ error: "Registration number is required." });
  const { data, error } = await supabaseAdmin.from("vehicles").insert({ registration_number: String(registration_number).trim().toUpperCase(), vehicle_name: String(vehicle_name || "").trim() }).select().single();
  if (error) return res.status(400).json({ error: error.message }); await writeSecurity("vehicle_created", req, req.user.id, { vehicle_id: data.id }); res.status(201).json({ data });
});
app.patch("/api/admin/vehicles/:id", requireAdmin, async (req, res) => {
  const { registration_number, vehicle_name, active, current_odometer } = req.body || {}, patch = {};
  if (registration_number !== undefined) patch.registration_number = String(registration_number).trim().toUpperCase();
  if (vehicle_name !== undefined) patch.vehicle_name = String(vehicle_name).trim(); if (active !== undefined) patch.active = Boolean(active); if (current_odometer !== undefined) patch.current_odometer = Number(current_odometer);
  patch.updated_at = new Date().toISOString(); const { error } = await supabaseAdmin.from("vehicles").update(patch).eq("id", req.params.id); if (error) return res.status(400).json({ error: error.message }); res.json({ ok: true });
});
app.delete("/api/admin/vehicles/:id", requireAdmin, async (req, res) => { const { error } = await supabaseAdmin.from("vehicles").delete().eq("id", req.params.id); if (error) return res.status(400).json({ error: error.message }); res.json({ ok: true }); });
app.get("/api/admin/fuel-logs", requireAdmin, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("machine_fuel_logs").select("*, driver_profiles(full_name)").order("timestamp", { ascending: false }).limit(1000); if (error) return res.status(400).json({ error: error.message }); res.json({ data: data || [] });
});
app.get("/api/admin/vehicle-problems", requireAdmin, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("vehicle_problems").select("*, driver_profiles(full_name), vehicles(registration_number,vehicle_name)").order("created_at", { ascending: false }).limit(1000); if (error) return res.status(400).json({ error: error.message }); res.json({ data: data || [] });
});
app.get("/api/admin/photo/*path", requireAdmin, async (req, res) => {
  const objectPath = Array.isArray(req.params.path) ? req.params.path.join("/") : req.params.path;
  const { data, error } = await supabaseAdmin.storage.from("shop-photos").createSignedUrl(objectPath, 300); if (error) return res.status(404).json({ error: "Photo unavailable" }); res.json({ url: data.signedUrl });
});

app.get("/api/driver/me", requireDriver, async (req, res) => {
  const { data: assignment } = await supabaseAdmin.from("driver_vehicle_assignments").select("vehicle_id,assigned_at,vehicles(*)").eq("driver_id", req.user.id).maybeSingle();
  res.json({ driver: req.driver, vehicle: assignment?.vehicles || null, assigned_at: assignment?.assigned_at || null });
});
app.get("/api/driver/fuel-logs", requireDriver, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("machine_fuel_logs").select("*").eq("driver_id", req.user.id).order("timestamp", { ascending: false }).limit(100); if (error) return res.status(400).json({ error: error.message }); res.json({ data: data || [] });
});
app.get("/api/driver/problems", requireDriver, async (req, res) => {
  const { data, error } = await supabaseAdmin.from("vehicle_problems").select("*, vehicles(registration_number,vehicle_name)").eq("driver_id", req.user.id).order("created_at", { ascending: false }).limit(100); if (error) return res.status(400).json({ error: error.message }); res.json({ data: data || [] });
});
app.post("/api/driver/fuel-log", requireDriver, async (req, res) => {
  try {
    const b = req.body || {}, required = ["shop_name","latitude","longitude","machine_number","fuel_pumped","machine_calibrated","refill_type"];
    for (const key of required) if (b[key] === undefined || b[key] === null || String(b[key]).trim() === "") return res.status(400).json({ error: `Missing ${key.replaceAll("_"," ")}.` });
    if (![-1,0,1].includes(0)) {}
    const payload = { driver_id: req.user.id, shop_name: String(b.shop_name).trim(), latitude: Number(b.latitude), longitude: Number(b.longitude), machine_number: String(b.machine_number).trim(), kp_number: String(b.kp_number || "").trim() || null, fuel_pumped: Number(b.fuel_pumped), display_photo_path: b.display_photo_path ? String(b.display_photo_path) : null, email_address: req.user.email, machine_calibrated: b.machine_calibrated === true || b.machine_calibrated === "true", refill_type: ["first_refill","second_refill","custom"].includes(b.refill_type) ? b.refill_type : "custom", comments: String(b.comments || "").trim() || null };
    if (!Number.isFinite(payload.latitude) || !Number.isFinite(payload.longitude) || !Number.isFinite(payload.fuel_pumped)) return res.status(400).json({ error: "Enter valid numeric GPS and fuel values." });
    const { data, error } = await supabaseAdmin.from("machine_fuel_logs").insert(payload).select().single(); if (error) return res.status(400).json({ error: error.message });
    await writeSecurity("driver_fuel_log", req, req.user.id, { fuel_log_id: data.id, shop_name: payload.shop_name }); res.status(201).json({ data });
  } catch (error) { req.log.error({ err: error }, "fuel log failed"); res.status(500).json({ error: "Could not save fuel log." }); }
});
app.post("/api/driver/vehicle-problem", requireDriver, async (req, res) => {
  const b = req.body || {}; if (!String(b.problem || "").trim()) return res.status(400).json({ error: "Describe the vehicle problem." });
  const { data: assignment } = await supabaseAdmin.from("driver_vehicle_assignments").select("vehicle_id").eq("driver_id", req.user.id).maybeSingle();
  const payload = { driver_id: req.user.id, vehicle_id: assignment?.vehicle_id || null, odometer: b.odometer === "" || b.odometer == null ? null : Number(b.odometer), problem: String(b.problem).trim(), issue_resolved: Boolean(b.issue_resolved), comments: String(b.comments || "").trim() || null };
  const { data, error } = await supabaseAdmin.from("vehicle_problems").insert(payload).select().single(); if (error) return res.status(400).json({ error: error.message });
  if (payload.odometer != null && Number.isFinite(payload.odometer) && assignment?.vehicle_id) {
    await supabaseAdmin.from("vehicles").update({ current_odometer: payload.odometer, updated_at: new Date().toISOString() }).eq("id", assignment.vehicle_id);
    await supabaseAdmin.from("vehicle_odometer_logs").insert({ driver_id: req.user.id, vehicle_id: assignment.vehicle_id, odometer: payload.odometer });
  }
  await writeSecurity("vehicle_problem_reported", req, req.user.id, { problem_id: data.id }); res.status(201).json({ data });
});
app.post("/api/driver/odometer", requireDriver, async (req, res) => {
  const value = Number(req.body?.odometer); if (!Number.isFinite(value) || value < 0) return res.status(400).json({ error: "Enter a valid odometer reading." });
  const { data: assignment } = await supabaseAdmin.from("driver_vehicle_assignments").select("vehicle_id").eq("driver_id", req.user.id).maybeSingle(); if (!assignment?.vehicle_id) return res.status(400).json({ error: "No vehicle is assigned to this driver." });
  const { error: vehicleError } = await supabaseAdmin.from("vehicles").update({ current_odometer: value, updated_at: new Date().toISOString() }).eq("id", assignment.vehicle_id); if (vehicleError) return res.status(400).json({ error: vehicleError.message });
  const { error } = await supabaseAdmin.from("vehicle_odometer_logs").insert({ driver_id: req.user.id, vehicle_id: assignment.vehicle_id, odometer: value }); if (error) return res.status(400).json({ error: error.message }); res.json({ ok: true });
});

app.get("/health", (req, res) => res.json({ ok: true, service: "moto-nzuri-field-ops" }));
app.use((req, res, next) => { if (req.path === "/") return res.sendFile(path.join(publicDir, "index.html")); next(); });
app.use((req, res) => res.status(404).json({ error: "Not found" }));
app.use((err, req, res, next) => { req.log?.error({ err }, "Unhandled error"); res.status(500).json({ error: "Internal server error" }); });
app.listen(PORT, () => log.info({ port: PORT, adminPath: ADMIN_PATH, driverPath: DRIVER_PATH, representativePath: REPRESENTATIVE_PATH }, "Moto Nzuri Field Ops running"));
