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
  try{const b=req.body||{};if(!String(b.issue_description||'').trim())return res.status(400).json({error:'Issue description is required.'});const payload=ticketPayload(b);payload.issue_description=String(b.issue_description).trim();payload.created_by=req.user.id;if(payload.assigned_representative_id||payload.assigned_technician_id){payload.assigned_by=req.user.id;payload.assigned_at=new Date().toISOString();if(!payload.status||payload.status==='Not resolved')payload.status='Assigned';}
    const {data,error}=await supabaseAdmin.from('customer_care_tickets').insert(payload).select().single();if(error)return res.status(400).json({error:error.message});await writeSecurity('customer_care_ticket_created',req,req.user.id,{ticket_no:data.ticket_no});res.status(201).json({data});
  }catch(e){res.status(400).json({error:e.message||'Could not create ticket.'});}
});
app.patch('/api/admin/customer-care/:id', requireAdmin, async (req,res)=>{
  try{const {data:current,error:readError}=await supabaseAdmin.from('customer_care_tickets').select('*').eq('id',req.params.id).maybeSingle();if(readError)return res.status(400).json({error:readError.message});if(!current)return res.status(404).json({error:'Ticket not found.'});const payload=ticketPayload(req.body,current);if(req.body?.issue_description!==undefined){payload.issue_description=String(req.body.issue_description||'').trim();if(!payload.issue_description)return res.status(400).json({error:'Issue description is required.'});}payload.updated_at=new Date().toISOString();payload.last_updated_by=req.user.id;if(payload.assigned_representative_id!==undefined||payload.assigned_technician_id!==undefined){payload.assigned_by=req.user.id;payload.assigned_at=new Date().toISOString();if((payload.assigned_representative_id||payload.assigned_technician_id)&&(!payload.status||payload.status==='Not resolved'))payload.status='Assigned';}const {error}=await supabaseAdmin.from('customer_care_tickets').update(payload).eq('id',req.params.id);if(error)return res.status(400).json({error:error.message});await writeSecurity('customer_care_ticket_updated',req,req.user.id,{ticket_id:req.params.id,ticket_no:current.ticket_no});res.json({ok:true});
  }catch(e){res.status(400).json({error:e.message||'Could not update ticket.'});}
});
app.delete('/api/admin/customer-care/:id', requireAdmin, async (req,res)=>{const {data:current}=await supabaseAdmin.from('customer_care_tickets').select('ticket_no').eq('id',req.params.id).maybeSingle();const {error}=await supabaseAdmin.from('customer_care_tickets').delete().eq('id',req.params.id);if(error)return res.status(400).json({error:error.message});await writeSecurity('customer_care_ticket_deleted',req,req.user.id,{ticket_id:req.params.id,ticket_no:current?.ticket_no});res.json({ok:true});});

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
