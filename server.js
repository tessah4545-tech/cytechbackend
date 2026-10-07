/* CyTech API: preserves existing routes, verifies payments before granting access. */
require("dotenv").config();
const express = require("express"),
  cors = require("cors"),
  helmet = require("helmet");
const rateLimit = require("express-rate-limit"),
  bcrypt = require("bcryptjs"),
  jwt = require("jsonwebtoken");
const crypto = require("crypto"),
  https = require("https"),
  fs = require("fs"),
  path = require("path");
const { Pool } = require("pg");
const production = process.env.NODE_ENV === "production";
const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(48).toString("hex");
const SECRET = process.env.PAYSTACK_SECRET_KEY || "";
const ADMIN_PATH = process.env.ADMIN_PATH || "cytech-admin-x9k2";
const PRICE_KES = { notes: 30, practicals: 100, course: 2000 };
const NOTE_IDS = [
  "cybersecurity-foundations",
  "ethical-hacking",
  "reverse-engineering",
  "network-security",
  "linux-security-tools",
  "dfir",
];
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
fs.mkdirSync(DATA_DIR, { recursive: true });
let mem = {
  users: [],
  transactions: [],
  applications: [],
  messages: [],
  settings: {},
  resets: [],
};
let pgReady = false;
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl:
        process.env.PG_SSL === "false"
          ? false
          : { rejectUnauthorized: process.env.PG_SSL_VERIFY === "true" },
      max: 5,
    })
  : null;
let flushQueue = Promise.resolve();
function persist() {
  const payload = JSON.stringify(mem);
  const operation = flushQueue
    .catch(() => {})
    .then(async () => {
      if (pool) {
        await pool.query(
          "INSERT INTO kvstore (id,payload,updated_at) VALUES ('main',$1,now()) ON CONFLICT (id) DO UPDATE SET payload=$1,updated_at=now()",
          [payload],
        );
        pgReady = true;
      } else if (production) throw new Error("Persistent database is required");
      fs.writeFileSync(DB_FILE + ".tmp", payload, { mode: 0o600 });
      fs.renameSync(DB_FILE + ".tmp", DB_FILE);
    });
  flushQueue = operation;
  return operation;
}
async function initialize() {
  if (
    production &&
    (!process.env.JWT_SECRET || JWT_SECRET.length < 32 || !pool)
  )
    throw new Error(
      "Production requires DATABASE_URL and a JWT_SECRET of at least 32 characters",
    );
  if (pool) {
    await pool.query(
      "CREATE TABLE IF NOT EXISTS kvstore (id TEXT PRIMARY KEY,payload JSONB,updated_at TIMESTAMPTZ DEFAULT now())",
    );
    const r = await pool.query("SELECT payload FROM kvstore WHERE id='main'");
    if (r.rows.length) mem = r.rows[0].payload;
    else if (fs.existsSync(DB_FILE))
      mem = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    pgReady = true;
  } else if (fs.existsSync(DB_FILE))
    mem = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  for (const k of [
    "users",
    "transactions",
    "applications",
    "messages",
    "resets",
  ])
    if (!Array.isArray(mem[k])) mem[k] = [];
  mem.settings = mem.settings || {};
  const email = (process.env.ADMIN_EMAIL || "").trim().toLowerCase(),
    password = process.env.ADMIN_PASSWORD || "";
  if (email && password) {
    if (
      !/^\S+@\S+\.\S+$/.test(email) ||
      password.length < 12 ||
      password.length > 128
    )
      throw new Error(
        "Configure a valid ADMIN_EMAIL and a 12–128 character ADMIN_PASSWORD",
      );
    const existing = mem.users.find((u) => u.email === email);
    if (existing && existing.role !== "admin")
      throw new Error(
        "Configured ADMIN_EMAIL belongs to a non-admin account; refusing automatic privilege escalation",
      );
    if (!existing)
      mem.users.push({
        id: uid(),
        name: "Administrator",
        email,
        pass: await bcrypt.hash(password, 12),
        role: "admin",
        createdAt: Date.now(),
      });
    else if (!(await bcrypt.compare(password, existing.pass)))
      existing.pass = await bcrypt.hash(password, 12);
  }
  if (!mem.settings.practicalUrl)
    mem.settings.practicalUrl = "http://testphp.vulnweb.com";
  if (!mem.settings.adminNote)
    mem.settings.adminNote =
      "Welcome to CyTech. Please contact the administrator for confirmed class times and venue.";
  await persist();
}
const uid = () => crypto.randomBytes(12).toString("hex");
const safeUser = (u) => ({
  id: u.id,
  name: u.name,
  email: u.email,
  role: u.role,
});
const sign = (u) =>
  jwt.sign({ id: u.id, email: u.email, role: u.role || "user" }, JWT_SECRET, {
    expiresIn: "7d",
    algorithm: "HS256",
  });
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(
  helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }),
);
const ALLOWED = (
  process.env.ALLOWED_ORIGINS || "http://localhost:3000,http://127.0.0.1:3000"
)
  .split(",")
  .map((s) => s.trim());
app.use(
  cors({
    origin: (origin, cb) => cb(null, !origin || ALLOWED.includes(origin)),
  }),
);
app.use(
  express.json({
    limit: "1mb",
    verify: (req, res, buf) => {
      if (req.path === "/api/pay/webhook") req.rawBody = buf;
    },
  }),
);
app.use(
  "/api/",
  rateLimit({
    windowMs: 15 * 60e3,
    max: 600,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests. Please wait and retry." },
    skip: (req) => req.path === "/pay/webhook",
  }),
);
const authLimiter = rateLimit({
  windowMs: 15 * 60e3,
  max: 30,
  message: {
    error: "Too many authentication attempts. Please wait and retry.",
  },
});
const paymentLimiter = rateLimit({
  windowMs: 60e3,
  max: 6,
  message: { error: "Too many payment attempts. Please wait a minute." },
});
const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);
function auth(req, res, next) {
  try {
    const match = /^Bearer (.+)$/.exec(req.headers.authorization || "");
    if (!match) throw Error();
    const token = jwt.verify(match[1], JWT_SECRET, { algorithms: ["HS256"] });
    const u = mem.users.find((x) => x.id === token.id);
    if (!u) throw Error();
    req.user = safeUser(u);
    next();
  } catch {
    res.status(401).json({ error: "Session expired. Please log in again." });
  }
}
function adminOnly(req, res, next) {
  if (req.user.role === "admin") return next();
  res.status(403).json({ error: "Administrator access required" });
}
function entitlements(id) {
  return [
    ...new Set(
      mem.transactions
        .filter((t) => t.userId === id && t.status === "success")
        .map((t) =>
          t.purpose === "notes"
            ? t.noteId
              ? "notes:" + t.noteId
              : null
            : t.purpose,
        )
        .filter(Boolean),
    ),
  ];
}
// Serialize mutating requests: KV persistence is designed for a single API instance.
let mutationQueue = Promise.resolve();
app.use("/api/", (req, res, next) => {
  if (
    (req.method === "GET" && !req.path.startsWith("/pay/verify/")) ||
    req.method === "OPTIONS"
  )
    return next();
  let release;
  const done = new Promise((r) => (release = r)),
    previous = mutationQueue;
  mutationQueue = previous.then(() => done);
  previous.then(() => {
    req.storeBefore = JSON.stringify(mem);
    res.once("finish", release);
    res.once("close", release);
    next();
  });
});
app.post(
  "/api/auth/signup",
  authLimiter,
  wrap(async (req, res) => {
    const { name, email, password } = req.body || {};
    const e = typeof email === "string" ? email.trim().toLowerCase() : "";
    if (
      typeof name !== "string" ||
      !name.trim() ||
      !/^\S+@\S+\.\S+$/.test(e) ||
      e.length > 254 ||
      typeof password !== "string" ||
      password.length < 6 ||
      password.length > 128
    )
      return res
        .status(400)
        .json({
          error:
            "Enter a name, valid email and a password of 6–128 characters.",
        });
    if (mem.users.some((u) => u.email === e))
      return res
        .status(409)
        .json({ error: "Email already registered. Please log in." });
    const u = {
      id: uid(),
      name: name.trim().slice(0, 60),
      email: e,
      pass: await bcrypt.hash(password, 12),
      role: "user",
      createdAt: Date.now(),
    };
    mem.users.push(u);
    await persist();
    res.status(201).json({ token: sign(u), user: safeUser(u) });
  }),
);
async function login(req, res, admin = false) {
  const { email, password } = req.body || {};
  const e = typeof email === "string" ? email.trim().toLowerCase() : "";
  const u = mem.users.find(
    (x) => x.email === e && (!admin || x.role === "admin"),
  );
  if (
    typeof password !== "string" ||
    password.length > 128 ||
    !u ||
    !(await bcrypt.compare(password, u.pass))
  )
    return res.status(401).json({ error: "Invalid email or password" });
  res.json({ token: sign(u), user: safeUser(u) });
}
app.post(
  "/api/auth/login",
  authLimiter,
  wrap((req, res) => login(req, res)),
);
app.post(
  "/api/admin/login",
  authLimiter,
  wrap((req, res) => login(req, res, true)),
);
app.post("/api/auth/forgot", authLimiter, (req, res) =>
  res
    .status(503)
    .json({
      error:
        "Email password reset is not configured. Please contact the administrator. No reset email has been sent.",
    }),
);
app.post(
  "/api/auth/reset",
  authLimiter,
  wrap(async (req, res) => {
    const { token, password } = req.body || {};
    const r = mem.resets.find((x) => x.token === token && x.exp > Date.now());
    if (
      !r ||
      typeof password !== "string" ||
      password.length < 6 ||
      password.length > 128
    )
      return res
        .status(400)
        .json({ error: "Invalid or expired reset token / password" });
    const u = mem.users.find((x) => x.id === r.userId);
    if (!u) return res.status(400).json({ error: "Invalid reset token" });
    u.pass = await bcrypt.hash(password, 12);
    mem.resets = mem.resets.filter((x) => x !== r);
    await persist();
    res.json({ ok: true });
  }),
);
app.get("/api/me", auth, (req, res) => {
  const paid = entitlements(req.user.id),
    application = mem.applications.find((a) => a.userId === req.user.id);
  res
    .set("Cache-Control", "no-store")
    .json({
      user: req.user,
      entitlements: paid,
      application,
      adminNote: application ? mem.settings.adminNote : undefined,
      practicalUrl: paid.includes("practicals")
        ? mem.settings.practicalUrl
        : undefined,
    });
});
function paystack(route, method, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const request = https.request(
      {
        hostname: "api.paystack.co",
        path: route,
        method,
        headers: {
          Authorization: "Bearer " + SECRET,
          "Content-Type": "application/json",
          ...(data ? { "Content-Length": Buffer.byteLength(data) } : {}),
        },
      },
      (response) => {
        let text = "";
        response.on("data", (c) => (text += c));
        response.on("end", () => {
          try {
            resolve(JSON.parse(text));
          } catch {
            reject(new Error("Invalid gateway response"));
          }
        });
      },
    );
    request.setTimeout(20000, () =>
      request.destroy(new Error("Gateway request timed out")),
    );
    request.on("error", reject);
    if (data) request.write(data);
    request.end();
  });
}
function normalizePhone(value) {
  let p = String(value || "").replace(/[\s()+-]/g, "");
  if (/^0[17]\d{8}$/.test(p)) p = "254" + p.slice(1);
  if (/^[17]\d{8}$/.test(p)) p = "254" + p;
  return /^254[17]\d{8}$/.test(p) ? p : null;
}
function paymentMatches(t, d) {
  return (
    !!d &&
    d.status === "success" &&
    d.reference === t.reference &&
    Number(d.amount) === t.amount * 100 &&
    d.currency === "KES" &&
    String((d.customer && d.customer.email) || "").toLowerCase() ===
      t.email.toLowerCase()
  );
}
function grant(t) {
  t.status = "success";
  t.verifiedAt = Date.now();
  if (
    t.purpose === "course" &&
    !mem.applications.some((a) => a.userId === t.userId)
  )
    mem.applications.push({
      id: uid(),
      userId: t.userId,
      email: t.email,
      status: "registered",
      createdAt: Date.now(),
    });
}
app.get("/api/pay/config", (req, res) =>
  res.json({
    publicKey: process.env.PAYSTACK_PUBLIC_KEY || "",
    configured: !!SECRET,
    mode: SECRET.startsWith("sk_live_") ? "live" : "test",
    prices: PRICE_KES,
    currency: "KES",
  }),
);
app.post(
  "/api/pay/init",
  auth,
  paymentLimiter,
  wrap(async (req, res) => {
    const { purpose, noteId, phone, method = "mpesa" } = req.body || {};
    if (!Object.prototype.hasOwnProperty.call(PRICE_KES, purpose))
      return res.status(400).json({ error: "Invalid payment purpose" });
    if (purpose === "notes" && !NOTE_IDS.includes(noteId))
      return res
        .status(400)
        .json({ error: "Select one valid PDF. KES 30 unlocks only that PDF." });
    if (!["mpesa", "checkout"].includes(method))
      return res.status(400).json({ error: "Invalid payment method" });
    if (!SECRET)
      return res
        .status(503)
        .json({
          error:
            "Payment gateway not configured. No payment or access has been granted.",
        });
    const normalized = normalizePhone(phone);
    if (method === "mpesa" && !normalized)
      return res
        .status(400)
        .json({
          error:
            "Enter a valid Kenyan M-PESA number, e.g. 07xxxxxxxx or 01xxxxxxxx.",
        });
    const entitlement = purpose === "notes" ? "notes:" + noteId : purpose;
    if (entitlements(req.user.id).includes(entitlement))
      return res
        .status(409)
        .json({
          error:
            "You already own this item. Reopen it to access your purchase.",
        });
    const recent = mem.transactions.find(
      (t) =>
        t.userId === req.user.id &&
        t.purpose === purpose &&
        t.noteId === (purpose === "notes" ? noteId : undefined) &&
        t.status === "pending" &&
        Date.now() - t.createdAt < 180e3,
    );
    if (recent)
      return res.json({
        reference: recent.reference,
        status: "pending",
        authorization_url: recent.authorizationUrl,
        message:
          "A payment is already pending. Complete or verify it before retrying.",
      });
    const t = {
      id: uid(),
      reference: "CYT-" + uid().toUpperCase(),
      userId: req.user.id,
      email: req.user.email,
      purpose,
      ...(purpose === "notes" ? { noteId } : {}),
      amount: PRICE_KES[purpose],
      status: "pending",
      createdAt: Date.now(),
    };
    mem.transactions.push(t);
    await persist();
    try {
      const payload = {
        email: t.email,
        amount: t.amount * 100,
        currency: "KES",
        reference: t.reference,
        metadata: {
          purpose,
          userId: t.userId,
          ...(t.noteId ? { noteId: t.noteId } : {}),
        },
      };
      if (method === "mpesa")
        payload.mobile_money = { phone: "+" + normalized, provider: "mpesa" };
      else payload.channels = ["card", "mobile_money"];
      const r = await paystack(
        method === "mpesa" ? "/charge" : "/transaction/initialize",
        "POST",
        payload,
      );
      if (!r.status || !r.data) {
        t.status = "failed";
        await persist();
        return res
          .status(502)
          .json({
            error: r.message || "Gateway rejected payment. Please retry.",
          });
      }
      if (r.data.reference && r.data.reference !== t.reference) {
        t.status = "failed";
        await persist();
        return res
          .status(502)
          .json({
            error: "Gateway reference mismatch; access has not been granted.",
          });
      }
      if (method === "checkout") t.authorizationUrl = r.data.authorization_url;
      if (r.data.status === "success") {
        if (paymentMatches(t, r.data)) grant(t);
        else {
          const v = await paystack(
            "/transaction/verify/" + encodeURIComponent(t.reference),
            "GET",
          );
          if (v.status && paymentMatches(t, v.data)) grant(t);
        }
      }
      if (["failed", "abandoned"].includes(r.data.status)) t.status = "failed";
      await persist();
      res.json({
        reference: t.reference,
        status: t.status,
        authorization_url: t.authorizationUrl,
        message:
          method === "mpesa"
            ? "Approve the M-PESA request on your phone. Access is granted only after confirmed payment."
            : "Complete secure checkout to confirm payment.",
      });
    } catch (error) {
      t.lastError = "Gateway request unavailable; verify before retrying";
      await persist();
      res
        .status(502)
        .json({
          error:
            "Gateway unavailable or timed out. Check pending payments before retrying.",
          reference: t.reference,
        });
    }
  }),
);
app.get(
  "/api/pay/verify/:reference",
  auth,
  wrap(async (req, res) => {
    const t = mem.transactions.find(
      (x) => x.reference === req.params.reference && x.userId === req.user.id,
    );
    if (!t) return res.status(404).json({ error: "Transaction not found" });
    if (t.status === "success")
      return res.json({
        status: t.status,
        purpose: t.purpose,
        noteId: t.noteId,
      });
    if (!SECRET)
      return res
        .status(503)
        .json({ error: "Payment verification is not configured" });
    const r = await paystack(
      "/transaction/verify/" + encodeURIComponent(t.reference),
      "GET",
    );
    if (r.status && r.data) {
      if (r.data.status === "success") {
        if (!paymentMatches(t, r.data))
          return res
            .status(409)
            .json({
              error: "Payment details did not match. Access was not granted.",
            });
        grant(t);
      } else if (["failed", "abandoned", "reversed"].includes(r.data.status))
        t.status = "failed";
      else t.status = "pending";
      await persist();
    }
    res.json({ status: t.status, purpose: t.purpose, noteId: t.noteId });
  }),
);
app.post(
  "/api/pay/webhook",
  wrap(async (req, res) => {
    if (!SECRET) return res.sendStatus(503);
    const signature = req.headers["x-paystack-signature"] || "";
    const hash = crypto
      .createHmac("sha512", SECRET)
      .update(req.rawBody || Buffer.alloc(0))
      .digest("hex");
    if (
      !/^[a-f0-9]{128}$/i.test(signature) ||
      !crypto.timingSafeEqual(
        Buffer.from(hash, "hex"),
        Buffer.from(signature, "hex"),
      )
    )
      return res.sendStatus(401);
    const ev = req.body;
    if (ev && ev.event === "charge.success" && ev.data) {
      const t = mem.transactions.find((x) => x.reference === ev.data.reference);
      if (t && t.status !== "success") {
        if (!paymentMatches(t, ev.data))
          return res.status(400).json({ error: "Payment details mismatch" });
        grant(t);
        await persist();
      }
    }
    res.sendStatus(200);
  }),
);
app.get("/api/notes", (req, res) =>
  res.json({
    notes: NOTE_IDS.map((id) => ({ id, price: 30, currency: "KES" })),
  }),
);
app.get("/api/notes/:id/download", auth, (req, res) => {
  const id = req.params.id;
  if (!NOTE_IDS.includes(id))
    return res.status(404).json({ error: "PDF not found" });
  if (
    req.user.role !== "admin" &&
    !entitlements(req.user.id).includes("notes:" + id)
  )
    return res
      .status(403)
      .json({ error: "Purchase this PDF for KES 30 first" });
  res.set("Cache-Control", "private, no-store");
  res.download(path.join(__dirname, "pdf", id + ".pdf"), id + ".pdf");
});
app.get("/notes/:file", (req, res) =>
  res
    .status(403)
    .json({
      error:
        "PDF downloads require authentication and purchase. Use the Notes Vault.",
    }),
);
app.get("/api/downloads", (req, res) => {
  const urls = {};
  for (const p of ["android", "ios", "windows", "mac"]) {
    const u = process.env["APP_" + p.toUpperCase() + "_URL"];
    if (u && /^https:\/\//.test(u)) urls[p] = u;
  }
  res.json({
    native: urls,
    webApp:
      process.env.FRONTEND_URL || "https://cytech-frontend-frontend.vercel.app",
    installable: true,
  });
});
app.get("/downloads/:file", (req, res) =>
  res
    .status(410)
    .json({
      error:
        "Placeholder installers have been removed. Install the web app from the CyTech app menu, or use a published native build.",
    }),
);
app.get("/api/config/public", (req, res) =>
  res.json({ practicalUrl: null, prices: PRICE_KES }),
);
app.get("/api/admin/overview", auth, adminOnly, (req, res) => {
  const tx = mem.transactions.slice().sort((a, b) => b.createdAt - a.createdAt);
  res
    .set("Cache-Control", "no-store")
    .json({
      wallet: {
        total: tx
          .filter((t) => t.status === "success")
          .reduce((s, t) => s + t.amount, 0),
        success: tx.filter((t) => t.status === "success"),
        pending: tx.filter((t) => t.status === "pending"),
        failed: tx.filter((t) => t.status === "failed"),
      },
      users: mem.users.map((u) => ({ ...safeUser(u), createdAt: u.createdAt })),
      applications: mem.applications,
      settings: mem.settings,
      db: { neon: pgReady, users: mem.users.length, txns: tx.length },
      gateway: {
        configured: !!SECRET,
        mode: SECRET.startsWith("sk_live_") ? "live" : "test",
      },
      legacyNotesPayments: tx.filter(
        (t) => t.purpose === "notes" && t.status === "success" && !t.noteId,
      ).length,
    });
});
app.post(
  "/api/admin/settings",
  auth,
  adminOnly,
  wrap(async (req, res) => {
    const { practicalUrl, adminNote } = req.body || {};
    if (practicalUrl !== undefined) {
      try {
        const u = new URL(practicalUrl);
        if (
          !["http:", "https:"].includes(u.protocol) ||
          String(practicalUrl).length > 500
        )
          throw Error();
      } catch {
        return res
          .status(400)
          .json({ error: "A valid HTTP(S) lab URL is required" });
      }
      mem.settings.practicalUrl = String(practicalUrl);
    }
    if (adminNote !== undefined)
      mem.settings.adminNote = String(adminNote).slice(0, 5000);
    await persist();
    res.json({ ok: true, settings: mem.settings });
  }),
);
app.post(
  "/api/admin/message",
  auth,
  adminOnly,
  wrap(async (req, res) => {
    const { userId, message, audience = "all" } = req.body || {};
    if (typeof message !== "string" || !message.trim())
      return res.status(400).json({ error: "Message required" });
    if (userId && !mem.users.some((u) => u.id === userId))
      return res.status(400).json({ error: "User not found" });
    if (!["all", "applicants"].includes(audience))
      return res.status(400).json({ error: "Invalid audience" });
    mem.messages.push({
      id: uid(),
      userId: userId || null,
      audience,
      message: message.trim().slice(0, 2000),
      createdAt: Date.now(),
    });
    await persist();
    res.json({ ok: true });
  }),
);
app.get("/api/messages", auth, (req, res) => {
  const applicant = mem.applications.some((a) => a.userId === req.user.id);
  res.json(
    mem.messages
      .filter(
        (m) =>
          (!m.userId || m.userId === req.user.id) &&
          (m.audience !== "applicants" || applicant),
      )
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, 20),
  );
});
app.post(
  "/api/admin/applications/:id",
  auth,
  adminOnly,
  wrap(async (req, res) => {
    const a = mem.applications.find((a) => a.id === req.params.id);
    if (!a) return res.status(404).json({ error: "Application not found" });
    if (
      !["registered", "accepted", "completed", "cancelled"].includes(
        req.body.status,
      )
    )
      return res.status(400).json({ error: "Invalid application status" });
    a.status = req.body.status;
    await persist();
    res.json({ ok: true, application: a });
  }),
);
app.post(
  "/api/admin/backup",
  auth,
  adminOnly,
  wrap(async (req, res) => {
    await persist();
    res.json({ ok: true, neon: pgReady });
  }),
);
app.get("/api/health", (req, res) =>
  res.json({ ok: true, neon: pgReady, time: Date.now() }),
);
app.use("/" + ADMIN_PATH, express.static(path.join(__dirname, "public")));
app.get("/", (req, res) =>
  res.json({ service: "CyTech API", status: "online" }),
);
app.use((req, res) => res.status(404).json({ error: "Endpoint not found" }));
app.use((err, req, res, next) => {
  console.error("[api]", err.message);
  if (req.storeBefore) mem = JSON.parse(req.storeBefore);
  if (res.headersSent) return next(err);
  res
    .status(err.type === "entity.parse.failed" ? 400 : 503)
    .json({
      error:
        err.type === "entity.parse.failed"
          ? "Invalid JSON request"
          : "Service unavailable. Please retry; access has not been granted.",
    });
});
let server;
async function start() {
  await initialize();
  server = app.listen(process.env.PORT || 10000, () =>
    console.log("CyTech API listening on", server.address().port),
  );
  return server;
}
if (require.main === module)
  start().catch((e) => {
    console.error("[startup]", e.message);
    process.exitCode = 1;
    if (pool) pool.end();
  });
module.exports = { app, start, initialize, normalizePhone, paymentMatches };
