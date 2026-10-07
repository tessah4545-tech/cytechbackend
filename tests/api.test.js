/* Isolated tests: Paystack HTTPS calls are mocked; no STK, money or production DB is touched. */
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict"),
  fs = require("fs"),
  os = require("os"),
  path = require("path"),
  crypto = require("crypto");
const https = require("https"),
  { EventEmitter } = require("events"),
  { spawn } = require("child_process");
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cytech-tests-"));
process.env.NODE_ENV = "test";
process.env.DATA_DIR = dir;
process.env.DATABASE_URL = "";
process.env.JWT_SECRET = "isolated-test-secret-at-least-32-characters";
process.env.ADMIN_EMAIL = "admin@example.test";
process.env.ADMIN_PASSWORD = "TestAdminPassword!2026";
process.env.PAYSTACK_SECRET_KEY = "sk_test_isolated_fake_not_real";
process.env.PORT = "0";
process.env.ALLOWED_ORIGINS = "http://localhost:3000";
let gatewayMode = "pending",
  captured = [],
  base,
  server,
  user,
  other,
  admin;
const originalRequest = https.request;
https.request = (opts, callback) => {
  const req = new EventEmitter();
  let raw = "";
  req.setTimeout = () => req;
  req.write = (d) => (raw += d);
  req.destroy = (e) => req.emit("error", e);
  req.end = () => {
    const body = raw ? JSON.parse(raw) : {};
    captured.push({ path: opts.path, body });
    const response = new EventEmitter();
    response.statusCode = 200;
    process.nextTick(() => {
      callback(response);
      let result;
      if (opts.path === "/charge")
        result = {
          status: true,
          data: { status: "pay_offline", reference: body.reference },
        };
      else if (opts.path === "/transaction/initialize")
        result = {
          status: true,
          data: {
            reference: body.reference,
            authorization_url: "https://checkout.paystack.com/test-only",
          },
        };
      else {
        const reference = decodeURIComponent(opts.path.split("/").pop());
        const initiation = captured.find((x) => x.body.reference === reference);
        const t = initiation.body;
        result = {
          status: true,
          data: {
            status: gatewayMode === "wrong-amount" ? "success" : gatewayMode,
            reference,
            amount: gatewayMode === "wrong-amount" ? 1 : t.amount,
            currency: "KES",
            customer: { email: t.email },
          },
        };
      }
      response.emit("data", JSON.stringify(result));
      response.emit("end");
    });
  };
  return req;
};
const api = require("../server");
async function request(p, { method = "GET", token, body, headers = {} } = {}) {
  const r = await fetch(base + p, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: "Bearer " + token } : {}),
      ...headers,
    },
    body:
      typeof body === "string" ? body : body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  return { status: r.status, data, headers: r.headers, text };
}
before(async () => {
  server = await api.start();
  await new Promise((r) =>
    server.listening ? r() : server.once("listening", r),
  );
  base = "http://127.0.0.1:" + server.address().port;
});
after(async () => {
  https.request = originalRequest;
  if (server) await new Promise((r) => server.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});
test("health, allowed CORS and denied cross-origin browser access", async () => {
  const r = await request("/api/health", {
    headers: { Origin: "http://localhost:3000" },
  });
  assert.equal(r.status, 200);
  assert.equal(r.data.ok, true);
  assert.equal(
    r.headers.get("access-control-allow-origin"),
    "http://localhost:3000",
  );
  const denied = await request("/api/health", {
    headers: { Origin: "https://untrusted.example" },
  });
  assert.equal(denied.headers.get("access-control-allow-origin"), null);
});
test("signup validates input and duplicate emails; login succeeds and rejects bad passwords", async () => {
  assert.equal(
    (
      await request("/api/auth/signup", {
        method: "POST",
        body: { name: " ", email: "bad", password: 123456 },
      })
    ).status,
    400,
  );
  const r = await request("/api/auth/signup", {
    method: "POST",
    body: {
      name: "Learner",
      email: "Learner@Example.test ",
      password: "CorrectPassword123",
    },
  });
  assert.equal(r.status, 201);
  user = r.data;
  assert.ok(user.token);
  assert.equal(user.user.email, "learner@example.test");
  assert.equal(user.user.pass, undefined);
  assert.equal(
    (
      await request("/api/auth/signup", {
        method: "POST",
        body: {
          name: "Same",
          email: "learner@example.test",
          password: "CorrectPassword123",
        },
      })
    ).status,
    409,
  );
  assert.equal(
    (
      await request("/api/auth/login", {
        method: "POST",
        body: { email: "learner@example.test", password: "wrong-password" },
      })
    ).status,
    401,
  );
  assert.equal(
    (
      await request("/api/auth/login", {
        method: "POST",
        body: { email: "LEARNER@example.test", password: "CorrectPassword123" },
      })
    ).status,
    200,
  );
  other = (
    await request("/api/auth/signup", {
      method: "POST",
      body: {
        name: "Other",
        email: "other@example.test",
        password: "OtherPassword123",
      },
    })
  ).data;
});
test("account authentication and admin RBAC", async () => {
  assert.equal((await request("/api/me")).status, 401);
  assert.equal(
    (await request("/api/admin/overview", { token: user.token })).status,
    403,
  );
  admin = (
    await request("/api/admin/login", {
      method: "POST",
      body: { email: "admin@example.test", password: "TestAdminPassword!2026" },
    })
  ).data;
  assert.ok(admin.token);
  assert.equal(
    (await request("/api/admin/overview", { token: admin.token })).status,
    200,
  );
  assert.deepEqual(
    (await request("/api/me", { token: user.token })).data.entitlements,
    [],
  );
});
test("phone normalization and payment field integrity", () => {
  assert.equal(api.normalizePhone("0712345678"), "254712345678");
  assert.equal(api.normalizePhone("0112345678"), "254112345678");
  assert.equal(api.normalizePhone("+254 712 345 678"), "254712345678");
  assert.equal(api.normalizePhone("12345"), null);
  const t = { reference: "REF", email: "a@example.test", amount: 30 };
  assert.equal(
    api.paymentMatches(t, {
      reference: "REF",
      status: "success",
      amount: 3000,
      currency: "KES",
      customer: { email: "a@example.test" },
    }),
    true,
  );
  assert.equal(
    api.paymentMatches(t, {
      reference: "REF",
      status: "success",
      amount: 30,
      currency: "KES",
      customer: { email: "a@example.test" },
    }),
    false,
  );
});
let noteRef, practicalRef, courseRef;
test("KES 30 requires one valid PDF, charges 3000 subunits and pending does not unlock", async () => {
  assert.equal(
    (
      await request("/api/pay/init", {
        method: "POST",
        token: user.token,
        body: { purpose: "notes", phone: "0712345678" },
      })
    ).status,
    400,
  );
  const r = await request("/api/pay/init", {
    method: "POST",
    token: user.token,
    body: { purpose: "notes", noteId: "ethical-hacking", phone: "0712345678" },
  });
  assert.equal(r.status, 200);
  assert.equal(r.data.status, "pending");
  noteRef = r.data.reference;
  const call = captured.find((x) => x.path === "/charge");
  assert.equal(call.body.amount, 3000);
  assert.equal(call.body.mobile_money.provider, "mpesa");
  assert.equal(call.body.mobile_money.phone, "+254712345678");
  assert.equal(call.body.metadata.noteId, "ethical-hacking");
  assert.equal(
    (
      await request("/api/notes/ethical-hacking/download", {
        token: user.token,
      })
    ).status,
    403,
  );
  assert.equal(
    (await request("/api/pay/verify/" + noteRef, { token: user.token })).data
      .status,
    "pending",
  );
  assert.equal(
    (await request("/api/pay/verify/" + noteRef, { token: other.token }))
      .status,
    404,
  );
});
test("pending duplicate is reused rather than sending a second STK request", async () => {
  const count = captured.filter((x) => x.path === "/charge").length;
  const r = await request("/api/pay/init", {
    method: "POST",
    token: user.token,
    body: { purpose: "notes", noteId: "ethical-hacking", phone: "0712345678" },
  });
  assert.equal(r.data.reference, noteRef);
  assert.equal(captured.filter((x) => x.path === "/charge").length, count);
});
test("wrong payment amount does not unlock; correct payment unlocks only purchased PDF", async () => {
  gatewayMode = "wrong-amount";
  assert.equal(
    (await request("/api/pay/verify/" + noteRef, { token: user.token })).status,
    409,
  );
  assert.deepEqual(
    (await request("/api/me", { token: user.token })).data.entitlements,
    [],
  );
  gatewayMode = "success";
  assert.equal(
    (await request("/api/pay/verify/" + noteRef, { token: user.token })).data
      .status,
    "success",
  );
  assert.deepEqual(
    (await request("/api/me", { token: user.token })).data.entitlements,
    ["notes:ethical-hacking"],
  );
  const pdf = await request("/api/notes/ethical-hacking/download", {
    token: user.token,
  });
  assert.equal(pdf.status, 200);
  assert.ok(pdf.headers.get("content-type").includes("pdf"));
  assert.ok(pdf.text.startsWith("%PDF"));
  assert.equal(
    (
      await request("/api/notes/network-security/download", {
        token: user.token,
      })
    ).status,
    403,
  );
  assert.equal((await request("/notes/ethical-hacking.pdf")).status, 403);
  assert.equal(
    (await request("/api/notes/ethical-hacking/download")).status,
    401,
  );
});
test("KES 100 practical access: authentic raw-byte signed webhook grants once", async () => {
  gatewayMode = "pending";
  const r = await request("/api/pay/init", {
    method: "POST",
    token: user.token,
    body: { purpose: "practicals", phone: "0712345678" },
  });
  practicalRef = r.data.reference;
  assert.equal(
    captured.find((x) => x.body.reference === practicalRef).body.amount,
    10000,
  );
  const event = {
    event: "charge.success",
    data: {
      reference: practicalRef,
      status: "success",
      amount: 10000,
      currency: "KES",
      customer: { email: user.user.email },
    },
  };
  const raw = JSON.stringify(event, null, 2);
  assert.equal(
    (
      await request("/api/pay/webhook", {
        method: "POST",
        body: raw,
        headers: { "x-paystack-signature": "0".repeat(128) },
      })
    ).status,
    401,
  );
  const signature = crypto
    .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
    .update(raw)
    .digest("hex");
  assert.equal(
    (
      await request("/api/pay/webhook", {
        method: "POST",
        body: raw,
        headers: { "x-paystack-signature": signature },
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await request("/api/pay/webhook", {
        method: "POST",
        body: raw,
        headers: { "x-paystack-signature": signature },
      })
    ).status,
    200,
  );
  const me = (await request("/api/me", { token: user.token })).data;
  assert.ok(me.entitlements.includes("practicals"));
  assert.ok(me.practicalUrl);
  const ov = (await request("/api/admin/overview", { token: admin.token }))
    .data;
  assert.equal(ov.wallet.total, 130);
});
test("course checkout verification creates exactly one application; admin can update and message it", async () => {
  const r = await request("/api/pay/init", {
    method: "POST",
    token: user.token,
    body: { purpose: "course", method: "checkout" },
  });
  courseRef = r.data.reference;
  assert.ok(r.data.authorization_url);
  assert.equal(
    captured.find((x) => x.body.reference === courseRef).body.amount,
    200000,
  );
  gatewayMode = "success";
  await request("/api/pay/verify/" + courseRef, { token: user.token });
  await request("/api/pay/verify/" + courseRef, { token: user.token });
  const me = (await request("/api/me", { token: user.token })).data;
  assert.equal(me.application.status, "registered");
  assert.equal(
    (
      await request("/api/admin/applications/" + me.application.id, {
        method: "POST",
        token: admin.token,
        body: { status: "accepted" },
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await request("/api/admin/message", {
        method: "POST",
        token: admin.token,
        body: { message: "Classes begin Monday", audience: "applicants" },
      })
    ).status,
    200,
  );
  assert.equal(
    (await request("/api/messages", { token: user.token })).data[0].message,
    "Classes begin Monday",
  );
  assert.equal(
    (await request("/api/messages", { token: other.token })).data.length,
    0,
  );
  assert.equal(
    (await request("/api/admin/overview", { token: admin.token })).data
      .applications.length,
    1,
  );
});
test("admin URL validation, snapshots, no fake installers and honest reset errors", async () => {
  assert.equal(
    (
      await request("/api/admin/settings", {
        method: "POST",
        token: admin.token,
        body: { practicalUrl: "javascript:alert(1)" },
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await request("/api/admin/settings", {
        method: "POST",
        token: admin.token,
        body: {
          practicalUrl: "https://example.test",
          adminNote: "Updated venue",
        },
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await request("/api/admin/backup", {
        method: "POST",
        token: admin.token,
        body: {},
      })
    ).data.ok,
    true,
  );
  assert.equal((await request("/api/downloads")).data.installable, true);
  assert.equal((await request("/downloads/cytech-android.txt")).status, 410);
  assert.equal(
    (
      await request("/api/auth/forgot", {
        method: "POST",
        body: { email: user.user.email },
      })
    ).status,
    503,
  );
  const db = JSON.parse(fs.readFileSync(path.join(dir, "db.json")));
  assert.equal(db.users.length, 3);
  assert.equal(db.transactions.length, 3);
  assert.equal(
    db.transactions.every((t) => t.status === "success"),
    true,
  );
});
test("missing gateway refuses free demo unlocks in separate isolated server", async () => {
  const childDir = fs.mkdtempSync(path.join(os.tmpdir(), "cytech-no-gateway-"));
  const child = spawn(process.execPath, ["server.js"], {
    cwd: path.join(__dirname, ".."),
    env: {
      ...process.env,
      DATA_DIR: childDir,
      PORT: "0",
      PAYSTACK_SECRET_KEY: "",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  const url = await new Promise((resolve, reject) => {
    child.stdout.on("data", (buf) => {
      output += buf;
      const match = /listening on (\d+)/.exec(output);
      if (match) resolve("http://127.0.0.1:" + match[1]);
    });
    child.once("error", reject);
  });
  try {
    const login = await fetch(url + "/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "admin@example.test",
        password: "TestAdminPassword!2026",
      }),
    }).then((r) => r.json());
    const r = await fetch(url + "/api/pay/init", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + login.token,
      },
      body: JSON.stringify({
        purpose: "notes",
        noteId: "dfir",
        phone: "0712345678",
      }),
    });
    assert.equal(r.status, 503);
    const me = await fetch(url + "/api/me", {
      headers: { Authorization: "Bearer " + login.token },
    }).then((r) => r.json());
    assert.deepEqual(me.entitlements, []);
  } finally {
    child.kill();
    await new Promise((r) => child.once("exit", r));
    fs.rmSync(childDir, { recursive: true, force: true });
  }
});
