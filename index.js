
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GMAIL_SEND_URL =
  "https://gmail.googleapis.com/gmail/v1/users/me/messages/send";

const encoder = new TextEncoder();

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;

  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);

  for (let i = 0; i < length; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }

  return diff === 0;
}

function hasHeaderInjection(value) {
  return /[\r\n]/.test(value);
}

function utf8Base64(value) {
  const bytes = encoder.encode(value);
  let binary = "";

  // Chunking avoids exceeding argument/string limits.
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }

  return btoa(binary);
}

function base64url(value) {
  return utf8Base64(value)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function encodeSubject(subject) {
  // RFC 2047 encoded-word: supports Persian and other Unicode subjects.
  return `=?UTF-8?B?${utf8Base64(subject)}?=`;
}

function normalizeEmail(value) {
  return typeof value === "string" ? value.trim() : "";
}

function validateEmail(value) {
  return (
    typeof value === "string" &&
    value.length <= 254 &&
    /^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/.test(value) &&
    !hasHeaderInjection(value)
  );
}

function buildRawEmail({ to, cc, bcc, from, subject, text, html }) {
  const boundary = `alt_${crypto.randomUUID().replace(/-/g, "")}`;

  const headers = [
    `To: ${to}`,
    ...(cc ? [`Cc: ${cc}`] : []),
    ...(bcc ? [`Bcc: ${bcc}`] : []),
    ...(from ? [`From: ${from}`] : []),
    `Subject: ${encodeSubject(subject)}`,
    "MIME-Version: 1.0",
  ];

  if (html) {
    headers.push(`Content-Type: multipart/alternative; boundary="${boundary}"`);

    const body = [
      `--${boundary}`,
      'Content-Type: text/plain; charset="UTF-8"',
      "Content-Transfer-Encoding: base64",
      "",
      utf8Base64(text || ""),
      `--${boundary}`,
      'Content-Type: text/html; charset="UTF-8"',
      "Content-Transfer-Encoding: base64",
      "",
      utf8Base64(html),
      `--${boundary}--`,
      "",
    ].join("\r\n");

    return `${headers.join("\r\n")}\r\n\r\n${body}`;
  }

  headers.push('Content-Type: text/plain; charset="UTF-8"');
  headers.push("Content-Transfer-Encoding: base64");

  return [
    headers.join("\r\n"),
    "",
    utf8Base64(text),
    "",
  ].join("\r\n");
}

async function getAccessToken(env) {
  const params = new URLSearchParams({
    client_id: env.GMAIL_CLIENT_ID,
    client_secret: env.GMAIL_CLIENT_SECRET,
    refresh_token: env.GMAIL_REFRESH_TOKEN,
    grant_type: "refresh_token",
  });

  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params.toString(),
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok || !data.access_token) {
    // Do not expose OAuth credentials or tokens to the caller.
    throw new Error(
      `GOOGLE_TOKEN_ERROR_${response.status}`
    );
  }

  return data.access_token;
}

async function sendGmail(env, message) {
  const accessToken = await getAccessToken(env);

  const raw = base64url(
    buildRawEmail({
      to: message.to,
      cc: message.cc,
      bcc: message.bcc,
      from: message.from,
      subject: message.subject,
      text: message.text,
      html: message.html,
    })
  );

  const response = await fetch(GMAIL_SEND_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ raw }),
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    // Avoid returning provider details that may contain sensitive data.
    throw new Error(`GMAIL_SEND_ERROR_${response.status}`);
  }

  return {
    id: data.id || null,
    threadId: data.threadId || null,
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method !== "POST" || url.pathname !== "/send") {
      return jsonResponse({ error: "Not found" }, 404);
    }

    // Require a separate secret to prevent public email abuse.
    const expectedKey = env.GMAIL_WORKER_API_KEY;
    const suppliedKey = request.headers.get("Authorization") || "";

    if (
      !expectedKey ||
      !safeEqual(suppliedKey, `Bearer ${expectedKey}`)
    ) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    if (
      !env.GMAIL_CLIENT_ID ||
      !env.GMAIL_CLIENT_SECRET ||
      !env.GMAIL_REFRESH_TOKEN
    ) {
      return jsonResponse(
        { error: "Gmail OAuth secrets are not configured" },
        500
      );
    }

    let body;

    try {
      const contentType = request.headers.get("Content-Type") || "";

      if (!contentType.toLowerCase().includes("application/json")) {
        return jsonResponse(
          { error: "Content-Type must be application/json" },
          415
        );
      }

      const rawBody = await request.text();

      if (encoder.encode(rawBody).byteLength > 64 * 1024) {
        return jsonResponse({ error: "Request body too large" }, 413);
      }

      body = JSON.parse(rawBody);
    } catch {
      return jsonResponse({ error: "Invalid JSON body" }, 400);
    }

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return jsonResponse({ error: "Invalid request body" }, 400);
    }

    const message = {
      to: normalizeEmail(body.to),
      cc: normalizeEmail(body.cc),
      bcc: normalizeEmail(body.bcc),
      from: normalizeEmail(body.from),
      subject: typeof body.subject === "string" ? body.subject.trim() : "",
      text: typeof body.text === "string" ? body.text : "",
      html: typeof body.html === "string" ? body.html : "",
    };

    if (!validateEmail(message.to)) {
      return jsonResponse({ error: "A valid recipient email is required" }, 400);
    }

    for (const field of ["cc", "bcc", "from"]) {
      if (message[field] && !validateEmail(message[field])) {
        return jsonResponse({ error: `Invalid ${field} email` }, 400);
      }
    }

    if (
      !message.subject ||
      hasHeaderInjection(message.subject) ||
      message.subject.length > 500
    ) {
      return jsonResponse({ error: "Invalid subject" }, 400);
    }

    if (!message.text && !message.html) {
      return jsonResponse(
        { error: "Provide a text or html message body" },
        400
      );
    }

    if (message.text.length > 40000 || message.html.length > 40000) {
      return jsonResponse({ error: "Email body too large" }, 400);
    }

    try {
      const result = await sendGmail(env, message);

      return jsonResponse({
        ok: true,
        message: "Email sent successfully",
        ...result,
      });
    } catch (error) {
      const code = error instanceof Error ? error.message : "";

      if (code.startsWith("GOOGLE_TOKEN_ERROR_")) {
        return jsonResponse(
          { error: "Could not obtain Google access token" },
          502
        );
      }

      if (code.startsWith("GMAIL_SEND_ERROR_")) {
        return jsonResponse(
          {
            error: "Gmail API rejected the message",
            upstreamStatus: Number(code.split("_").pop()),
          },
          502
        );
      }

      return jsonResponse({ error: "Internal server error" }, 500);
    }
  },
};
