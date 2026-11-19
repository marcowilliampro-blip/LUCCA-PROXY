
const express = require("express");
const cors = require("cors");
const dns = require("node:dns").promises;
const net = require("node:net");

const app = express();
const PORT = process.env.PORT || 3000;

const ALLOWED_HOSTS = (
  process.env.ALLOWED_HOSTS ||
  "example.com,www.example.com,developer.mozilla.org"
)
  .split(",")
  .map(host => host.trim().toLowerCase())
  .filter(Boolean);

app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || "*"
}));

app.use(express.json({ limit: "10kb" }));

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  return (
    parts[0] === 10 ||
    parts[0] === 127 ||
    parts[0] === 0 ||
    (parts[0] === 169 && parts[1] === 254) ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168)
  );
}

function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase();

  return (
    normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:")
  );
}

async function validateUrl(value) {
  const url = new URL(value);

  if (url.protocol !== "https:") {
    throw new Error("Solo se permiten direcciones HTTPS.");
  }

  if (url.username || url.password) {
    throw new Error("No se permiten credenciales en la dirección.");
  }

  const host = url.hostname.toLowerCase();

  if (!ALLOWED_HOSTS.includes(host)) {
    throw new Error("Este dominio no está autorizado.");
  }

  if (net.isIP(host)) {
    throw new Error("No se permiten direcciones IP.");
  }

  const addresses = await dns.lookup(host, { all: true });

  if (
    addresses.length === 0 ||
    addresses.some(({ address, family }) =>
      family === 4
        ? isPrivateIPv4(address)
        : isPrivateIPv6(address)
    )
  ) {
    throw new Error("La dirección de destino no está permitida.");
  }

  return url;
}

app.get("/", (req, res) => {
  res.json({
    name: "LUCCA PROXY",
    version: "2.0",
    status: "online"
  });
});

app.get("/api/status", (req, res) => {
  res.json({
    online: true,
    service: "LUCCA PROXY",
    version: "2.0"
  });
});

app.get("/api/fetch", async (req, res) => {
  let response;

  try {
    const url = await validateUrl(req.query.url);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    try {
      response = await fetch(url, {
        redirect: "error",
        signal: controller.signal,
        headers: {
          "User-Agent": "LUCCA-Proxy/2.0",
          "Accept": "text/html"
        }
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      return res.status(502).json({
        error: "No se pudo obtener la página."
      });
    }

    const contentType = response.headers.get("content-type") || "";

    if (!contentType.includes("text/html")) {
      return res.status(415).json({
        error: "El contenido no es HTML."
      });
    }

    const html = await response.text();

    if (Buffer.byteLength(html, "utf8") > 1024 * 1024) {
      return res.status(413).json({
        error: "El contenido supera el límite permitido."
      });
    }

    res.json({
      success: true,
      originalUrl: url.href,
      html
    });

  } catch (error) {
    res.status(400).json({
      error: "No se pudo procesar la solicitud.",
      message: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`LUCCA PROXY 2.0 activo en puerto ${PORT}`);
});
