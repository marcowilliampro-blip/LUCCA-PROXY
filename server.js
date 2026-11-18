
const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;

const ALLOWED_HOSTS = (
  process.env.ALLOWED_HOSTS ||
  "example.com,www.example.com,youtube.com,www.youtube.com,m.youtube.com,tiktok.com,www.tiktok.com,google.com,www.google.com,instagram.com,www.instagram.com,spotify.com,www.spotify.com,open.spotify.com,chatgpt.com,www.chatgpt.com"
)
  .split(",")
  .map(host => host.trim().toLowerCase())
  .filter(Boolean);

app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || "*"
}));

app.use(express.json({ limit: "10kb" }));

function validateUrl(value) {
  let url;

  try {
    url = new URL(value);
  } catch {
    throw new Error("Dirección web no válida.");
  }

  if (url.protocol !== "https:") {
    throw new Error("Solo se permiten direcciones HTTPS.");
  }

  if (
    url.username ||
    url.password ||
    !ALLOWED_HOSTS.includes(url.hostname.toLowerCase())
  ) {
    throw new Error("Este dominio no está autorizado.");
  }

  return url;
}

app.get("/", (req, res) => {
  res.json({
    name: "LUCCA PROXY",
    status: "online",
    version: "1.0"
  });
});

app.get("/api/status", (req, res) => {
  res.json({
    online: true,
    service: "LUCCA PROXY"
  });
});

app.get("/api/fetch", async (req, res) => {
  try {
    const url = validateUrl(req.query.url);

    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      10000
    );

    let response;

    try {
      response = await fetch(url, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent": "LUCCA-Proxy/1.0",
          "Accept": "text/html"
        }
      });
    } finally {
      clearTimeout(timeout);
    }

    if (response.status >= 300 && response.status < 400) {
      return res.status(403).json({
        error: "Las redirecciones externas no están permitidas."
      });
    }

    if (!response.ok) {
      return res.status(502).json({
        error: "No se pudo obtener la página."
      });
    }

    const contentType =
      response.headers.get("content-type") || "";

    if (!contentType.includes("text/html")) {
      return res.status(415).json({
        error: "Este servicio solo admite contenido HTML."
      });
    }

    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    const MAX_SIZE = 2 * 1024 * 1024;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      total += value.length;

      if (total > MAX_SIZE) {
        await reader.cancel();
        return res.status(413).json({
          error: "La página supera el límite de 2 MB."
        });
      }

      chunks.push(value);
    }

    const html = Buffer.concat(chunks).toString("utf8");

    res.json({
      success: true,
      originalUrl: url.href,
      html
    });

  } catch (error) {
    res.status(400).json({
      error: error.message || "Error al procesar la solicitud."
    });
  }
});

app.listen(PORT, () => {
  console.log(`LUCCA PROXY activo en puerto ${PORT}`);
});

