# LUCCA Proxy

Proxy web al estilo Hidester. Escribes una dirección (o una búsqueda) y LUCCA carga la página por ti: el sitio de destino ve la IP del servidor, no la tuya.

## Instalar y ejecutar en tu computadora

Requiere Node.js 18.14 o superior.

```bash
cd LUCCA-PROXY
npm install
LUCCA_PASSWORD="tu-contraseña" LUCCA_SECRET="una-clave-larga-y-aleatoria" npm start
```

Abre http://localhost:3000 (en Windows PowerShell: `$env:LUCCA_PASSWORD="..."; npm start`).

## Variables de entorno

Nunca escribas aquí valores reales: este repositorio es público. Se configuran en el panel de Render (Environment).

| Variable | Qué hace |
|---|---|
| `PORT` | Puerto del servidor (por defecto 3000). Render lo define solo. |
| `LUCCA_PASSWORD` | Contraseña del usuario `admin`. Activa el login y el panel `/admin`. Sin ella, el acceso es libre y el panel queda desactivado. |
| `LUCCA_SECRET` | Clave para firmar la sesión de login. Fíjala para que los logins sobrevivan a reinicios. |
| `LUCCA_COOKIES` | Pon `off` para no guardar cookies de los sitios visitados. |
| `YOUTUBE_API_KEY` | Clave de la API de YouTube Data v3. Activa la búsqueda por texto en `/youtube`. Sin ella, solo funcionan los enlaces de video. |
| `TRUST_PROXY` | Pon `1` si va detrás de Render, Nginx, Caddy o Cloudflare, para que los límites usen la IP real. |

## Funciones

- **Login con usuario y contraseña:** sesión de 7 días, máximo 5 intentos fallidos cada 15 minutos por IP. Cierra sesión en `/logout` o con "Salir" en la barra.
- **Varios usuarios:** el usuario `admin` usa la contraseña de `LUCCA_PASSWORD`. Los demás se crean desde el panel y se guardan en `users.json` con la contraseña cifrada (scrypt). Al eliminar un usuario, su sesión deja de valer al instante. Cada usuario tiene sus propias cookies de sitios.
- **Panel de administración (`/admin`):** solo para `admin`. Permite editar la lista de bloqueo, crear usuarios y eliminarlos. Aparece como "Panel" en la barra superior.
- **Lista de bloqueo:** edítala desde el panel o directamente en `blocklist.txt` (un dominio por línea). Bloquea el dominio y sus subdominios, y se aplica sin reiniciar.
- **Cookies por sesión:** LUCCA guarda las cookies de los sitios en el servidor, separadas por usuario, así los inicios de sesión en otros sitios funcionan. Se borran tras 2 horas sin actividad, al reiniciar el servidor o con "Borrar cookies" en la barra. Tu navegador nunca las recibe.
- **YouTube (`/youtube`):** YouTube no se puede reescribir como una web normal (JavaScript pesado, video firmado, bloqueos a servidores). Por eso LUCCA ofrece su propio buscador y el reproductor oficial incrustado. Cualquier enlace a youtube.com o youtu.be escrito en el buscador del proxy redirige ahí. El video se reproduce directo desde YouTube, así que YouTube sí ve la IP real del visitante. Algunos videos no permiten incrustarse.
- Reescribe enlaces, imágenes, scripts, CSS, `srcset` y formularios (GET y POST) para que todo pase por LUCCA.
- Sigue redirecciones por el proxy, quita CSP y X-Frame-Options, e intercepta `fetch`, `XMLHttpRequest` y `window.open`.
- Bloquea destinos internos (localhost, 10.x, 192.168.x, etc.), limita peticiones por IP y el tamaño de las páginas.

## Desplegar en Render

1. Sube los archivos a este repositorio: `server.js`, `package.json`, `blocklist.txt`, `.gitignore` y `public/index.html`.
2. En Render, el servicio es un Web Service de Node con `npm install` como build y `npm start` como inicio.
3. En Environment, define `LUCCA_PASSWORD`, `LUCCA_SECRET` y `TRUST_PROXY=1` (y `YOUTUBE_API_KEY` si quieres buscar en YouTube).
4. Cada commit en `main` despliega solo.

## Límites conocidos

- Sitios con mucho JavaScript, streaming de video o WebSockets pueden fallar.
- Las cookies de los sitios viven solo en memoria: si el servidor se reinicia, se pierden.
- En el plan gratuito de Render el disco no es permanente: `users.json` y los cambios de la lista de bloqueo hechos desde el panel se pierden al volver a desplegar o al reiniciarse el servicio. Para conservarlos hace falta un disco persistente (de pago) o editar `blocklist.txt` en GitHub.
- En el plan gratuito el servidor se duerme sin uso y la primera visita puede tardar un minuto.
- Un proxy no es una VPN ni Tor: quien administra el servidor puede ver el tráfico.
