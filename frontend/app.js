import * as api from "./api.js";

let token = null;
let username = null;
const objectUrls = new Map();

const $ = (id) => document.getElementById(id);

function setMsg(el, text, ok = false) {
  el.textContent = text || "";
  el.style.color = ok ? "var(--muted)" : "var(--danger)";
}

function showApp() {
  $("view-auth").classList.add("hidden");
  $("view-app").classList.remove("hidden");
  $("btn-logout").classList.remove("hidden");
  $("whoami").textContent = username ? `Signed in as ${username}` : "";
}

function showAuth() {
  $("view-app").classList.add("hidden");
  $("view-auth").classList.remove("hidden");
  $("btn-logout").classList.add("hidden");
  $("whoami").textContent = "";
  clearGallery();
}

function clearGallery() {
  for (const url of objectUrls.values()) URL.revokeObjectURL(url);
  objectUrls.clear();
  $("gallery").innerHTML = "";
  $("count").textContent = "";
}

function fmtBytes(n) {
  if (n == null) return "";
  const u = ["B","KB","MB","GB"];
  let i = 0;
  let x = Number(n);
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
  return `${x.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

async function renderGallery(items) {
  clearGallery();
  $("count").textContent = `${items.length} item(s)`;
  if (items.length === 0) return;

  const gallery = $("gallery");
  for (const item of items) {
    const tile = document.createElement("div");
    tile.className = "tile";

    const mediaWrap = document.createElement("div");
    mediaWrap.className = "media";
    mediaWrap.textContent = "Loading…";
    tile.appendChild(mediaWrap);

    const meta = document.createElement("div");
    meta.className = "meta";

    const name = document.createElement("div");
    name.className = "name";
    name.textContent = item.originalName || item.id;
    meta.appendChild(name);

    const sub = document.createElement("div");
    sub.className = "sub";
    const dt = item.createdAt ? new Date(item.createdAt).toLocaleString() : "";
    sub.textContent = [item.type, fmtBytes(item.sizeBytes), dt].filter(Boolean).join(" • ");
    meta.appendChild(sub);

    const del = document.createElement("button");
    del.className = "btn";
    del.type = "button";
    del.textContent = "Delete";
    del.addEventListener("click", async () => {
      del.disabled = true;
      try {
        await api.deleteMedia(token, item.id);
        await refresh();
      } catch (e) {
        del.disabled = false;
        alert(e.message || "Delete failed");
      }
    });
    meta.appendChild(del);

    tile.appendChild(meta);
    gallery.appendChild(tile);

    try {
      const { blob, mime } = await api.fetchMediaBlob(token, item.id);
      const url = URL.createObjectURL(blob);
      objectUrls.set(item.id, url);

      mediaWrap.textContent = "";
      if ((item.type || "").toLowerCase() === "video" || mime.startsWith("video/")) {
        const v = document.createElement("video");
        v.src = url;
        v.controls = true;
        v.playsInline = true;
        mediaWrap.appendChild(v);
      } else {
        const img = document.createElement("img");
        img.src = url;
        img.alt = item.originalName || "photo";
        mediaWrap.appendChild(img);
      }
    } catch {
      mediaWrap.textContent = "Failed to load";
    }
  }
}

async function refresh() {
  const data = await api.listMedia(token);
  await renderGallery(data.items || []);
}

$("form-register").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.currentTarget);
  const u = String(fd.get("username") || "").trim();
  const p = String(fd.get("password") || "");
  setMsg($("register-msg"), "");
  try {
    await api.register(u, p);
    setMsg($("register-msg"), "Account created. You can log in now.", true);
    e.currentTarget.reset();
  } catch (err) {
    setMsg($("register-msg"), err.message || "Register failed");
  }
});

$("form-login").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.currentTarget);
  const u = String(fd.get("username") || "").trim();
  const p = String(fd.get("password") || "");
  setMsg($("login-msg"), "");
  try {
    const data = await api.login(u, p);
    token = data.token;
    username = data.username;
    showApp();
    await refresh();
    e.currentTarget.reset();
  } catch (err) {
    setMsg($("login-msg"), err.message || "Login failed");
  }
});

$("btn-logout").addEventListener("click", async () => {
  if (!token) return;
  try { await api.logout(token); } catch {}
  token = null;
  username = null;
  showAuth();
});

$("btn-refresh").addEventListener("click", async () => {
  if (!token) return;
  await refresh();
});

$("form-upload").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!token) return;
  const file = $("file").files && $("file").files[0];
  setMsg($("upload-msg"), "");
  if (!file) {
    setMsg($("upload-msg"), "Select a file first.");
    return;
  }
  const max = file.type.startsWith("video/") ? 250 * 1024 * 1024 : 25 * 1024 * 1024;
  if (file.size > max) {
    setMsg($("upload-msg"), `File too large. Max ${(max/1024/1024).toFixed(0)}MB.`);
    return;
  }
  $("form-upload").querySelector("button[type=submit]").disabled = true;
  try {
    await api.uploadMedia(token, file);
    setMsg($("upload-msg"), "Uploaded.", true);
    $("file").value = "";
    await refresh();
  } catch (err) {
    setMsg($("upload-msg"), err.message || "Upload failed");
  } finally {
    $("form-upload").querySelector("button[type=submit]").disabled = false;
  }
});

showAuth();
