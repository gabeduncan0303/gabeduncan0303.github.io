import { CONFIG } from "./config.js";

async function req(path, opts = {}) {
  const res = await fetch(CONFIG.API_BASE + path, {
    ...opts,
    headers: {
      ...(opts.headers || {}),
      "Accept": "application/json",
    }
  });
  let data = null;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) data = await res.json();
  if (!res.ok) {
    const msg = (data && (data.error || data.message)) || (await res.text().catch(() => "")) || "Request failed";
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return data;
}

export async function register(username, password) {
  return req("/api/register", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ username, password })
  });
}

export async function login(username, password) {
  return req("/api/login", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ username, password })
  });
}

export async function logout(token) {
  return req("/api/logout", {
    method: "POST",
    headers: { "Authorization": `Bearer ${token}` }
  });
}

export async function listMedia(token) {
  return req("/api/media", {
    method: "GET",
    headers: { "Authorization": `Bearer ${token}` }
  });
}

export async function uploadMedia(token, file) {
  const fd = new FormData();
  fd.append("file", file, file.name);
  const res = await fetch(CONFIG.API_BASE + "/api/media", {
    method: "POST",
    headers: { "Authorization": `Bearer ${token}` },
    body: fd
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error((data && data.error) || "Upload failed");
  return data;
}

export async function deleteMedia(token, id) {
  return req(`/api/media/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: { "Authorization": `Bearer ${token}` }
  });
}

export async function fetchMediaBlob(token, id) {
  const res = await fetch(CONFIG.API_BASE + `/api/media/${encodeURIComponent(id)}/file`, {
    method: "GET",
    headers: { "Authorization": `Bearer ${token}` }
  });
  if (!res.ok) throw new Error("Failed to load media");
  const blob = await res.blob();
  const mime = res.headers.get("content-type") || blob.type || "application/octet-stream";
  return { blob, mime };
}
