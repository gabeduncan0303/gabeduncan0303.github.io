import React, { useMemo, useState } from "react";
import { useAuth } from "../auth/AuthProvider.jsx";
import { BUCKET, supabase } from "../supabaseClient.js";

function bytes(n) {
  const units = ["B", "KB", "MB", "GB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function isAllowed(file) {
  const t = file.type || "";
  if (t.startsWith("image/")) return true;
  if (t.startsWith("video/")) return true;
  return false;
}

function uid() {
  if (crypto?.randomUUID) return crypto.randomUUID();
  return Math.random().toString(16).slice(2) + Date.now().toString(16);
}

export default function UploadPage() {
  const { user } = useAuth();
  const [files, setFiles] = useState([]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const totalBytes = useMemo(() => files.reduce((a, f) => a + f.size, 0), [files]);

  function onPick(e) {
    setMsg("");
    const picked = Array.from(e.target.files || []);
    const ok = picked.filter(isAllowed);
    setFiles(ok);
  }

  async function onUpload() {
    setMsg("");
    if (!files.length) return;
    setBusy(true);
    try {
      for (const file of files) {
        const safeName = file.name.replaceAll("/", "_");
        const path = `${user.id}/${uid()}-${safeName}`;
        const up = await supabase.storage.from(BUCKET).upload(path, file, {
          cacheControl: "3600",
          upsert: false,
          contentType: file.type || undefined
        });
        if (up.error) throw up.error;

        const ins = await supabase.from("media").insert({
          owner_id: user.id,
          storage_path: path,
          mime_type: file.type || "application/octet-stream",
          original_name: file.name,
          size_bytes: file.size
        });
        if (ins.error) throw ins.error;
      }
      setFiles([]);
      setMsg("Uploaded.");
    } catch (err) {
      setMsg(err?.message || "Upload error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h1 className="h1">Upload</h1>
      <p className="muted">Images and videos only.</p>

      <div className="form">
        <input className="input" type="file" accept="image/*,video/*" multiple onChange={onPick} />
        <div className="muted">{files.length ? `${files.length} file(s) selected • ${bytes(totalBytes)}` : "No files selected"}</div>
        <button className="btn btn-primary" onClick={onUpload} disabled={busy || !files.length}>
          {busy ? "Uploading..." : "Upload"}
        </button>
      </div>

      {files.length ? (
        <div className="list">
          {files.map((f) => (
            <div key={f.name + f.size} className="listitem">
              <div className="mono">{f.name}</div>
              <div className="muted">{f.type || "unknown"} • {bytes(f.size)}</div>
            </div>
          ))}
        </div>
      ) : null}

      {msg ? <div className="notice">{msg}</div> : null}
    </div>
  );
}
