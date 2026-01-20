import React, { useEffect, useMemo, useState } from "react";
import { useAuth } from "../auth/AuthProvider.jsx";
import { BUCKET, supabase } from "../supabaseClient.js";

function isVideo(mime) {
  return (mime || "").startsWith("video/");
}

export default function GalleryPage() {
  const { user } = useAuth();
  const [items, setItems] = useState([]);
  const [urls, setUrls] = useState({});
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  const sorted = useMemo(() => items.slice().sort((a, b) => new Date(b.created_at) - new Date(a.created_at)), [items]);

  async function refresh() {
    setMsg("");
    setBusy(true);
    try {
      const res = await supabase
        .from("media")
        .select("id, storage_path, mime_type, original_name, size_bytes, created_at")
        .eq("owner_id", user.id)
        .order("created_at", { ascending: false })
        .limit(200);

      if (res.error) throw res.error;
      setItems(res.data || []);
    } catch (err) {
      setMsg(err?.message || "Load error");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function signAll() {
      const next = {};
      for (const it of sorted) {
        const s = await supabase.storage.from(BUCKET).createSignedUrl(it.storage_path, 60);
        if (!s.error && s.data?.signedUrl) next[it.id] = s.data.signedUrl;
      }
      if (!cancelled) setUrls(next);
    }
    if (sorted.length) signAll();
    else setUrls({});
    return () => { cancelled = true; };
  }, [sorted]);

  async function onDelete(it) {
    setMsg("");
    setBusy(true);
    try {
      const delObj = await supabase.storage.from(BUCKET).remove([it.storage_path]);
      if (delObj.error) throw delObj.error;
      const delRow = await supabase.from("media").delete().eq("id", it.id).eq("owner_id", user.id);
      if (delRow.error) throw delRow.error;
      await refresh();
    } catch (err) {
      setMsg(err?.message || "Delete error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <div className="row row-between">
        <div>
          <h1 className="h1">Gallery</h1>
          <p className="muted">Up to 200 most recent items.</p>
        </div>
        <button className="btn btn-ghost" onClick={refresh} disabled={busy}>{busy ? "Working..." : "Refresh"}</button>
      </div>

      {msg ? <div className="notice">{msg}</div> : null}

      {!sorted.length ? (
        <div className="empty">
          <div className="muted">No media yet.</div>
        </div>
      ) : (
        <div className="grid">
          {sorted.map((it) => {
            const url = urls[it.id];
            const video = isVideo(it.mime_type);
            return (
              <div key={it.id} className="tile">
                <div className="media">
                  {url ? (
                    video ? (
                      <video src={url} controls playsInline className="mediaEl" />
                    ) : (
                      <img src={url} alt={it.original_name} className="mediaEl" loading="lazy" />
                    )
                  ) : (
                    <div className="mediaPlaceholder">Loading...</div>
                  )}
                </div>
                <div className="meta">
                  <div className="mono trunc">{it.original_name}</div>
                  <div className="muted small">{new Date(it.created_at).toLocaleString()}</div>
                </div>
                <div className="actions">
                  <button className="btn btn-danger" onClick={() => onDelete(it)} disabled={busy}>Delete</button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
