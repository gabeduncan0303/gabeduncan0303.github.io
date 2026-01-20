import React, { useState } from "react";
import { supabase } from "../supabaseClient.js";
import { useAuth } from "../auth/AuthProvider.jsx";
import { useNavigate } from "react-router-dom";

export default function AuthPage() {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const { user, loading } = useAuth();
  const nav = useNavigate();

  if (!loading && user) {
    nav("/gallery", { replace: true });
  }

  async function onSubmit(e) {
    e.preventDefault();
    setMsg("");
    setBusy(true);
    try {
      if (mode === "signup") {
        const { error } = await supabase.auth.signUp({ email, password });
        if (error) throw error;
        setMsg("Account created. Check your email if confirmation is enabled. Then log in.");
        setMode("login");
      } else {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        nav("/gallery", { replace: true });
      }
    } catch (err) {
      setMsg(err?.message || "Auth error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h1 className="h1">{mode === "signup" ? "Create account" : "Sign in"}</h1>
      <p className="muted">Accounts and private media are handled by Supabase.</p>

      <form onSubmit={onSubmit} className="form">
        <label className="label">
          Email
          <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </label>

        <label className="label">
          Password
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={6} />
        </label>

        <button className="btn btn-primary" type="submit" disabled={busy}>
          {busy ? "Working..." : (mode === "signup" ? "Sign up" : "Sign in")}
        </button>
      </form>

      {msg ? <div className="notice">{msg}</div> : null}

      <div className="row">
        <button className="btn btn-ghost" onClick={() => setMode(mode === "signup" ? "login" : "signup")} type="button">
          {mode === "signup" ? "Have an account? Sign in" : "Need an account? Sign up"}
        </button>
      </div>
    </div>
  );
}
