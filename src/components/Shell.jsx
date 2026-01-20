import React from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider.jsx";
import { supabase } from "../supabaseClient.js";

export default function Shell({ children }) {
  const { user } = useAuth();
  const loc = useLocation();
  const nav = useNavigate();

  async function onLogout() {
    await supabase.auth.signOut();
    nav("/auth", { replace: true });
  }

  const isAuth = loc.pathname === "/auth";

  return (
    <div className="page">
      <header className="topbar">
        <div className="brand">Private Gallery</div>
        <nav className="nav">
          {!isAuth && user ? (
            <>
              <Link className={"navlink" + (loc.pathname === "/gallery" ? " active" : "")} to="/gallery">Gallery</Link>
              <Link className={"navlink" + (loc.pathname === "/upload" ? " active" : "")} to="/upload">Upload</Link>
              <button className="btn btn-ghost" onClick={onLogout}>Log out</button>
            </>
          ) : (
            <span className="muted">Hosted on GitHub Pages</span>
          )}
        </nav>
      </header>

      <main className="container">
        {children}
      </main>

      <footer className="footer">
        <span className="muted">Media is private via Supabase signed URLs.</span>
      </footer>
    </div>
  );
}
