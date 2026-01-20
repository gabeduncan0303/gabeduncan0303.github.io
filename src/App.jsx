import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthProvider.jsx";
import Shell from "./components/Shell.jsx";
import AuthPage from "./pages/AuthPage.jsx";
import GalleryPage from "./pages/GalleryPage.jsx";
import UploadPage from "./pages/UploadPage.jsx";

function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <Shell><div className="card">Loading...</div></Shell>;
  if (!user) return <Navigate to="/auth" replace />;
  return children;
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/" element={<Navigate to="/gallery" replace />} />
        <Route path="/auth" element={<Shell><AuthPage /></Shell>} />
        <Route path="/gallery" element={<Protected><Shell><GalleryPage /></Shell></Protected>} />
        <Route path="/upload" element={<Protected><Shell><UploadPage /></Shell></Protected>} />
        <Route path="*" element={<Navigate to="/gallery" replace />} />
      </Routes>
    </AuthProvider>
  );
}
