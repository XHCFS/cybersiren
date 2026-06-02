import { Navigate, Route, Routes, Link, useNavigate } from "react-router-dom";
import { useAuth } from "./context/AuthContext.jsx";
import LoginForm from "./components/LoginForm.jsx";
import Dashboard from "./components/Dashboard.jsx";
import ScanList from "./components/ScanList.jsx";
import ScanDetail from "./components/ScanDetail.jsx";

function ProtectedLayout({ children }) {
  const { isAuthed, user, logout } = useAuth();
  const navigate = useNavigate();
  if (!isAuthed) return <Navigate to="/login" replace />;
  return (
    <div className="app">
      <nav className="nav">
        <span className="brand">CyberSiren</span>
        <Link to="/">Dashboard</Link>
        <Link to="/scans">Scans</Link>
        <span className="spacer" />
        <span className="user">{user?.email}</span>
        <button onClick={() => { logout(); navigate("/login"); }}>Log out</button>
      </nav>
      <main className="content">{children}</main>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginForm />} />
      <Route path="/" element={<ProtectedLayout><Dashboard /></ProtectedLayout>} />
      <Route path="/scans" element={<ProtectedLayout><ScanList /></ProtectedLayout>} />
      <Route path="/scans/:id" element={<ProtectedLayout><ScanDetail /></ProtectedLayout>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
