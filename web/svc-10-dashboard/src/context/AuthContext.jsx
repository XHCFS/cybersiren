import { createContext, useContext, useState } from "react";
import api, { getToken, setToken } from "../services/api.js";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setTok] = useState(getToken());
  const [user, setUser] = useState(() => {
    const raw = localStorage.getItem("cs_user");
    return raw ? JSON.parse(raw) : null;
  });

  async function login(email, password) {
    const { data } = await api.post("/auth/login", { email, password });
    setToken(data.token);
    setTok(data.token);
    setUser(data.user);
    localStorage.setItem("cs_user", JSON.stringify(data.user));
    return data;
  }

  function logout() {
    setToken(null);
    setTok(null);
    setUser(null);
    localStorage.removeItem("cs_user");
  }

  return (
    <AuthContext.Provider value={{ token, user, login, logout, isAuthed: Boolean(token) }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
