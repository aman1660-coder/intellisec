import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { authApi } from "../services/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem("intellisec_token"));
  const [user, setUser] = useState(() => {
    const raw = localStorage.getItem("intellisec_user");
    return raw ? JSON.parse(raw) : null;
  });
  const [loading, setLoading] = useState(Boolean(token && !user));

  useEffect(() => {
    let active = true;
    if (!token) {
      setLoading(false);
      return;
    }
    authApi
      .me()
      .then((data) => {
        if (!active) return;
        setUser(data.user);
        localStorage.setItem("intellisec_user", JSON.stringify(data.user));
      })
      .catch(() => {
        if (!active) return;
        localStorage.removeItem("intellisec_token");
        localStorage.removeItem("intellisec_user");
        setToken(null);
        setUser(null);
      })
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [token]);

  const commitSession = (data) => {
    localStorage.setItem("intellisec_token", data.token);
    localStorage.setItem("intellisec_user", JSON.stringify(data.user));
    setToken(data.token);
    setUser(data.user);
  };

  const value = useMemo(
    () => ({
      token,
      user,
      loading,
      isAuthenticated: Boolean(token && user),
      async login(payload) {
        const data = await authApi.login(payload);
        commitSession(data);
        return data;
      },
      async register(payload) {
        const data = await authApi.register(payload);
        commitSession(data);
        return data;
      },
      logout() {
        localStorage.removeItem("intellisec_token");
        localStorage.removeItem("intellisec_user");
        setToken(null);
        setUser(null);
      }
    }),
    [token, user, loading]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return useContext(AuthContext);
}

