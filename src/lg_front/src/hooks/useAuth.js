import { useState, useEffect } from 'react';

/**
 * Alternative hook to use auth without context
 * Use this if you prefer hooks over context
 */
const useAuth = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const storedUser = localStorage.getItem('soc_user');
    if (storedUser) {
      try {
        setUser(JSON.parse(storedUser));
      } catch (error) {
        console.error('Failed to parse stored user:', error);
        localStorage.removeItem('soc_user');
      }
    }
    setLoading(false);
  }, []);

  const login = async (credentials) => {
    const demoUser = {
      id: '1',
      username: credentials.username || 'demo',
      email: 'demo@soc.local',
      role: 'analyst',
      permissions: ['read', 'write', 'analyze']
    };

    setUser(demoUser);
    localStorage.setItem('soc_user', JSON.stringify(demoUser));
    return demoUser;
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('soc_user');
  };

  return {
    user,
    login,
    logout,
    loading,
    isAuthenticated: !!user
  };
};

export default useAuth;