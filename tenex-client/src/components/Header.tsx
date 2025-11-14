import { Link, useNavigate } from "react-router-dom";

export default function Header() {
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      const response = await fetch('http://localhost:4000/logout', {
        method: 'POST',
        credentials: 'include',
      });

      if (response.ok) {
        navigate('/login');
      }
    } catch (err) {
      console.error('Logout failed:', err);
    }
  };

  return (
  <header style={{ 
    borderBottom: '1px solid #e0e0e0', 
    padding: '16px 20px',
    marginBottom: '20px'
  }}>
    <nav style={{ 
      display: 'flex',
      gap: '20px',
      alignItems: 'center'
    }}>
      <Link to="/" style={{ textDecoration: 'none', color: '#333', fontWeight: '500' }}>
        Home
      </Link>
      <Link to="/signup" style={{ textDecoration: 'none', color: '#333', fontWeight: '500' }}>
        Signup
      </Link>
      <Link to="/login" style={{ textDecoration: 'none', color: '#333', fontWeight: '500' }}>
        Login
      </Link>
      <button 
        onClick={handleLogout}
        style={{
          background: '#dc2626',
          color: 'white',
          border: 'none',
          padding: '8px 16px',
          borderRadius: '4px',
          cursor: 'pointer',
          fontWeight: '500',
          marginLeft: 'auto'
        }}
      >
        Logout
      </button>
    </nav>
  </header>
);
}