import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

interface LoginResponse {
  error?: string;
  message?: string;
}

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);

  const handleSubmit = async (e: React.MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('http://localhost:4000/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ username, password }),
      });

      const data: LoginResponse = await response.json();

      if (data.error) {
        setError(data.error);
      } else if (data.message) {
        console.log('Login successful, cookies:', document.cookie);
        navigate('/dashboard');
      }
    } catch (err) {
      setError('Failed to connect to server');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '400px', margin: '40px auto', padding: '20px' }}>
        <h2 style={{ fontSize: '2rem', marginBottom: '24px', textAlign: 'center' }}>
        Login
        </h2>
        <div>
        {error && (
            <div style={{
            background: '#fee',
            border: '1px solid #fcc',
            color: '#c33',
            padding: '12px',
            borderRadius: '4px',
            marginBottom: '16px'
            }}>
            {error}
            </div>
        )}
        
        <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            style={{
            width: '100%',
            padding: '10px',
            marginBottom: '12px',
            border: '1px solid #ddd',
            borderRadius: '4px',
            fontSize: '1rem',
            boxSizing: 'border-box'
            }}
        />
        
        <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={{
            width: '100%',
            padding: '10px',
            marginBottom: '16px',
            border: '1px solid #ddd',
            borderRadius: '4px',
            fontSize: '1rem',
            boxSizing: 'border-box'
            }}
        />
        
        <button 
            onClick={handleSubmit} 
            disabled={loading}
            style={{
            width: '100%',
            padding: '12px',
            background: loading ? '#999' : '#2563eb',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            fontSize: '1rem',
            fontWeight: '500',
            cursor: loading ? 'not-allowed' : 'pointer'
            }}
        >
            {loading ? 'Logging in...' : 'Log In'}
        </button>
        </div>
    </div>
    );
}