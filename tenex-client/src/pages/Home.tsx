export default function Home() {
  return (
    <div style={{ maxWidth: '900px', margin: '0 auto', padding: '60px 20px' }}>
      <div style={{ textAlign: 'center', marginBottom: '48px' }}>
        <h1 style={{ 
          fontSize: '3rem', 
          marginBottom: '16px', 
          fontWeight: 'bold',
          color: '#1f2937'
        }}>
          SSH Log Analyzer
        </h1>
        <p style={{ 
          fontSize: '1.25rem', 
          color: '#6b7280',
          fontWeight: '300'
        }}>
          Automated security analysis powered by AI
        </p>
      </div>

      <div style={{ 
        background: '#f9fafb',
        border: '1px solid #e5e7eb',
        borderRadius: '8px',
        padding: '32px',
        lineHeight: '1.8'
      }}>
        <h2 style={{ 
          fontSize: '1.5rem', 
          marginBottom: '20px', 
          fontWeight: '600',
          color: '#374151'
        }}>
          What does it do?
        </h2>
        
        <p style={{ marginBottom: '20px', fontSize: '1.05rem', color: '#4b5563' }}>
          Upload your SSH authentication logs (
          <code style={{ 
            background: '#e0f2fe', 
            color: '#0369a1',
            padding: '3px 8px', 
            borderRadius: '4px',
            fontFamily: 'monospace',
            fontSize: '0.95rem'
          }}>
            .log
          </code>
          {' '}or{' '}
          <code style={{ 
            background: '#e0f2fe', 
            color: '#0369a1',
            padding: '3px 8px', 
            borderRadius: '4px',
            fontFamily: 'monospace',
            fontSize: '0.95rem'
          }}>
            .txt
          </code>
          ) and get instant insights into your system's security posture.
        </p>

        <div style={{ 
          borderLeft: '4px solid #3b82f6',
          paddingLeft: '20px',
          marginBottom: '20px'
        }}>
          <p style={{ marginBottom: '12px', fontSize: '1.05rem', color: '#4b5563' }}>
            <strong style={{ color: '#1f2937' }}>Automated Detection:</strong> Identifies suspicious patterns, failed login attempts, and potential intrusion attempts across thousands of log entries.
          </p>
          <p style={{ marginBottom: '12px', fontSize: '1.05rem', color: '#4b5563' }}>
            <strong style={{ color: '#1f2937' }}>AI-Powered Analysis:</strong> Uses advanced language models to explain anomalies and assess threat confidence levels.
          </p>
          <p style={{ fontSize: '1.05rem', color: '#4b5563' }}>
            <strong style={{ color: '#1f2937' }}>Actionable Insights:</strong> Understand exactly what's happening in your system without manually parsing log files.
          </p>
        </div>

        <p style={{ fontSize: '1.05rem', color: '#6b7280', fontStyle: 'italic' }}>
          Perfect for system administrators, security teams, and anyone managing SSH access to their servers.
        </p>
      </div>
    </div>
  );
}