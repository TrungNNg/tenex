import { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';

interface Anomaly {
  IP: string;
  PIDs: string[];
  DNSWarningsCount: number;
  InvalidUserCount: number;
  AuthFailuresCount: number;
  RepeatedMessageCount: number;
  MaxAuthFailuresCount: number;
  NoIdentificationCount: number;
  FirstSeen: string;
  LastSeen: string;
  Usernames: string[];
}

interface Analysis {
  TotalEvents: number;
  DNSWarningCount: number;
  InvalidUserCount: number;
  AuthRequestCount: number;
  PAMMessageCount: number;
  AuthFailuresCount: number;
  AuthSuccessCount: number;
  ConnectionClosedCount: number;
  DisconnectCount: number;
  RepeatedMessageCount: number;
  MaxAuthFailuresCount: number;
  NoIdentificationCount: number;
  ErrorMessageCount: number;
  UniqueIPs: number;
  TimeRange: string;
  Anomalies: Anomaly[];
}

interface ParseResponse {
  file_id: string;
  analyze_result: Analysis;
}

interface AnalyzeResponse {
  explanation: string;
  confidence: string;
  matched_lines: number;
}

export default function Details() {
  const location = useLocation();
  const fileId = location.state?.fileId;
  const filename = location.state?.filename;
  
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');
  const [analyzingIP, setAnalyzingIP] = useState<string | null>(null);
  const [analyzeResult, setAnalyzeResult] = useState<{ [key: string]: AnalyzeResponse }>({});

  useEffect(() => {
    if (!fileId) {
      setError('No file ID provided');
      setLoading(false);
      return;
    }

    const parseFile = async () => {
      try {
        const response = await fetch('http://localhost:4000/parse', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({ file_id: fileId }),
        });

        if (response.ok) {
          const data: ParseResponse = await response.json();
          setAnalysis(data.analyze_result);
        } else {
          const errorData = await response.json();
          setError(errorData.error || 'Failed to parse file');
        }
      } catch (err) {
        setError('Failed to connect to server');
      } finally {
        setLoading(false);
      }
    };

    parseFile();
  }, [fileId]);

  const getSortedAnomalies = (anomalies: Anomaly[]): Anomaly[] => {
    return [...anomalies].sort((a, b) => {
      const sumA = a.DNSWarningsCount + a.InvalidUserCount + a.AuthFailuresCount + 
                   a.RepeatedMessageCount + a.MaxAuthFailuresCount + a.NoIdentificationCount;
      const sumB = b.DNSWarningsCount + b.InvalidUserCount + b.AuthFailuresCount + 
                   b.RepeatedMessageCount + b.MaxAuthFailuresCount + b.NoIdentificationCount;
      return sumB - sumA;
    });
  };

  const handleAnalyze = async (ip: string, pids: string[]) => {
    if (!fileId) return;
    
    setAnalyzingIP(ip);
    
    try {
      const response = await fetch('http://localhost:4000/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ file_id: fileId, pids }),
      });

      if (response.ok) {
        const data: AnalyzeResponse = await response.json();
        setAnalyzeResult(prev => ({ ...prev, [ip]: data }));
      } else {
        const errorData = await response.json();
        alert(errorData.error || 'Failed to analyze');
      }
    } catch (err) {
      alert('Failed to connect to server');
    } finally {
      setAnalyzingIP(null);
    }
  };

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!analysis) return <div>No analysis data</div>;

  const sortedAnomalies = getSortedAnomalies(analysis.Anomalies || []);

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '40px 20px' }}>
        <h1 style={{ fontSize: '2.5rem', marginBottom: '32px', fontWeight: 'bold' }}>
        Details Page for {filename || 'Unknown File'}
        </h1>
        
        <h2 style={{ fontSize: '1.75rem', marginBottom: '16px', fontWeight: '600', borderBottom: '2px solid #e0e0e0', paddingBottom: '8px' }}>
        Summary
        </h2>
        <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', 
        gap: '12px',
        marginBottom: '32px'
        }}>
        <p><strong>Total Events:</strong> {analysis.TotalEvents}</p>
        <p><strong>Time Range:</strong> {analysis.TimeRange}</p>
        <p><strong>Unique IPs:</strong> {analysis.UniqueIPs}</p>
        <p><strong>DNS Warning Count:</strong> {analysis.DNSWarningCount}</p>
        <p><strong>Invalid User Count:</strong> {analysis.InvalidUserCount}</p>
        <p><strong>Auth Request Count:</strong> {analysis.AuthRequestCount}</p>
        <p><strong>PAM Message Count:</strong> {analysis.PAMMessageCount}</p>
        <p><strong>Auth Failures Count:</strong> {analysis.AuthFailuresCount}</p>
        <p><strong>Auth Success Count:</strong> {analysis.AuthSuccessCount}</p>
        <p><strong>Connection Closed Count:</strong> {analysis.ConnectionClosedCount}</p>
        <p><strong>Disconnect Count:</strong> {analysis.DisconnectCount}</p>
        <p><strong>Repeated Message Count:</strong> {analysis.RepeatedMessageCount}</p>
        <p><strong>Max Auth Failures Count:</strong> {analysis.MaxAuthFailuresCount}</p>
        <p><strong>No Identification Count:</strong> {analysis.NoIdentificationCount}</p>
        <p><strong>Error Message Count:</strong> {analysis.ErrorMessageCount}</p>
        </div>

        <h2 style={{ fontSize: '1.75rem', marginBottom: '16px', fontWeight: '600', borderBottom: '2px solid #e0e0e0', paddingBottom: '8px' }}>
        Anomalies (Sorted by Total Count)
        </h2>
        {sortedAnomalies.length === 0 ? (
        <p style={{ color: '#666', fontStyle: 'italic' }}>No anomalies detected</p>
        ) : (
        <div>
            {sortedAnomalies.map((anomaly, index) => {
            const totalCount = anomaly.DNSWarningsCount + anomaly.InvalidUserCount + 
                            anomaly.AuthFailuresCount + anomaly.RepeatedMessageCount + 
                            anomaly.MaxAuthFailuresCount + anomaly.NoIdentificationCount;
            
            return (
                <div 
                key={index} 
                style={{ 
                    border: '1px solid #ddd', 
                    padding: '20px', 
                    marginBottom: '20px',
                    borderRadius: '8px',
                    background: '#fafafa'
                }}
                >
                <h3 style={{ fontSize: '1.25rem', marginBottom: '12px', color: '#dc2626' }}>
                    IP: {anomaly.IP} <span style={{ color: '#666' }}>(Total: {totalCount})</span>
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '8px', marginBottom: '16px' }}>
                    <p><strong>PIDs:</strong> {anomaly.PIDs.join(', ')}</p>
                    <p><strong>DNS Warnings:</strong> {anomaly.DNSWarningsCount}</p>
                    <p><strong>Invalid User:</strong> {anomaly.InvalidUserCount}</p>
                    <p><strong>Auth Failures:</strong> {anomaly.AuthFailuresCount}</p>
                    <p><strong>Repeated Message:</strong> {anomaly.RepeatedMessageCount}</p>
                    <p><strong>Max Auth Failures:</strong> {anomaly.MaxAuthFailuresCount}</p>
                    <p><strong>No Identification:</strong> {anomaly.NoIdentificationCount}</p>
                    <p><strong>First Seen:</strong> {new Date(anomaly.FirstSeen).toLocaleString()}</p>
                    <p><strong>Last Seen:</strong> {new Date(anomaly.LastSeen).toLocaleString()}</p>
                </div>
                <p style={{ marginBottom: '16px' }}><strong>Usernames:</strong> {anomaly.Usernames.join(', ')}</p>
                
                <button 
                    onClick={() => handleAnalyze(anomaly.IP, anomaly.PIDs)}
                    disabled={analyzingIP === anomaly.IP}
                    style={{
                    padding: '10px 20px',
                    background: analyzingIP === anomaly.IP ? '#999' : '#7c3aed',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    fontSize: '1rem',
                    fontWeight: '500',
                    cursor: analyzingIP === anomaly.IP ? 'not-allowed' : 'pointer'
                    }}
                >
                    {analyzingIP === anomaly.IP ? 'Analyzing...' : 'Analyze'}
                </button>
                
                {analyzeResult[anomaly.IP] && (
                    <div style={{ 
                    marginTop: '16px', 
                    padding: '16px', 
                    background: '#e0f2fe',
                    border: '1px solid #0284c7',
                    borderRadius: '6px'
                    }}>
                    <h4 style={{ fontSize: '1.1rem', marginBottom: '12px', fontWeight: '600' }}>
                        Analysis Result
                    </h4>
                    <p style={{ marginBottom: '8px', lineHeight: '1.6' }}>
                        <strong>Explanation:</strong> {analyzeResult[anomaly.IP].explanation}
                    </p>
                    <p style={{ marginBottom: '8px' }}>
                        <strong>Confidence:</strong> {analyzeResult[anomaly.IP].confidence}
                    </p>
                    <p>
                        <strong>Matched Lines:</strong> {analyzeResult[anomaly.IP].matched_lines}
                    </p>
                    </div>
                )}
                </div>
            );
            })}
        </div>
        )}
    </div>
    );
}