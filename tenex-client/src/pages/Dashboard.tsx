import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

interface FileData {
  ID: string;
  Filename: string;
  UploadedAt: string;
}

interface FilesResponse {
  files: FileData[];
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [message, setMessage] = useState<string>('');
  const [_, setUserId] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [files, setFiles] = useState<FileData[]>([]);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string>('');
  const [uploadSuccess, setUploadSuccess] = useState<string>('');

  useEffect(() => {
    const fetchProtectedData = async () => {
      try {
        const response = await fetch('http://localhost:4000/test', {
          method: 'GET',
          credentials: 'include',
        });

        if (response.ok) {
          const data = await response.json();
          if (data.user_id) {
            setUserId(data.user_id);
            setMessage(`Hi user ${data.user_id}`);
          } else {
            setMessage(data.message || JSON.stringify(data));
          }
        } else if (response.status === 401 || response.status === 403) {
          setError('Unauthorized');
        } else {
          setError('Failed to fetch data');
        }
      } catch (err) {
        setError('Failed to connect to server');
      } finally {
        setLoading(false);
      }
    };

    fetchProtectedData();
    fetchFiles();
  }, []);

  const fetchFiles = async () => {
    try {
      const response = await fetch('http://localhost:4000/files', {
        method: 'GET',
        credentials: 'include',
      });

      if (response.ok) {
        const data: FilesResponse = await response.json();
        setFiles(data.files || []);
      }
    } catch (err) {
      console.error('Failed to fetch files:', err);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const ext = file.name.split('.').pop()?.toLowerCase();
      if (ext === 'log' || ext === 'txt') {
        setSelectedFile(file);
        setUploadError('');
      } else {
        setUploadError('Only .log and .txt files are allowed');
        setSelectedFile(null);
      }
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setUploadError('Please select a file');
      return;
    }

    setUploading(true);
    setUploadError('');
    setUploadSuccess('');

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const response = await fetch('http://localhost:4000/upload', {
        method: 'POST',
        credentials: 'include',
        body: formData,
      });

      const data = await response.json();

      if (response.ok) {
        setUploadSuccess(data.message || 'File uploaded successfully');
        setSelectedFile(null);
        // Reset file input
        const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
        if (fileInput) fileInput.value = '';
        // Refresh file list
        fetchFiles();
      } else {
        setUploadError(data.error || 'Upload failed');
      }
    } catch (err) {
      setUploadError('Failed to upload file');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div style={{ maxWidth: '900px', margin: '0 auto', padding: '40px 20px' }}>
        <h1 style={{ fontSize: '2.5rem', marginBottom: '16px', fontWeight: 'bold' }}>
        User Dashboard Page
        </h1>
        {loading && <p style={{ color: '#666' }}>Loading...</p>}
        {error && (
        <p style={{ 
            background: '#fee', 
            border: '1px solid #fcc', 
            color: '#c33', 
            padding: '12px', 
            borderRadius: '4px' 
        }}>
            Error: {error}
        </p>
        )}
        {message && <p style={{ color: '#666', marginBottom: '24px' }}>{message}</p>}

        <hr style={{ border: 'none', borderTop: '1px solid #e0e0e0', margin: '32px 0' }} />

        <h2 style={{ fontSize: '1.75rem', marginBottom: '16px', fontWeight: '600' }}>
        Upload File
        </h2>
        <div style={{ marginBottom: '24px' }}>
        <input
            type="file"
            accept=".log,.txt"
            onChange={handleFileChange}
            disabled={uploading}
            style={{
            padding: '8px',
            marginBottom: '12px',
            border: '1px solid #ddd',
            borderRadius: '4px',
            display: 'block'
            }}
        />
        <button 
            onClick={handleUpload} 
            disabled={!selectedFile || uploading}
            style={{
            padding: '10px 20px',
            background: (!selectedFile || uploading) ? '#999' : '#2563eb',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            fontSize: '1rem',
            fontWeight: '500',
            cursor: (!selectedFile || uploading) ? 'not-allowed' : 'pointer'
            }}
        >
            {uploading ? 'Uploading...' : 'Upload'}
        </button>
        {uploadError && (
            <p style={{ 
            background: '#fee', 
            border: '1px solid #fcc', 
            color: '#c33', 
            padding: '12px', 
            borderRadius: '4px',
            marginTop: '12px'
            }}>
            {uploadError}
            </p>
        )}
        {uploadSuccess && (
            <p style={{ 
            background: '#efe', 
            border: '1px solid #cfc', 
            color: '#363', 
            padding: '12px', 
            borderRadius: '4px',
            marginTop: '12px'
            }}>
            {uploadSuccess}
            </p>
        )}
        </div>

        <hr style={{ border: 'none', borderTop: '1px solid #e0e0e0', margin: '32px 0' }} />

        <h2 style={{ fontSize: '1.75rem', marginBottom: '16px', fontWeight: '600' }}>
        Your Files
        </h2>
        {files.length === 0 ? (
        <p style={{ color: '#666', fontStyle: 'italic' }}>No files uploaded yet</p>
        ) : (
        <ul style={{ listStyle: 'none', padding: 0 }}>
            {files.map((file) => (
            <li 
                key={file.ID}
                style={{
                padding: '16px',
                marginBottom: '12px',
                border: '1px solid #e0e0e0',
                borderRadius: '6px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                background: '#fafafa'
                }}
            >
                <span style={{ flex: 1 }}>
                <strong>{file.Filename}</strong>
                <br />
                <span style={{ color: '#666', fontSize: '0.9rem' }}>
                    {new Date(file.UploadedAt).toLocaleString()}
                </span>
                </span>
                <button 
                onClick={() => navigate('/details', { state: { fileId: file.ID, filename: file.Filename } })}
                style={{
                    padding: '8px 16px',
                    background: '#16a34a',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    fontWeight: '500',
                    cursor: 'pointer'
                }}
                >
                Parse
                </button>
            </li>
            ))}
        </ul>
        )}
    </div>
    );
}