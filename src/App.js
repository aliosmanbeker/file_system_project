import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';
import Register from './Register.js';

function App() {
  const [file, setFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [fileInfo, setFileInfo] = useState(null);
  const [sumResult, setSumResult] = useState(null);
  const [historyData, setHistoryData] = useState([]);
  const [showTable, setShowTable] = useState(false);

  const [userToken, setUserToken] = useState(localStorage.getItem('jwt-token'));


  useEffect(() => {
    const storedToken = localStorage.getItem('jwt-token');

    if (storedToken) {
      setUserToken(storedToken);
    }
    
    const fetchHistoryData = async () => {
      try {
        const response = await axios.get('http://localhost:5000/history', {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('jwt-token')}`,
          },
        });

        setHistoryData(response.data);
      } catch (error) {
        console.error('Error fetching history data:', error);
        
      }
    };

    if (userToken) {
      fetchHistoryData();
    }
  }, [userToken]);

  const handleFileChange = (event) => {
    const selectedFile = event.target.files[0];
    setFile(selectedFile);

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      setFileContent(content);

      const lineCount = content.split('\n').length;
      const fileSizeInBytes = selectedFile.size;
      const fileSizeInMB = fileSizeInBytes / (1024 * 1024);
      const fileCreatedDate = selectedFile.lastModifiedDate.toLocaleDateString();
      const fileModifiedDate = selectedFile.lastModifiedDate.toLocaleDateString();

      setFileInfo({
        size: fileSizeInMB.toFixed(2),
        lines: lineCount,
        createdDate: fileCreatedDate,
        modifiedDate: fileModifiedDate,
      });
    };
    reader.readAsText(selectedFile);
  };

  const Login = ({ onSuccess }) => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');

    const handleLogin = async () => {
      try {
        const response = await axios.post('http://localhost:5000/token', {
          email: email,
          password_hash: password,
        });

        if (response.status === 200) {
          const data = response.data;
          localStorage.setItem('jwt-token', data.token);
          onSuccess(data.token);
            alert('Welcome!');
        } else {
          throw Error('There was a problem in the login request');
        }
      } catch (error) {
        console.error('Login error:', error);
        alert('Incorrect email address or password.');
      }
    };

    return (
      <div>
        <h2>Login</h2>
        <label>Email:</label>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <br />
        <label>Password:</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <br />
        
        <button type="button" class="btn btn-success"onClick={handleLogin}>Login</button>
      </div>
    );
  };

  const handleSumButtonClick = async () => {
    try {
      if (fileContent.trim() === '') {
        alert('File content is empty!');
        return;
      }

      if (fileInfo && parseFloat(fileInfo.size) > 100) {
        alert('Adding cannot be done because the file size is larger than 100 MB.');
        return;
      }

      const response = await axios.post('http://localhost:5000/sum', {
        numbers: fileContent.split('\n').map(Number),
      });

      const sumResult = response.data.sum;
      const scientificNotation = parseFloat(sumResult).toExponential();
      setSumResult(scientificNotation);
    } catch (error) {
      console.error('Error:', error);
    }
  };

  const handleSaveToDatabase = async () => {
    try {
      if (!fileInfo) {
        alert('Dosya bilgileri eksik!');
        return;
      }

      const response = await axios.post('http://localhost:5000/save', {
        fileInfo: {
          fileName: file.name,
          fileSize: fileInfo.size,
          lines: fileInfo.lines,
          createdDate: fileInfo.createdDate,
          modifiedDate: fileInfo.modifiedDate,
        },
        sumResult: sumResult,
        success: true,
      });

      if (response.data.success) {
        alert('Saved successfully');
      } else {
        alert('Save operation failed');
      }
    } catch (error) {
      console.error('Error:', error);
    }
  };

  const handleViewHistoryClick = async () => {
    try {
      const response = await axios.get('http://localhost:5000/history', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('jwt-token')}`,
        },
      });
  
      
      if (response.status === 403) {
        alert('You must have admin authority for this operation.');
      } else {
        setShowTable(true);
      }
    } catch (error) {
      console.error('Error fetching history data:', error);
      alert('You must have admin authority for this operation.');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('jwt-token');
    setUserToken(null);

    setShowTable(false);
  };

  const handleLoginSuccess = (token) => {
    setUserToken(token);
  };

  return (
    <div className="App">
      {!userToken && (
        <div>
          <Login onSuccess={handleLoginSuccess} />
          <Register />
        </div>
      )}
      {userToken && (
        <div>
          <h2>Logged In</h2>
          
          <button type="button" class="btn btn-danger"onClick={handleLogout}>Logout</button>
        </div>
      )}
      <div>
        
        <input type="file" id="fileInput" style={{ display: 'none' }} onChange={handleFileChange} accept="text/plain" />
        <button onClick={() => document.getElementById('fileInput').click()}>Choose A File</button>
      </div>

      
      {fileInfo && (
        <div style={{ marginLeft: '100px' }}>
          <p>File size: {fileInfo.size} MB</p>
          <p>Number of Rows: {fileInfo.lines}</p>
          <p>Creation Date: {fileInfo.createdDate}</p>
          <p>Modified Date: {fileInfo.modifiedDate}</p>
          {sumResult !== null && <p>Total of Numbers in File: {sumResult}</p>}
          <button onClick={handleSaveToDatabase}>Save to Database</button>
        </div>
      )}
      <button onClick={handleSumButtonClick} disabled={!fileInfo || fileInfo.size > 100000000}>
        Add Numbers
      </button>
      <button onClick={handleViewHistoryClick}>View History</button>
      {showTable && (
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>IP Address</th>
              <th>Port</th>
              <th>File Name</th>
              <th>File Size</th>
              <th>Lines</th>
              <th>Created Date</th>
              <th>Modified Date</th>
              <th>Sum Result</th>
              <th>Success</th>
            </tr>
          </thead>
          <tbody>
            {historyData.map((entry, index) => (
              <tr key={index}>
                <td>{entry.timestamp}</td>
                <td>{entry.ip_address}</td>
                <td>{entry.port}</td>
                <td>{entry.file_name}</td>
                <td>{entry.file_size}</td>
                <td>{entry.lines}</td>
                <td>{entry.created_date}</td>
                <td>{entry.modified_date}</td>
                <td>{entry.sum_result}</td>
                <td>{entry.success}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default App;