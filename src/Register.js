import React, { useState } from 'react';
import axios from 'axios';

const Register = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const handleRegister = async () => {
    try {
      // Parola doğrulaması yap
      if (password !== confirmPassword) {
        alert('Passwords do not match.');
        return;
      }

      const response = await axios.post('http://localhost:5000/register', {
        email: email,
        password: password,
      });

      alert(response.data.message);  // Kayıt tamamlandı mesajını göster
    } catch (error) {
      console.error('Register error:', error);
    }
  };

  return (
    <div>
      <h2>Register</h2>
      <label>Email:</label>
      <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
      <br />
      <label>Password:</label>
      <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <br />
      <label>Confirm Password:</label>
      <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
      <br />
      <button onClick={handleRegister}>Register</button>
    </div>
  );
};

export default Register;
