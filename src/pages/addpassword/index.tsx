import React, { useState } from 'react';
import { useRouter } from 'next/router';


const NewPassword: React.FC = () => {
  const [title, setTitle] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    try {
      const response = await fetch("/api/dashboard?action=new", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({
          title,
          username,
          password,
        }),
      });

      if (response.ok) {
        // Handle successful response
        console.log('Password added successfully');
        alert('Password added successfully');
        router.push('/dashboard')
      } else {
        // Handle error response
        console.error('Failed to add password:', await response.json());
      }
    } catch (error) {
      console.error('Error during form submission:', error);
    }
  };

  return (
    <section className="vh-100 container-fluid d-flex align-items-center justify-content-center darkColor pb-5">
      <div className="col-md-3 rounded blue p-5 border border-dark">
        <h2 className="text-center darkGreen font-weight-bold">New Password</h2>
        <p className="text-secondary text-center">
          Add a new password and information about the account it belongs to.
        </p>
        <form className="newPasswordForm" onSubmit={handleSubmit}>
          <div className="mb-3">
            <label className="form-label oliveGreen">Website Name</label>
            <input
              type="text"
              className="form-control darkColor border border-dark yellow"
              id="title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
          </div>
          <div className="mb-3">
            <label className="form-label oliveGreen">Username</label>
            <input
              type="text"
              className="form-control darkColor border border-dark yellow"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div className="mb-3">
            <label className="form-label oliveGreen">Password</label>
            <input
              type="password"
              className="form-control darkColor border border-dark yellow"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <div className="d-flex justify-content-center">
            <button type="submit" className="btn yellow darkColor" id="addPass">
              Add Password
            </button>
          </div>
        </form>
      </div>
    </section>
  );
};

export default NewPassword;
