import React from "react";
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import jwt from "jsonwebtoken";
import Cookies from "js-cookie";

interface UsernameState {
  value: string;
}

interface PasswordState {
  value: string;
}

const Login: React.FC = () => {
  const [username, setUserName] = useState<UsernameState>({ value: '' });
  const [password, setPassword] = useState<PasswordState>({ value: '' });

  const router = useRouter();

  const sessionToken = Cookies.get("sessionToken");

  if (sessionToken) {
    // Decode the JWT token (no verification)
    const decodedToken = jwt.decode(sessionToken) as jwt.JwtPayload;

    if (decodedToken && decodedToken.logged_in) {
      router.push("/dashboard");
    }
  }

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    if (username && password) {
      try {
        const response = await fetch("/api/api/users?action=login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "include",
          body: JSON.stringify({
            userName: username.value,
            password: password.value,
          }),
        });

        if (response.ok) {
          const responseData = await response.json();
          const { user, message } = responseData;
          window.location.href = '/dashboard';
        } else {
          if (response.status === 401) {
            alert("Invalid Login Attempt");
          } else {
            alert("Login Failed");
          }
        }
      } catch (error) {
        console.error("Error during login:", error);
        alert("An error occurred during login");
      }
    }
  }

  return (
    <section className="vh-100 container-fluid d-flex align-items-center justify-content-center darkColor pb-5">
      <section className="col-md-3 rounded blue p-5 border border-dark">
        <h2 className="text-center darkGreen font-weight-bold">Login Form</h2>
        <form className="loginForm" onSubmit={handleSubmit}>
          <div className="mb-3">
            <label htmlFor="username" className="form-label oliveGreen">
              Username
            </label>
            <input
              type="text"
              className="form-control darkColor border border-dark yellow"
              id="username"
              name="username"
              value={username.value}
              onChange={(e) => setUserName({ value: e.target.value })}
            />
          </div>
          <div className="mb-3">
            <label htmlFor="password" className="form-label oliveGreen">
              Password
            </label>
            <input
              type="password"
              className="form-control darkColor border border-dark yellow"
              id="password"
              name="password"
              value={password.value}
              onChange={(e) => setPassword({ value: e.target.value })}
            />
          </div>
          <div className="d-flex justify-content-center">
            <button
              type="submit"
              id="login"
              className="d-flex align-items-center btn"
            >
              <h1 className="bold text-slate-400 yellow">Log In</h1>
            </button>
          </div>
          <p className="mb-0 pt-3 text-center darkGreen">
            Don't have an account? Click here to{" "}
            <Link href="/signup" className="yellow">Sign Up.</Link>
          </p>
        </form>
      </section>
    </section>
  );
};

export default Login;
