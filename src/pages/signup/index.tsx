import React, { useState } from "react";
import Link from "next/link";
import Cookies from "js-cookie";
import jwt from "jsonwebtoken";
import { useRouter } from "next/router";

interface UsernameState {
  value: string;
}

interface PasswordState {
  value: string;
}

// Define a type for the expected error structure
interface ErrorResponse {
  original: {
    sqlMessage: string;
  };
}

// Type guard to check if the object has the expected structure
function isErrorResponse(data: unknown): data is ErrorResponse {
  return (
    typeof data === "object" &&
    data !== null &&
    "original" in data &&
    typeof (data as ErrorResponse).original === "object" &&
    (data as ErrorResponse).original !== null &&
    "sqlMessage" in (data as ErrorResponse).original &&
    typeof (data as ErrorResponse).original.sqlMessage === "string"
  );
}

export default function SignupForm() {
  const [userName, setUserName] = useState<UsernameState>({ value: "" });
  const [password, setPassword] = useState<PasswordState>({ value: "" });
  const router = useRouter();

  const sessionToken = Cookies.get("sessionToken");

  if (sessionToken) {
    // Decode the JWT token (no verification)
    const decodedToken = jwt.decode(sessionToken) as jwt.JwtPayload;

    if (decodedToken?.logged_in) {
      router.push("/dashboard");
    }
  }

  const handleSignup = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    try {
      const response: Response = await fetch(
        "/api/api/users",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          credentials: "include",
          body: JSON.stringify({
            userName: userName.value,
            password: password.value,
          }),
        }
      );

      if (response.ok) {
        // Signup successful, handle the response as needed
        router.push("/dashboard");
      } else {
        // Signup failed, handle the error response
        const errorData: unknown = await response.json();

        // Check if the errorData has the expected structure
        if (isErrorResponse(errorData)) {
          const errorMessage = errorData.original.sqlMessage;
          console.log(errorMessage);

          if (errorMessage.includes("Duplicate")) {
            alert("User with this name already exists.");
          } else {
            // Handle other errors or show a generic message
            alert("Signup failed. Please try again.");
          }
        } else {
          // Handle other errors or show a generic message
          alert("Signup failed. Please try again.");
        }
      }
    } catch (error: unknown) {
  console.error("Signup failed:", error);

  if (typeof error === "object" && error !== null && "error" in error) {
    const errorMessage = (error as { error: string }).error;

    if (errorMessage.includes("Duplicate")) {
      alert("User with this name already exists.");
    } else {
      // Handle other errors or show a generic message
      alert("Signup failed. Please try again.");
    }
  } else {
    // Handle other errors or show a generic message
    alert("Signup failed. Please try again.");
  }
}
}

  return (
    <section className="vh-100 container-fluid d-flex align-items-center justify-content-center darkColor pb-5">
      <section className="col-md-3 rounded blue p-5 border border-dark">
        <h2 className="text-center darkGreen font-weight-bold">Signup Form</h2>
        <form className="signUpForm" onSubmit={handleSignup}>
          <div className="mb-3">
            <label className="form-label oliveGreen" htmlFor="userName">
              Username
            </label>
            <input
              type="text"
              className="form-control darkColor border border-dark yellow"
              id="userName"
              value={userName.value}
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
              value={password.value}
              onChange={(e) => setPassword({ value: e.target.value })}
            />
          </div>
          <div className="d-flex justify-content-center">
            <button
              type="submit"
              id="signup"
              className="d-flex align-items-center btn"
            >
              <h1 className="bold text-slate-400 yellow">Sign Up</h1>
            </button>
          </div>
          <p className="mb-0 pt-3 text-center darkGreen">
            Already have an account? Click here to{" "}
            <Link href="/" className="yellow">
              Log In.
            </Link>
          </p>
        </form>
      </section>
    </section>
  );
}
