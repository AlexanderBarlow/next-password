import { useRouter } from "next/router";
import { useState, useEffect } from "react";
import Cookies from "js-cookie";
import jwt from "jsonwebtoken";

interface Response {
  status: number;
}

const UpdatePassword = () => {
  const router = useRouter();
  const id = router.query!.id!; // Use non-null assertion operator
  const [title, setTitle] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  useEffect(() => {
    // Use an empty string as the default value if Cookies.get("sessionToken") is undefined
    const sessionToken = Cookies.get("sessionToken") || "";

    try {
      // Decode the JWT token (no verification)
      const decodedToken = jwt.decode(sessionToken) as jwt.JwtPayload;

      if (!decodedToken?.logged_in) {
        console.error("User not logged in.");
        alert("You must login to continue.");
        // Redirect to login page or handle accordingly
        router.replace("/");
      }

      if (
        id &&
        ((typeof id === "string" && !/^\d+$/.test(id)) ||
          (Array.isArray(id) &&
            id.length > 0 &&
            typeof id[0] === "string" &&
            !/^\d+$/.test(id[0]?.toString())))
      ) {
        console.error("Invalid ID parameter.");
        alert("Invalid ID parameter.");
        // Redirect to dashboard or handle accordingly
        router.replace("/dashboard");
      }
    } catch (error) {
      console.error("Error decoding JWT token:", error);
      alert("An unexpected error occurred.");
      // Redirect to login page or handle accordingly
      router.replace("/");
    }
  }, [router]);

  const updatePassword = async (event: React.FormEvent) => {
    event.preventDefault();

    if (id) {
      const response: Response = await fetch(
        `http://localhost:3001/api/passwords/${id}`,
        {
          method: "PUT",
          body: JSON.stringify({ title, username, password }),
          headers: { "Content-Type": "application/json" },
        }
      );

      if (response.status === 200) {
        router.replace("/dashboard");
      } else {
        alert("Failed to update password");
      }
    }
  };

  return (
    <section className="container-fluid darkColor">
      <section className="row justify-content-center">
        <section className="col-3 p-5 bg-white border rounded align-self-center">
          <h2>Update Password</h2>
          <p className="text-secondary">
            Add a new password and information about the account it belongs to.
          </p>
          <form
            className="newPasswordForm"
            onSubmit={updatePassword}
            data-id={`${id}`}
          >
            <div className="mb-3">
              <label className="form-label">Website Name</label>
              <input
                id="title"
                type="text"
                className="form-control"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
            </div>
            <div className="mb-3">
              <label className="form-label">Username</label>
              <input
                id="username"
                type="text"
                className="form-control"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <div className="mb-3">
              <label className="form-label">Password</label>
              <input
                id="password"
                type="password"
                className="form-control"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <button type="submit" className="btn btn-primary">
              Update Password
            </button>
          </form>
        </section>
      </section>
    </section>
  );
};

export default UpdatePassword;
