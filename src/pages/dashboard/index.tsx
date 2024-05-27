import type { NextPage } from "next";
import { useRouter } from "next/router";
import Cookies from "js-cookie";
import jwt from "jsonwebtoken";
import { useEffect, useState } from "react";
import PasswordCard from "../../../components/PasswordCard";

interface Password {
  id: number;
  title?: string;
  user_name?: string;
  user_password?: string;
}

interface DashboardProps {
  loggedIn: boolean;
  passwordData: Password[];
}

interface DecryptedData {
  decryptedData: string;
}

interface ErrorData {
  message: string;
}

const Dashboard: NextPage<DashboardProps> = () => {
  const [issue, setAlert] = useState(false);
  const [isAdmin, setAdmin] = useState(false);
  const [passwordData, setPasswordData] = useState<Password[]>([]);
  const [allPasswords, setAllPasswords] = useState<Password[]>([]);
  const router = useRouter();

  useEffect(() => {
    const fetchUserData = async () => {
      const sessionToken = await Cookies.get("sessionToken");

      if (sessionToken) {
        try {
          const decodedToken = jwt.decode(sessionToken) as jwt.JwtPayload;
          console.log(decodedToken);
          

          if (decodedToken && decodedToken.logged_in) {
            setAlert(false);

            if (decodedToken.user_name === "AdminAlex") {
              setAdmin(true);
              const response = await fetch("/api/", {
                method: "GET",
                headers: {
                  "Content-Type": "application/json",
                  Authorization: `Bearer ${sessionToken}`,
                },
                credentials: "include",
              });

              if (response.ok) {
                const data: [] = await response.json();
                setAllPasswords(data);
              } else {
                console.error("Fetch failed:", response.statusText);
              }
            } else {
              // Fetch user-specific data for non-admin users
              const response = await fetch("/api/dashboard/", {
                method: "GET",
                headers: {
                  "Content-Type": "application/json",
                  Authorization: `Bearer ${sessionToken}`, // Include the JWT in the Authorization header
                },
                credentials: "include",
              });

              if (response.ok) {
                const data = await response.json();
                setPasswordData(data.passwords);
                // Handle the data as needed
              } else {
                // Handle error response
                console.error("Fetch failed:", response.statusText);
              }
            }
          }
        } catch (error) {
          console.error("Error decoding JWT token:", error);
          alert("You must login to continue.");
          setAlert(true);
          // Use setTimeout to delay the redirection and allow the user to see the alert
          setTimeout(() => router.push("/"), 2000);
        }
      } else {
        console.error("No session token found.");
        alert("You must login to continue.");
        setAlert(true);
        // Use setTimeout to delay the redirection and allow the user to see the alert
        setTimeout(() => router.push("/"), 2000);
      }
    };

    fetchUserData();
  }, []);

  const onCopy = async (id: number) => {
    const copiedData = passwordData.find((item) => item.id === id);

    if (copiedData) {
      try {
        const sessionToken = Cookies.get("sessionToken");

        const response = await fetch(`/api/dashboard/copy/${id}`, {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${sessionToken}`,
          },
          credentials: "include",
        });

        if (response.ok) {
          const data: DecryptedData = await response.json();
          const decryptedPassword = data.decryptedData;

          navigator.clipboard.writeText(decryptedPassword).then(
            function () {
              alert("Copying to clipboard was successful!");
            },
            function () {
              alert("Could not copy text.");
            }
          );
        } else {
          const errorData: ErrorData = await response.json();
          console.error("Fetch failed:", response.statusText, errorData);
          alert(`Failed to copy: ${errorData.message}`);
        }
      } catch (error) {
        console.error("Error during fetch:", error);
        alert("An unexpected error occurred.");
      }
    }
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Get the session token from cookies
        const sessionToken = Cookies.get("sessionToken");

        if (sessionToken) {
          const response = await fetch("/api/dashboard/", {
            method: "GET",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${sessionToken}`, // Include the JWT in the Authorization header
            },
            credentials: "include",
          });

          if (response.ok) {
            const data = await response.json();
            setPasswordData(data.password);
            // Handle the data as needed
          } else {
            // Handle error response
            console.error("Fetch failed:", response.statusText);
          }
        } else {
          console.error("No session token found.");
        }
      } catch (error) {
        console.error("Error during fetch:", error);
      }
    };

    fetchData();
  }, []);

  const onDelete = async (id: number) => {
    const sessionToken = Cookies.get("sessionToken");

    try {
      const response = await fetch(`/api/api/passwords/${id}`, {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${sessionToken}`,
        },
        credentials: "include",
      });

      if (response.ok) {
        setPasswordData((prevData) =>
          prevData.filter((item) => item.id !== id)
        );
        alert(`Password with ID ${id} deleted successfully`);
      } else {
        const errorData: ErrorData = await response.json();
        console.error("Delete failed:", response.statusText, errorData);
        alert(`Failed to delete: ${errorData.message}`);
      }
    } catch (error) {
      console.error("Error during fetch:", error);
      alert("An unexpected error occurred.");
    }
  };

  const [revealedPasswordId, setRevealedPasswordId] = useState<number | null>(
    null
  );

  // Event handler for mouse down
  const handleMouseDown = (event: React.MouseEvent, item: Password) => {
    const itemId = item.id ?? 0; // Use 0 as a default value if item.id is undefined
    if (event.button === 0) {
      setRevealedPasswordId(itemId);
    }
  };

  // Event handler for mouse up
  const handleMouseUp = () => {
    setRevealedPasswordId(null);
  };

  const updateUserPassword = async (userId: number | undefined) => {
    if (userId === undefined) {
      console.error("User ID is undefined");
      return;
    }

    try {
      const newPassword = prompt("Enter the new password:");

      if (!newPassword) {
        // User canceled the operation
        return;
      }

      const sessionToken = Cookies.get("sessionToken");

      const response = await fetch("/api/api/users/updatep", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${sessionToken}`,
        },
        credentials: "include",
        body: JSON.stringify({
          id: userId,
          newPassword: newPassword,
        }),
      });

      if (response.ok) {
        alert("Password updated successfully!");
      } else {
        const errorData: ErrorData = await response.json();
        console.error("Update failed:", response.statusText, errorData);
        throw new Error(`Failed to update password: ${errorData.message}`);
      }
    } catch (error) {
      // Do nothing or handle the error if needed
      throw error; // Propagate the error to the calling code
    }
  };
  return (
    <div className="container-fluid darkColor flex min-h-screen h-fit items-center justify-center pb-5">
      <div className="blue border-dark mt-3 w-full rounded border p-5 text-center md:w-8/12">
        {isAdmin ? (
          <div>
            <h1 className="darkGreen mb-2">Welcome Admin!</h1>
            {allPasswords.map((item) => (
              <div
                key={item.id}
                onMouseDown={(e) => handleMouseDown(e, item)}
                className="custom-card mx-auto mb-3 border p-3"
              >
                <p className="darkGreen">Username: {item.user_name}</p>
                <p className="oliveGreen">ID: {item.id}</p>
                <p className="yellow">
                  Password:{" "}
                  {revealedPasswordId === item.id
                    ? item.user_password
                    : "********"}
                </p>
                <button
                  data-id={item.id}
                  className="darkGreen"
                  onClick={() => updateUserPassword(item.id)}
                >
                  Update Password
                </button>
              </div>
            ))}
          </div>
        ) : (
          <>
            <h2 className="darkGreen mb-4 text-center font-bold md:text-left">
              Dashboard
            </h2>
            {issue ? (
              <div>
                <h1>You Must Login To Access This Page.</h1>
              </div>
            ) : passwordData && passwordData.length > 0 ? (
              <div className="dash flex flex-wrap justify-center gap-4">
                {passwordData.map((item) => (
                  <div key={item.id} className="mb-3">
                    <PasswordCard
                      item={item}
                      onCopy={onCopy}
                      onDelete={onDelete}
                    />
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center">
                <div className="mb-4 text-center">
                  <p className="oliveGreen">Your dashboard is empty.</p>
                </div>
              </div>
            )}
            {!isAdmin && (
              <div className="flex justify-center">
                <a href="/addpassword">
                  <button className="btn yellow">Add Password</button>
                </a>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
