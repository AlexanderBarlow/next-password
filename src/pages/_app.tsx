import type { AppProps } from "next/app";
import Head from "next/head";
import "bootstrap/dist/css/bootstrap.min.css"; // Import Bootstrap CSS
import React from "react";
import Cookies from "js-cookie";
import { useEffect, useState } from "react";
import "../styles/globals.css";

async function logout(event: React.MouseEvent<HTMLAnchorElement, MouseEvent>) {
  event.preventDefault();
  Cookies.remove("sessionToken");
  document.location.replace("/");
}

function MyApp({ Component, pageProps }: AppProps) {
  const [hasSessionToken, setHasSessionToken] = useState(false);

  useEffect(() => {
    // Check if the sessionToken cookie exists
    const sessionToken = Cookies.get("sessionToken");
    setHasSessionToken(!!sessionToken);
  }, []);

  return (
    <>
      <Head>
        <meta charSet="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      </Head>
      <div className="">
        <nav className="navbar navbar-dark navbar-expand-lg darkColor">
          <div className="container-fluid justify-content-between">
            <h1 className="nav navbar-brand fw-bold fs-2 darkGreen">
              Password Tracker
            </h1>
            {hasSessionToken && (
              <a
                id="logout"
                className="nav navbar-brand fw-bold fs-2"
                onClick={logout}
              >
                <button className="darkGreen">Logout</button>
              </a>
            )}
          </div>
        </nav>
          <Component {...pageProps} />
      </div>
    </>
  );
}

export default MyApp;
