// pages/404.js (or pages/404.tsx for TypeScript)
import Link from "next/link";

const NotFound = () => {
  return (
    <div>
      <h1>404 - Page Not Found</h1>
      <p>
        The page you are looking for might have been removed, had its name
        changed, or is temporarily unavailable.
      </p>
      <Link href="/">
        <p>Go back to the home page</p>
      </Link>
    </div>
  );
};

export default NotFound;
