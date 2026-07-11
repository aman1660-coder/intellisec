import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <div className="mesh flex min-h-screen items-center justify-center px-4 text-center">
      <div className="panel max-w-md rounded-lg p-8">
        <h1 className="text-4xl font-semibold text-white">404</h1>
        <p className="mt-3 text-slate-400">That route is not part of the IntelliSec workspace.</p>
        <Link className="btn-primary mt-6" to="/">Return home</Link>
      </div>
    </div>
  );
}
