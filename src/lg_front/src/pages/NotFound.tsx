import { Link } from 'react-router-dom';

export default function NotFoundPage() {
  return (
    <div className="py-16 text-center">
      <h1 className="text-lg font-semibold text-white">Page not found</h1>
      <p className="mt-2 text-sm text-slate-300">
        <Link to="/" className="text-sky-300 underline hover:text-sky-200">
          Go to the dashboard
        </Link>
      </p>
    </div>
  );
}
