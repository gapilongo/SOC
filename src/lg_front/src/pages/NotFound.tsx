import { Link } from 'react-router-dom';

export default function NotFoundPage() {
  return (
    <div className="py-16 text-center">
      <h1 className="text-lg font-semibold text-fg">Page not found</h1>
      <p className="mt-2 text-sm text-secondary">
        <Link to="/" className="text-link underline hover:text-link">
          Go to the dashboard
        </Link>
      </p>
    </div>
  );
}
