
import React, { useState } from 'react';
import { useAuth } from './AuthContext';

export const LoginPanel: React.FC = () => {
  const { signIn } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await signIn(email, password);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Login failed'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[60vh] flex items-center justify-center p-6">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-md rounded-2xl border border-white/10 bg-slate-900 p-8 shadow-xl"
      >
        <h2 className="text-2xl font-bold text-white mb-2">
          Municipality Login
        </h2>

        <p className="text-sm text-slate-400 mb-6">
          Sign in to access municipal operations.
        </p>

        <label className="block text-sm text-slate-300 mb-2">
          Email
        </label>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          autoComplete="email"
          className="w-full rounded-lg bg-slate-800 border border-slate-700 px-4 py-3 text-white mb-4 outline-none focus:border-cyan-500"
          placeholder="Enter your email"
        />

        <label className="block text-sm text-slate-300 mb-2">
          Password
        </label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          autoComplete="current-password"
          className="w-full rounded-lg bg-slate-800 border border-slate-700 px-4 py-3 text-white mb-4 outline-none focus:border-cyan-500"
          placeholder="Enter your password"
        />

        {error && (
          <p className="text-sm text-red-400 mb-4">{error}</p>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 px-4 py-3 font-semibold text-white transition-colors"
        >
          {loading ? 'Signing in...' : 'Sign In'}
        </button>
      </form>
    </div>
  );
};
