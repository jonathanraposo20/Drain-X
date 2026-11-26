import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:http/http.dart' as http;
import '../../app/routes.dart';
import '../../models/user_session.dart';
import '../config/api_config.dart';
import 'secure_session_store.dart';

class AuthException implements Exception {
  final String message;
  final int? statusCode;

  AuthException(this.message, {this.statusCode});

  @override
  String toString() => 'AuthException: $message';
}

class AuthService with ChangeNotifier {
  static final AuthService _instance = AuthService._internal();

  factory AuthService() => _instance;

  AuthService._internal();

  UserSession? _currentSession;
  http.Client _httpClient = http.Client();
  SecureSessionStore _sessionStore = FlutterSecureSessionStore();
  Future<UserSession>? _refreshInFlight;

  @visibleForTesting
  set httpClient(http.Client client) => _httpClient = client;

  @visibleForTesting
  set sessionStoreForTesting(SecureSessionStore store) => _sessionStore = store;

  @visibleForTesting
  void setSessionForTesting(UserSession? session) => _currentSession = session;

  UserSession? get currentSession => _currentSession;

  bool get isLoggedIn => _currentSession != null;

  UserRole? get currentRole => _currentSession?.role;

  bool get isDemo => _currentSession?.isDemo ?? true;

  /// Demo sessions strictly return no bearer token.
  String? get currentToken {
    final session = _currentSession;
    if (session == null || session.isDemo) return null;
    return session.token;
  }

  /// Restores the last authenticated session from encrypted platform storage.
  /// Expired access tokens are refreshed before the session is returned.
  /// A transient network failure retains the refresh token for a later retry.
  Future<UserSession?> restoreSession() async {
    try {
      final stored = await _sessionStore.readSession();
      if (stored == null || stored.isEmpty) return null;

      final decoded = jsonDecode(stored);
      if (decoded is! Map<String, dynamic>) {
        await _sessionStore.clearSession();
        return null;
      }

      final restored = UserSession.fromJson(decoded);
      if (!restored.isAuthenticated ||
          restored.refreshToken == null ||
          restored.refreshToken!.isEmpty) {
        await _sessionStore.clearSession();
        return null;
      }

      _currentSession = restored;
      notifyListeners();

      if (restored.isTokenExpired) {
        try {
          return await refreshSession();
        } on AuthException catch (error) {
          // Invalid/revoked refresh credentials are cleared by refreshSession.
          // Network/server failures retain the persisted session for retry.
          if (error.statusCode == 400 || error.statusCode == 401) {
            return null;
          }
          return restored;
        }
      }
      return restored;
    } catch (_) {
      // Storage corruption is not allowed to create an authenticated session.
      _currentSession = null;
      try {
        await _sessionStore.clearSession();
      } catch (_) {}
      notifyListeners();
      return null;
    }
  }

  /// Starts a verified Demo session. Demo credentials are never persisted.
  UserSession loginDemo({
    required UserRole role,
    required String displayName,
    String? email,
    String? assignedTeam,
  }) {
    unawaited(_clearPersistedSession());
    final prefix = role == UserRole.citizen
        ? 'DEMO-CITIZEN'
        : (role == UserRole.municipality ? 'DEMO-MUNI' : 'DEMO-WORKER');
    final suffix = DateTime.now().millisecondsSinceEpoch % 10000;
    _currentSession = UserSession(
      userId: '$prefix-$suffix',
      name: displayName,
      email: email ??
          '${displayName.toLowerCase().replaceAll(' ', '.')}@drainx-demo.local',
      role: role,
      authType: AuthType.demo,
      token: null,
      assignedTeam: assignedTeam,
    );
    notifyListeners();
    return _currentSession!;
  }

  /// Supabase password grant. Authorization role is read only from app_metadata.
  Future<UserSession> loginWithCredentials({
    required String email,
    required String password,
  }) async {
    final supabaseUrl = ApiConfig.supabaseUrl;
    final supabaseAnonKey = ApiConfig.supabaseAnonKey;
    if (supabaseUrl == null ||
        supabaseUrl.isEmpty ||
        supabaseAnonKey == null ||
        supabaseAnonKey.isEmpty) {
      throw AuthException(
        'Production Supabase Auth is not configured. '
        'Set SUPABASE_URL and SUPABASE_ANON_KEY in ApiConfig or use Demo Mode.',
      );
    }

    final endpoint = Uri.parse(
      '${supabaseUrl.replaceAll(RegExp(r'/+$'), '')}/auth/v1/token?grant_type=password',
    );
    try {
      final response = await _httpClient
          .post(
            endpoint,
            headers: {
              'Content-Type': 'application/json',
              'apikey': supabaseAnonKey,
            },
            body: jsonEncode({'email': email.trim(), 'password': password}),
          )
          .timeout(const Duration(seconds: 12));

      if (response.statusCode != 200) {
        throw _authErrorFromResponse(response);
      }
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      final session = _sessionFromAuthResponse(data, fallbackEmail: email.trim());
      await _persistSession(session);
      _currentSession = session;
      notifyListeners();
      return session;
    } on AuthException {
      rethrow;
    } catch (error) {
      throw AuthException('Network error connecting to authentication service: $error');
    }
  }

  /// Refreshes an access token using Supabase's rotating refresh-token grant.
  /// Concurrent callers share one request so a one-time refresh token is not
  /// accidentally consumed multiple times.
  Future<UserSession> refreshSession() {
    final existing = _refreshInFlight;
    if (existing != null) return existing;

    final operation = _refreshSessionInternal();
    _refreshInFlight = operation;
    return operation.whenComplete(() {
      if (identical(_refreshInFlight, operation)) {
        _refreshInFlight = null;
      }
    });
  }

  Future<UserSession> _refreshSessionInternal() async {
    final current = _currentSession;
    final refreshToken = current?.refreshToken;
    final supabaseUrl = ApiConfig.supabaseUrl;
    final anonKey = ApiConfig.supabaseAnonKey;
    if (current == null ||
        !current.isAuthenticated ||
        refreshToken == null ||
        refreshToken.isEmpty ||
        supabaseUrl == null ||
        supabaseUrl.isEmpty ||
        anonKey == null ||
        anonKey.isEmpty) {
      handleUnauthorized(redirect: false);
      throw AuthException('No valid refresh credentials are available.', statusCode: 401);
    }

    final endpoint = Uri.parse(
      '${supabaseUrl.replaceAll(RegExp(r'/+$'), '')}/auth/v1/token?grant_type=refresh_token',
    );
    try {
      final response = await _httpClient
          .post(
            endpoint,
            headers: {
              'Content-Type': 'application/json',
              'apikey': anonKey,
            },
            body: jsonEncode({'refresh_token': refreshToken}),
          )
          .timeout(const Duration(seconds: 12));

      if (response.statusCode != 200) {
        final error = _authErrorFromResponse(response);
        if (response.statusCode == 400 || response.statusCode == 401) {
          handleUnauthorized();
        }
        throw error;
      }

      final data = jsonDecode(response.body) as Map<String, dynamic>;
      final refreshed = _sessionFromAuthResponse(
        data,
        fallbackEmail: current.email,
        fallbackName: current.name,
        fallbackRefreshToken: refreshToken,
      );
      try {
        await _persistSession(refreshed);
      } on AuthException {
        // Supabase has already rotated the refresh token. If secure storage
        // cannot save its replacement, the old token may no longer be usable.
        // Fail closed rather than retaining credentials that can strand the
        // user in a broken session after the next request or app restart.
        await _invalidateAfterRefreshPersistenceFailure();
        throw AuthException(
          'Your session was refreshed, but the new credentials could not be '
          'saved securely. Please sign in again.',
        );
      }
      _currentSession = refreshed;
      notifyListeners();
      return refreshed;
    } on AuthException {
      rethrow;
    } catch (error) {
      throw AuthException('Unable to refresh authentication session: $error');
    }
  }

  UserSession _sessionFromAuthResponse(
    Map<String, dynamic> data, {
    String? fallbackEmail,
    String? fallbackName,
    String? fallbackRefreshToken,
  }) {
    final accessToken = data['access_token'] as String?;
    if (accessToken == null || accessToken.isEmpty) {
      throw AuthException('Authentication response did not include an access token.');
    }
    final user = data['user'] as Map<String, dynamic>?;
    if (user == null || user['id'] is! String) {
      throw AuthException('Authentication response did not include a valid user.');
    }
    final appMetadata = user['app_metadata'] as Map<String, dynamic>? ?? {};
    final role = UserRole.fromString(appMetadata['role'] as String?);
    final userMetadata = user['user_metadata'] as Map<String, dynamic>? ?? {};
    final email = user['email'] as String? ?? fallbackEmail;
    final displayName = userMetadata['full_name'] as String? ??
        userMetadata['name'] as String? ??
        fallbackName ??
        (email?.split('@').first ?? 'DRAIN-X User');
    final expiresIn = data['expires_in'] as int? ?? 3600;

    return UserSession(
      userId: user['id'] as String,
      name: displayName,
      email: email,
      role: role,
      authType: AuthType.authenticated,
      token: accessToken,
      refreshToken: data['refresh_token'] as String? ?? fallbackRefreshToken,
      expiresAt: DateTime.now().add(Duration(seconds: expiresIn)),
      assignedTeam: (appMetadata['team'] ?? appMetadata['assigned_team']) as String?,
    );
  }

  AuthException _authErrorFromResponse(http.Response response) {
    String message = 'Authentication failed.';
    try {
      final body = jsonDecode(response.body) as Map<String, dynamic>;
      message = body['error_description'] as String? ??
          body['msg'] as String? ??
          body['message'] as String? ??
          body['error'] as String? ??
          message;
    } catch (_) {}
    return AuthException(message, statusCode: response.statusCode);
  }

  Future<void> _persistSession(UserSession session) async {
    try {
      await _sessionStore.writeSession(jsonEncode(session.toJson()));
    } catch (error) {
      throw AuthException('Could not securely persist the authentication session: $error');
    }
  }

  /// Fails closed when Supabase rotates a refresh token but the replacement
  /// cannot be persisted. The previous refresh token may already be invalid.
  Future<void> _invalidateAfterRefreshPersistenceFailure() async {
    final hadSession = _currentSession != null;
    _currentSession = null;
    try {
      await _sessionStore.clearSession();
    } catch (_) {
      // A later restore will reject the stale token with Supabase and clear it.
    }
    if (hadSession) notifyListeners();
    try {
      AppRoutes.navigatorKey.currentState?.pushNamedAndRemoveUntil(
        AppRoutes.welcome,
        (route) => false,
      );
    } catch (_) {
      // Safe no-op without an active Navigator (e.g. unit tests).
    }
  }

  Future<void> _clearPersistedSession() async {
    try {
      await _sessionStore.clearSession();
    } catch (_) {}
  }

  /// Clears credentials after a confirmed unauthorized response.
  void handleUnauthorized({bool redirect = true}) {
    final hadSession = _currentSession != null;
    _currentSession = null;
    unawaited(_clearPersistedSession());
    if (hadSession) notifyListeners();
    if (redirect) {
      try {
        AppRoutes.navigatorKey.currentState?.pushNamedAndRemoveUntil(
          AppRoutes.welcome,
          (route) => false,
        );
      } catch (_) {
        // Safe no-op without an active Navigator (e.g. unit tests).
      }
    }
  }

  /// Clears the in-memory and persisted session.
  void logout() {
    final hadSession = _currentSession != null;
    _currentSession = null;
    unawaited(_clearPersistedSession());
    if (hadSession) notifyListeners();
  }

  bool checkAccess(UserRole requiredRole) {
    final session = _currentSession;
    if (session == null) return false;
    return session.canAccess(requiredRole);
  }
}
