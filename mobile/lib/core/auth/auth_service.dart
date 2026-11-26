import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:supabase_flutter/supabase_flutter.dart' as supabase;

import '../../app/routes.dart';
import '../../models/user_session.dart';
import '../config/api_config.dart';

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
  supabase.SupabaseClient? _supabaseClient;
  StreamSubscription<supabase.AuthState>? _authStateSubscription;
  Future<void>? _initializationFuture;
  String? _initializationError;

  /// Initializes Supabase once and restores its persisted session before the
  /// first screen is rendered. The SDK owns refresh-token rotation and storage.
  Future<void> initialize() =>
      _initializationFuture ??= _initializeSupabase();

  Future<void> _initializeSupabase() async {
    final url = ApiConfig.supabaseUrl;
    final key = ApiConfig.supabaseAnonKey;
    if (url == null || url.isEmpty || key == null || key.isEmpty) {
      return; // Local/demo builds remain usable without production credentials.
    }

    try {
      await supabase.Supabase.initialize(
        url: url,
        publishableKey: key,
        authOptions: const supabase.FlutterAuthClientOptions(
          autoRefreshToken: true,
          persistSession: true,
        ),
      );
      _attachSupabaseClient(supabase.Supabase.instance.client);
      _initializationError = null;
    } catch (error, stackTrace) {
      // Keep Demo Mode available if Supabase is temporarily unreachable.
      _initializationError = error.toString();
      // Allow a later login attempt to retry initialization after transient
      // network failures instead of reusing this completed failed future.
      _initializationFuture = null;
      debugPrint('DRAIN-X Supabase initialization failed: $error');
      debugPrintStack(stackTrace: stackTrace);
    }
  }

  void _attachSupabaseClient(supabase.SupabaseClient client) {
    _supabaseClient = client;
    _applySupabaseSession(client.auth.currentSession);

    unawaited(_authStateSubscription?.cancel() ?? Future<void>.value());
    _authStateSubscription = client.auth.onAuthStateChange.listen(
      (state) {
        if (state.session != null) {
          _applySupabaseSession(state.session);
        } else if (_currentSession?.isAuthenticated == true) {
          _currentSession = null;
          notifyListeners();
        }
      },
      onError: (Object error, StackTrace stackTrace) {
        debugPrint('DRAIN-X Supabase auth-state stream error: $error');
      },
    );
  }

  void _applySupabaseSession(supabase.Session? session) {
    if (session == null) return;
    final user = session.user;
    // Only signed app_metadata may determine authorization roles.
    final appMetadata = user.appMetadata;
    final userMetadata = user.userMetadata ?? const <String, dynamic>{};
    final email = user.email;
    final displayName = userMetadata['full_name'] as String? ??
        userMetadata['name'] as String? ??
        (email == null || email.isEmpty ? 'DRAIN-X User' : email.split('@').first);
    final expiresAt = session.expiresAt;

    _currentSession = UserSession(
      userId: user.id,
      name: displayName,
      email: email,
      role: UserRole.fromString(appMetadata['role'] as String? ?? 'citizen'),
      authType: AuthType.authenticated,
      token: session.accessToken,
      refreshToken: session.refreshToken,
      expiresAt: expiresAt == null
          ? null
          : DateTime.fromMillisecondsSinceEpoch(expiresAt * 1000, isUtc: true),
      assignedTeam: appMetadata['assigned_team'] as String? ??
          appMetadata['team'] as String?,
    );
    notifyListeners();
  }

  @visibleForTesting
  void setSupabaseClientForTesting(supabase.SupabaseClient? client) {
    unawaited(_authStateSubscription?.cancel() ?? Future<void>.value());
    _authStateSubscription = null;
    _supabaseClient = client;
    if (client != null) _attachSupabaseClient(client);
  }

  @visibleForTesting
  void setSessionForTesting(UserSession? session) => _currentSession = session;

  UserSession? get currentSession => _currentSession;
  bool get isLoggedIn => _currentSession != null;
  UserRole? get currentRole => _currentSession?.role;
  bool get isDemo => _currentSession?.isDemo ?? true;

  /// Demo sessions never expose a bearer token. For real sessions, read the
  /// SDK's current token so a just-completed refresh is immediately reflected.
  String? get currentToken {
    if (_currentSession == null || _currentSession!.isDemo) return null;
    return _supabaseClient?.auth.currentSession?.accessToken ??
        _currentSession?.token;
  }

  /// Refresh an expired SDK session before a protected backend request.
  /// Normal refresh scheduling and rotation remain managed by Supabase.
  Future<void> ensureValidSession() async {
    final current = _currentSession;
    if (current == null || current.isDemo) return;

    final client = _supabaseClient;
    if (client == null) {
      if (current.isTokenExpired) {
        handleUnauthorized(redirect: false);
        throw AuthException('Authentication token has expired.', statusCode: 401);
      }
      return;
    }

    final sdkSession = client.auth.currentSession;
    if (sdkSession == null) {
      handleUnauthorized(redirect: false);
      throw AuthException('Supabase session is no longer available.', statusCode: 401);
    }

    if (!sdkSession.isExpired) {
      if (_currentSession?.token != sdkSession.accessToken ||
          _currentSession?.refreshToken != sdkSession.refreshToken) {
        _applySupabaseSession(sdkSession);
      }
      return;
    }

    try {
      final refreshed = await client.auth.refreshSession();
      final validSession = refreshed.session ?? client.auth.currentSession;
      if (validSession == null || validSession.isExpired) {
        handleUnauthorized(redirect: false);
        throw AuthException('Supabase session could not be refreshed.', statusCode: 401);
      }
      _applySupabaseSession(validSession);
    } catch (error) {
      if (error is AuthException) rethrow;
      if (client.auth.currentSession == null) {
        handleUnauthorized(redirect: false);
        throw AuthException(
          'Supabase session expired. Please sign in again.',
          statusCode: 401,
        );
      }
      // Preserve the session on transient connectivity failures.
      throw AuthException(
        'Unable to refresh the Supabase session: $error',
        statusCode: 0,
      );
    }
  }

  /// Start a demo session without fabricating production claims.
  UserSession loginDemo({
    required UserRole role,
    required String displayName,
    String? email,
    String? assignedTeam,
  }) {
    if (_supabaseClient?.auth.currentSession != null) {
      unawaited(_signOutSupabaseLocally());
    }

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

  /// Supabase SDK sign-in. It persists the session and rotates refresh tokens.
  Future<UserSession> loginWithCredentials({
    required String email,
    required String password,
  }) async {
    var client = _supabaseClient;
    if (client == null) {
      await initialize();
      client = _supabaseClient;
    }

    if (client == null) {
      final reason = _initializationError == null
          ? 'Set SUPABASE_URL and SUPABASE_ANON_KEY in ApiConfig or use Demo Mode.'
          : 'Supabase could not initialize: $_initializationError';
      throw AuthException('Production Supabase Auth is not configured. $reason');
    }

    try {
      final response = await client.auth.signInWithPassword(
        email: email.trim(),
        password: password,
      );
      final session = response.session ?? client.auth.currentSession;
      if (session == null) {
        throw AuthException('Supabase sign-in completed without an active session.');
      }
      _applySupabaseSession(session);
      return _currentSession!;
    } on supabase.AuthException catch (error) {
      throw AuthException(error.message);
    } on AuthException {
      rethrow;
    } catch (error) {
      throw AuthException('Network error connecting to authentication service: $error');
    }
  }

  Future<void> _signOutSupabaseLocally() async {
    final client = _supabaseClient;
    if (client == null) return;
    try {
      await client.auth.signOut(scope: supabase.SignOutScope.local);
    } catch (error) {
      debugPrint('DRAIN-X Supabase sign-out failed: $error');
    }
  }

  /// Clears the local session and persisted SDK session on this device only.
  void logout() {
    final shouldSignOut = _supabaseClient?.auth.currentSession != null ||
        _currentSession?.isAuthenticated == true;
    _currentSession = null;
    notifyListeners();
    if (shouldSignOut) unawaited(_signOutSupabaseLocally());
  }

  void handleUnauthorized({bool redirect = true}) {
    logout();
    if (redirect) {
      try {
        AppRoutes.navigatorKey.currentState?.pushNamedAndRemoveUntil(
          AppRoutes.welcome,
          (route) => false,
        );
      } catch (_) {
        // Safe no-op when executing in unit tests without a Navigator.
      }
    }
  }

  bool checkAccess(UserRole requiredRole) {
    if (_currentSession == null) return false;
    return _currentSession!.canAccess(requiredRole);
  }
}
