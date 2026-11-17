import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:http/http.dart' as http;
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
  http.Client _httpClient = http.Client();

  @visibleForTesting
  set httpClient(http.Client client) => _httpClient = client;

  @visibleForTesting
  void setSessionForTesting(UserSession? session) => _currentSession = session;

  UserSession? get currentSession => _currentSession;

  bool get isLoggedIn => _currentSession != null;

  UserRole? get currentRole => _currentSession?.role;

  bool get isDemo => _currentSession?.isDemo ?? true;

  /// Returns the active bearer token only for authenticated sessions.
  /// Demo sessions strictly return null to prevent leaking fake credentials.
  String? get currentToken {
    if (_currentSession == null || _currentSession!.isDemo) {
      return null;
    }
    return _currentSession?.token;
  }

  /// Start a verified Demo session for hackathon evaluation or competition preview.
  /// Generates a structured demo session without fabricating production claims.
  UserSession loginDemo({
    required UserRole role,
    required String displayName,
    String? email,
    String? assignedTeam,
  }) {
    final prefix = role == UserRole.citizen
        ? 'DEMO-CITIZEN'
        : (role == UserRole.municipality ? 'DEMO-MUNI' : 'DEMO-WORKER');
    final suffix = DateTime.now().millisecondsSinceEpoch % 10000;
    final generatedId = '$prefix-$suffix';

    _currentSession = UserSession(
      userId: generatedId,
      name: displayName,
      email: email ?? '${displayName.toLowerCase().replaceAll(' ', '.')}@drainx-demo.local',
      role: role,
      authType: AuthType.demo,
      token: null, // Strictly null for demo sessions
      assignedTeam: assignedTeam,
    );

    notifyListeners();
    return _currentSession!;
  }

  /// Production Supabase Auth integration via standard REST API.
  /// Exchanges email and password directly with Supabase Auth endpoint:
  /// POST {supabaseUrl}/auth/v1/token?grant_type=password
  ///
  /// Extracts role claim strictly from `app_metadata.role` (anti-privilege escalation).
  Future<UserSession> loginWithCredentials({
    required String email,
    required String password,
  }) async {
    final supabaseUrl = ApiConfig.supabaseUrl;
    final supabaseAnonKey = ApiConfig.supabaseAnonKey;

    if (supabaseUrl == null || supabaseUrl.isEmpty || supabaseAnonKey == null || supabaseAnonKey.isEmpty) {
      throw AuthException(
        'Production Supabase Auth is not configured. '
        'Set SUPABASE_URL and SUPABASE_ANON_KEY in ApiConfig or use Demo Mode.',
      );
    }

    final tokenEndpoint = Uri.parse('${supabaseUrl.replaceAll(RegExp(r'/+$'), '')}/auth/v1/token?grant_type=password');

    try {
      final response = await _httpClient.post(
        tokenEndpoint,
        headers: {
          'Content-Type': 'application/json',
          'apikey': supabaseAnonKey,
        },
        body: jsonEncode({
          'email': email.trim(),
          'password': password,
        }),
      ).timeout(const Duration(seconds: 12));

      if (response.statusCode != 200) {
        final Map<String, dynamic> errorBody = jsonDecode(response.body) as Map<String, dynamic>;
        final errorDescription = errorBody['error_description'] as String? ??
            errorBody['msg'] as String? ??
            'Invalid credentials or unauthorized login.';
        throw AuthException(errorDescription, statusCode: response.statusCode);
      }

      final Map<String, dynamic> data = jsonDecode(response.body) as Map<String, dynamic>;
      final accessToken = data['access_token'] as String;
      final refreshToken = data['refresh_token'] as String?;
      final expiresIn = data['expires_in'] as int? ?? 3600;
      final user = data['user'] as Map<String, dynamic>;
      final userId = user['id'] as String;

      // Extract role strictly from app_metadata (never trust editable user_metadata)
      final appMetadata = user['app_metadata'] as Map<String, dynamic>? ?? {};
      final roleString = appMetadata['role'] as String? ?? 'citizen';
      final role = UserRole.fromString(roleString);

      final userMetadata = user['user_metadata'] as Map<String, dynamic>? ?? {};
      final displayName = userMetadata['full_name'] as String? ??
          userMetadata['name'] as String? ??
          email.split('@').first;

      _currentSession = UserSession(
        userId: userId,
        name: displayName,
        email: email,
        role: role,
        authType: AuthType.authenticated,
        token: accessToken,
        refreshToken: refreshToken,
        expiresAt: DateTime.now().add(Duration(seconds: expiresIn)),
      );

      notifyListeners();
      return _currentSession!;
    } catch (e) {
      if (e is AuthException) rethrow;
      throw AuthException('Network error connecting to authentication service: $e');
    }
  }

  /// Central handler for 401 Unauthorized responses or preflight token expiry.
  /// Invalidates the active session, clears in-memory credentials, and notifies listeners.
  /// If redirect is true and WidgetsBinding is active, triggers a safe navigation back to the welcome route.
  void handleUnauthorized({bool redirect = true}) {
    final hadSession = _currentSession != null;
    _currentSession = null;
    if (hadSession) {
      notifyListeners();
    }
    if (redirect) {
      try {
        AppRoutes.navigatorKey.currentState?.pushNamedAndRemoveUntil(
          AppRoutes.welcome,
          (route) => false,
        );
      } catch (_) {
        // Safe no-op when executing in unit test environments without an active Navigator
      }
    }
  }

  /// Terminates the active session and clears tokens.
  void logout() {
    _currentSession = null;
    notifyListeners();
  }

  /// Verifies if the currently logged-in user possesses the required role.
  bool checkAccess(UserRole requiredRole) {
    if (_currentSession == null) return false;
    return _currentSession!.canAccess(requiredRole);
  }
}
