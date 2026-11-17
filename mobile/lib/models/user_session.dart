import 'dart:convert';

enum UserRole {
  citizen,
  municipality,
  fieldWorker;

  String get displayName {
    switch (this) {
      case UserRole.citizen:
        return 'Citizen';
      case UserRole.municipality:
        return 'Municipality';
      case UserRole.fieldWorker:
        return 'Field Worker';
    }
  }

  String get technicalRole {
    switch (this) {
      case UserRole.citizen:
        return 'citizen';
      case UserRole.municipality:
        return 'municipality';
      case UserRole.fieldWorker:
        return 'worker';
    }
  }

  static UserRole fromString(String? role) {
    switch (role?.toLowerCase()) {
      case 'municipality':
      case 'municipal':
      case 'admin':
        return UserRole.municipality;
      case 'worker':
      case 'field_worker':
      case 'fieldworker':
        return UserRole.fieldWorker;
      case 'citizen':
      default:
        // Unknown, null, or malformed roles default safely to citizen (least-privilege)
        return UserRole.citizen;
    }
  }
}

enum AuthType {
  demo,
  authenticated;

  bool get isDemo => this == AuthType.demo;
}

class UserSession {
  final String userId;
  final String name;
  final String? email;
  final UserRole role;
  final AuthType authType;
  final String? token;
  final String? refreshToken;
  final DateTime? expiresAt;
  final DateTime loggedInAt;
  final String? assignedTeam;

  UserSession({
    required this.userId,
    required this.name,
    this.email,
    required this.role,
    this.authType = AuthType.demo,
    this.token,
    this.refreshToken,
    DateTime? expiresAt,
    DateTime? loggedInAt,
    this.assignedTeam,
  })  : loggedInAt = loggedInAt ?? DateTime.now(),
        expiresAt = expiresAt ?? (token != null ? extractExpFromJwt(token) : null);

  bool get isDemo => authType.isDemo;

  bool get isAuthenticated => authType == AuthType.authenticated && token != null;

  /// Detects whether the current session token has expired.
  /// Demo sessions are synthetic and never expire via JWT claims.
  bool get isTokenExpired {
    if (!isAuthenticated) return false;
    final exp = expiresAt ?? (token != null ? extractExpFromJwt(token!) : null);
    if (exp == null) return false;
    return DateTime.now().isAfter(exp);
  }

  /// Extracts the exp timestamp from a standard 3-part base64url JWT without third-party dependencies.
  static DateTime? extractExpFromJwt(String jwtToken) {
    try {
      final parts = jwtToken.split('.');
      if (parts.length != 3) return null;
      final normalized = base64Url.normalize(parts[1]);
      final payloadString = utf8.decode(base64Url.decode(normalized));
      final Map<String, dynamic> payload = jsonDecode(payloadString) as Map<String, dynamic>;
      final exp = payload['exp'];
      if (exp is int) {
        return DateTime.fromMillisecondsSinceEpoch(exp * 1000);
      } else if (exp is num) {
        return DateTime.fromMillisecondsSinceEpoch((exp * 1000).toInt());
      }
    } catch (_) {
      return null;
    }
    return null;
  }

  bool canAccess(UserRole requiredRole) {
    // Exact role match is always allowed
    if (role == requiredRole) return true;
    // Municipality administrators have supervisory oversight
    if (role == UserRole.municipality && requiredRole == UserRole.fieldWorker) {
      return true;
    }
    return false;
  }

  Map<String, dynamic> toJson() {
    return {
      'user_id': userId,
      'name': name,
      'email': email,
      'role': role.technicalRole,
      'auth_type': authType.name,
      'token': token,
      'refresh_token': refreshToken,
      'expires_at': expiresAt?.toIso8601String(),
      'logged_in_at': loggedInAt.toIso8601String(),
      'assigned_team': assignedTeam,
    };
  }

  factory UserSession.fromJson(Map<String, dynamic> json) {
    final token = json['token'] as String?;
    DateTime? exp;
    if (json['expires_at'] != null) {
      exp = DateTime.tryParse(json['expires_at'] as String);
    }
    if (exp == null && token != null) {
      exp = extractExpFromJwt(token);
    }

    return UserSession(
      userId: json['user_id'] as String,
      name: json['name'] as String,
      email: json['email'] as String?,
      role: UserRole.fromString(json['role'] as String?),
      authType: json['auth_type'] == 'authenticated' ? AuthType.authenticated : AuthType.demo,
      token: token,
      refreshToken: json['refresh_token'] as String?,
      expiresAt: exp,
      loggedInAt: json['logged_in_at'] != null ? DateTime.tryParse(json['logged_in_at'] as String) : null,
      assignedTeam: json['assigned_team'] as String?,
    );
  }
}
