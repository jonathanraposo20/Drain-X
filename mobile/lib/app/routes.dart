import 'package:flutter/material.dart';
import '../core/auth/auth_service.dart';
import '../models/user_session.dart';
import '../features/auth/unauthorized_screen.dart';

class AppRoutes {
  static final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

  static const String welcome = '/';
  static const String citizenLogin = '/citizen/login';
  static const String municipalLogin = '/municipal/login';
  static const String workerLogin = '/worker/login';
  static const String citizenDashboard = '/citizen/dashboard';
  static const String citizenReport = '/citizen/report';
  static const String municipalDashboard = '/municipal/dashboard';
  static const String workerDashboard = '/worker/dashboard';
  static const String unauthorized = '/unauthorized';

  /// Wraps a destination widget in a role guard.
  /// Checks the restored local auth state and role. The Supabase SDK refreshes
  /// expired tokens before API calls, so startup must not reject a restorable session.
  static Widget guarded({
    required UserRole requiredRole,
    required Widget Function(UserSession session) builder,
  }) {
    final authService = AuthService();
    final session = authService.currentSession;
    if (session == null || !session.canAccess(requiredRole)) {
      return UnauthorizedScreen(
        requiredRole: requiredRole,
        userRole: session?.role,
      );
    }
    return builder(session);
  }
}
