import 'package:flutter/material.dart';
import '../core/theme/app_theme.dart';
import '../features/auth/welcome_screen.dart';
import '../features/auth/citizen_login_screen.dart';
import '../features/auth/municipal_login_screen.dart';
import '../features/auth/worker_login_screen.dart';
import '../features/auth/unauthorized_screen.dart';
import '../features/citizen/citizen_dashboard_screen.dart';
import '../features/municipal/municipal_dashboard_screen.dart';
import '../features/worker/worker_dashboard_screen.dart';
import '../models/user_session.dart';
import 'routes.dart';

class DrainXMobileApp extends StatelessWidget {
  const DrainXMobileApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      navigatorKey: AppRoutes.navigatorKey,
      title: 'DRAIN-X Mobile',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.lightTheme,
      initialRoute: AppRoutes.welcome,
      routes: {
        AppRoutes.welcome: (_) => const WelcomeScreen(),
        AppRoutes.citizenLogin: (_) => const CitizenLoginScreen(),
        AppRoutes.municipalLogin: (_) => const MunicipalLoginScreen(),
        AppRoutes.workerLogin: (_) => const WorkerLoginScreen(),
        AppRoutes.unauthorized: (_) => const UnauthorizedScreen(),
        AppRoutes.citizenDashboard: (_) => AppRoutes.guarded(
              requiredRole: UserRole.citizen,
              builder: (session) => CitizenDashboardScreen(reporterName: session.name),
            ),
        AppRoutes.municipalDashboard: (_) => AppRoutes.guarded(
              requiredRole: UserRole.municipality,
              builder: (session) => MunicipalDashboardScreen(officerName: session.name),
            ),
        AppRoutes.workerDashboard: (_) => AppRoutes.guarded(
              requiredRole: UserRole.fieldWorker,
              builder: (session) => WorkerDashboardScreen(
                workerName: session.name,
                assignedTeam: session.assignedTeam ?? 'Team Alpha — St. Inez Drainage Crew',
              ),
            ),
      },
    );
  }
}
