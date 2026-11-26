import 'package:flutter_test/flutter_test.dart';
import 'package:drainx_mobile/app/app.dart';
import 'package:drainx_mobile/features/auth/supabase_login_screen.dart';
import 'package:drainx_mobile/core/auth/auth_service.dart';
import 'package:drainx_mobile/features/citizen/citizen_dashboard_screen.dart';
import 'package:drainx_mobile/models/user_session.dart';

void main() {
  testWidgets('welcome screen opens the real Supabase account sign-in form', (
    tester,
  ) async {
    await tester.pumpWidget(const DrainXMobileApp());
    await tester.pumpAndSettle();

    final signInButton = find.text('Sign in with DRAIN-X account');
    await tester.ensureVisible(signInButton);
    await tester.tap(signInButton);
    await tester.pumpAndSettle();

    expect(find.byType(SupabaseLoginScreen), findsOneWidget);
    expect(find.text('Email address'), findsOneWidget);
    expect(find.text('Password'), findsOneWidget);
    expect(find.text('Sign in'), findsOneWidget);
  });

  testWidgets('restored authenticated session resumes its role dashboard after reload', (
    tester,
  ) async {
    AuthService().setSupabaseClientForTesting(null);
    AuthService().setSessionForTesting(
      UserSession(
        userId: 'restored-citizen',
        name: 'Restored Citizen',
        role: UserRole.citizen,
        authType: AuthType.authenticated,
        token: 'restored-access-token',
        expiresAt: DateTime.now().add(const Duration(hours: 1)),
      ),
    );
    addTearDown(() => AuthService().logout());

    await tester.pumpWidget(const DrainXMobileApp());
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 500));
    await tester.pump();

    expect(find.byType(CitizenDashboardScreen), findsOneWidget);
  });
}
