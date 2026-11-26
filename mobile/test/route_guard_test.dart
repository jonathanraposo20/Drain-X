import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:drainx_mobile/app/routes.dart';
import 'package:drainx_mobile/core/auth/auth_service.dart';
import 'package:drainx_mobile/core/network/api_client.dart';
import 'package:drainx_mobile/features/auth/unauthorized_screen.dart';
import 'package:drainx_mobile/features/auth/worker_login_screen.dart';
import 'package:drainx_mobile/features/worker/worker_dashboard_screen.dart';
import 'package:drainx_mobile/models/user_session.dart';

void main() {
  setUp(() {
    AuthService().logout();
  });

  tearDown(() {
    AuthService().logout();
  });

  group('Route Guards & Role Protection', () {
    testWidgets('renders UnauthorizedScreen when unauthenticated user accesses guarded route', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AppRoutes.guarded(
            requiredRole: UserRole.fieldWorker,
            builder: (session) => const Text('Guarded Worker Content'),
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.byType(UnauthorizedScreen), findsOneWidget);
      expect(find.text('Role-Based Authorization Required'), findsOneWidget);
      expect(find.text('Guarded Worker Content'), findsNothing);
    });

    testWidgets('renders UnauthorizedScreen when citizen attempts accessing worker route', (tester) async {
      AuthService().loginDemo(role: UserRole.citizen, displayName: 'Maria Fernandes');

      await tester.pumpWidget(
        MaterialApp(
          home: AppRoutes.guarded(
            requiredRole: UserRole.fieldWorker,
            builder: (session) => const Text('Guarded Worker Content'),
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.byType(UnauthorizedScreen), findsOneWidget);
      expect(find.text('Citizen'), findsOneWidget); // Current role
      expect(find.text('Field Worker'), findsOneWidget); // Required role
      expect(find.text('Guarded Worker Content'), findsNothing);
    });

    testWidgets('renders target screen when authorized worker accesses worker route', (tester) async {
      AuthService().loginDemo(
        role: UserRole.fieldWorker,
        displayName: 'R. Shirodkar',
        assignedTeam: 'Team Alpha — St. Inez Drainage Crew',
      );

      await tester.pumpWidget(
        MaterialApp(
          home: AppRoutes.guarded(
            requiredRole: UserRole.fieldWorker,
            builder: (session) => Text('Welcome Worker ${session.name}'),
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('Welcome Worker R. Shirodkar'), findsOneWidget);
      expect(find.byType(UnauthorizedScreen), findsNothing);
    });
  });

  group('Worker Persona & Navigation', () {
    testWidgets('renders WorkerLoginScreen identities and proceeds to dashboard', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: WorkerLoginScreen(),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('Field Worker Demo Login'), findsOneWidget);
      expect(find.text('R. Shirodkar (Crew Lead)'), findsOneWidget);
      expect(find.textContaining('Team Alpha — St. Inez Drainage Crew'), findsOneWidget);

      // Ensure visible in SingleChildScrollView and tap Enter Worker Console
      await tester.ensureVisible(find.text('ENTER WORKER CONSOLE'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('ENTER WORKER CONSOLE'));
      await tester.pumpAndSettle();

      // Verified session is logged in as fieldWorker
      expect(AuthService().isLoggedIn, isTrue);
      expect(AuthService().currentRole, UserRole.fieldWorker);
      expect(find.byType(WorkerDashboardScreen), findsOneWidget);
    });
  });

  group('ApiClient Authenticated Header Injection', () {
    test('injects Authorization: Bearer token when session has token', () async {
      String? capturedAuthHeader;

      final mockClient = MockClient((request) async {
        capturedAuthHeader = request.headers['Authorization'];
        return http.Response(jsonEncode([]), 200);
      });

      // Test 1: In demo mode without token, no Bearer header is sent
      final auth = AuthService();
      auth.loginDemo(role: UserRole.municipality, displayName: 'Test Officer');
      final unauthedClient = ApiClient(httpClient: mockClient, authService: auth);

      await unauthedClient.getIncidents();
      expect(capturedAuthHeader, isNull);

      // Test 2: When authenticated with token, Bearer header is automatically injected
      auth.setSessionForTesting(UserSession(
        userId: 'usr-1',
        name: 'Officer Rao',
        email: 'rao@drainx.gov',
        role: UserRole.municipality,
        authType: AuthType.authenticated,
        token: 'secret-bearer-token-abc',
        expiresAt: DateTime.now().add(const Duration(hours: 1)),
      ));

      final authedClient = ApiClient(httpClient: mockClient, authService: auth);
      await authedClient.getIncidents();

      expect(capturedAuthHeader, 'Bearer secret-bearer-token-abc');
    });
  });
}
