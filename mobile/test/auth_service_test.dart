import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:drainx_mobile/core/auth/auth_service.dart';
import 'package:drainx_mobile/core/config/api_config.dart';
import 'package:drainx_mobile/models/user_session.dart';

void main() {
  late AuthService authService;

  setUp(() {
    authService = AuthService();
    authService.logout(); // Reset session before each test
  });

  tearDown(() {
    authService.logout();
    ApiConfig.supabaseUrl = null;
    ApiConfig.supabaseAnonKey = null;
  });

  group('UserSession Model & Anti-Privilege Escalation', () {
    test('creates UserSession with demo defaults', () {
      final session = UserSession(
        userId: 'DEMO-CITIZEN-101',
        name: 'Maria Fernandes',
        role: UserRole.citizen,
      );

      expect(session.userId, 'DEMO-CITIZEN-101');
      expect(session.name, 'Maria Fernandes');
      expect(session.role, UserRole.citizen);
      expect(session.isDemo, isTrue);
      expect(session.isAuthenticated, isFalse);
    });

    test('enforces strict role-based access checks (canAccess)', () {
      final citizenSession = UserSession(
        userId: 'C1',
        name: 'Citizen Jane',
        role: UserRole.citizen,
      );

      final workerSession = UserSession(
        userId: 'W1',
        name: 'Worker Bob',
        role: UserRole.fieldWorker,
        assignedTeam: 'Team Alpha',
      );

      final municipalSession = UserSession(
        userId: 'M1',
        name: 'Officer Coutinho',
        role: UserRole.municipality,
      );

      // Citizen can only access citizen routes
      expect(citizenSession.canAccess(UserRole.citizen), isTrue);
      expect(citizenSession.canAccess(UserRole.municipality), isFalse);
      expect(citizenSession.canAccess(UserRole.fieldWorker), isFalse);

      // Field Worker can only access worker routes
      expect(workerSession.canAccess(UserRole.fieldWorker), isTrue);
      expect(workerSession.canAccess(UserRole.citizen), isFalse);
      expect(workerSession.canAccess(UserRole.municipality), isFalse);

      // Municipality supervisor can access municipal and worker triage routes
      expect(municipalSession.canAccess(UserRole.municipality), isTrue);
      expect(municipalSession.canAccess(UserRole.fieldWorker), isTrue);
      expect(municipalSession.canAccess(UserRole.citizen), isFalse);
    });

    test('serializes and deserializes UserSession correctly', () {
      final session = UserSession(
        userId: 'U-99',
        name: 'S. Naik',
        email: 's.naik@example.com',
        role: UserRole.fieldWorker,
        authType: AuthType.authenticated,
        token: 'eyJhbGciOi...',
        assignedTeam: 'Team Gamma — Fontainhas Heritage Maintenance',
      );

      final json = session.toJson();
      final revived = UserSession.fromJson(json);

      expect(revived.userId, 'U-99');
      expect(revived.name, 'S. Naik');
      expect(revived.role, UserRole.fieldWorker);
      expect(revived.authType, AuthType.authenticated);
      expect(revived.token, 'eyJhbGciOi...');
      expect(revived.assignedTeam, 'Team Gamma — Fontainhas Heritage Maintenance');
    });
  });

  group('AuthService Lifecycle & Demo Mode', () {
    test('logs in demo citizen and updates active session state', () {
      expect(authService.isLoggedIn, isFalse);

      final session = authService.loginDemo(
        role: UserRole.citizen,
        displayName: 'P. Fernandes',
      );

      expect(authService.isLoggedIn, isTrue);
      expect(authService.currentSession?.name, 'P. Fernandes');
      expect(authService.currentRole, UserRole.citizen);
      expect(authService.isDemo, isTrue);
      expect(session.userId, startsWith('DEMO-CITIZEN-'));
    });

    test('logs in demo worker with assigned team', () {
      final session = authService.loginDemo(
        role: UserRole.fieldWorker,
        displayName: 'R. Shirodkar',
        assignedTeam: 'Team Alpha — St. Inez Drainage Crew',
      );

      expect(authService.isLoggedIn, isTrue);
      expect(authService.currentRole, UserRole.fieldWorker);
      expect(session.assignedTeam, 'Team Alpha — St. Inez Drainage Crew');
      expect(session.userId, startsWith('DEMO-WORKER-'));
    });

    test('logout clears session completely', () {
      authService.loginDemo(role: UserRole.municipality, displayName: 'Eng. Coutinho');
      expect(authService.isLoggedIn, isTrue);

      authService.logout();

      expect(authService.isLoggedIn, isFalse);
      expect(authService.currentSession, isNull);
      expect(authService.currentRole, isNull);
    });

    test('authenticates via mock Supabase endpoint extracting app_metadata.role', () async {
      ApiConfig.supabaseUrl = 'https://mock.supabase.co';
      ApiConfig.supabaseAnonKey = 'mock-anon-key-12345';

      final mockClient = MockClient((request) async {
        if (request.url.path.contains('/auth/v1/token')) {
          final body = jsonDecode(request.body) as Map<String, dynamic>;
          if (body['email'] == 'officer@drainx.gov' && body['password'] == 'Secret123!') {
            return http.Response(
              jsonEncode({
                'access_token': 'jwt-mock-access-token-xyz',
                'refresh_token': 'jwt-mock-refresh-token',
                'expires_in': 3600,
                'user': {
                  'id': 'usr-supabase-uuid-1',
                  'email': 'officer@drainx.gov',
                  // Anti-Privilege Escalation: Role must come from app_metadata
                  'app_metadata': {
                    'role': 'municipality',
                  },
                  // Editable user_metadata attempts to claim admin (must be ignored)
                  'user_metadata': {
                    'role': 'admin_root',
                    'full_name': 'Municipal Supervisor Rao',
                  },
                },
              }),
              200,
              headers: {'Content-Type': 'application/json'},
            );
          }
          return http.Response(jsonEncode({'error_description': 'Invalid credentials'}), 400);
        }
        return http.Response('Not Found', 404);
      });

      authService.httpClient = mockClient;

      final session = await authService.loginWithCredentials(
        email: 'officer@drainx.gov',
        password: 'Secret123!',
      );

      expect(session.userId, 'usr-supabase-uuid-1');
      expect(session.name, 'Municipal Supervisor Rao');
      // Verify app_metadata was used, NOT user_metadata
      expect(session.role, UserRole.municipality);
      expect(session.token, 'jwt-mock-access-token-xyz');
      expect(session.isAuthenticated, isTrue);
      expect(session.isDemo, isFalse);
    });
  });
}
