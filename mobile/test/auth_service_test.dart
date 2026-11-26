import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:supabase_flutter/supabase_flutter.dart' as supabase;
import 'package:drainx_mobile/core/auth/auth_service.dart';
import 'package:drainx_mobile/core/config/api_config.dart';
import 'package:drainx_mobile/models/user_session.dart';

void main() {
  late AuthService authService;

  setUp(() {
    authService = AuthService();
    authService.setSupabaseClientForTesting(null);
    authService.logout(); // Reset session before each test
  });

  tearDown(() {
    authService.setSupabaseClientForTesting(null);
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

    test('authenticates through Supabase SDK and trusts app_metadata.role', () async {
      ApiConfig.supabaseUrl = 'https://mock.supabase.co';
      ApiConfig.supabaseAnonKey = 'mock-publishable-key';

      final now = DateTime.now().toUtc();
      final exp = now.millisecondsSinceEpoch ~/ 1000 + 3600;
      final payload = base64Url.encode(utf8.encode(jsonEncode({'exp': exp}))).replaceAll('=', '');
      final accessToken = 'eyJhbGciOiJub25lIn0.$payload.signature';
      final mockClient = MockClient((request) async {
        if (request.url.path.endsWith('/token') &&
            request.url.queryParameters['grant_type'] == 'password') {
          return http.Response(
            jsonEncode({
              'access_token': accessToken,
              'refresh_token': 'jwt-mock-refresh-token',
              'token_type': 'bearer',
              'expires_in': 3600,
              'expires_at': exp,
              'user': {
                'id': 'usr-supabase-uuid-1',
                'aud': 'authenticated',
                'created_at': now.toIso8601String(),
                'email': 'officer@drainx.gov',
                'app_metadata': {'role': 'municipality'},
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
        if (request.url.path.endsWith('/logout')) {
          return http.Response('', 204);
        }
        return http.Response('Not Found', 404);
      });

      final client = supabase.SupabaseClient(
        'https://mock.supabase.co',
        'mock-publishable-key',
        authOptions: const supabase.AuthClientOptions(autoRefreshToken: false),
        httpClient: mockClient,
      );
      authService.setSupabaseClientForTesting(client);

      final session = await authService.loginWithCredentials(
        email: 'officer@drainx.gov',
        password: 'Secret123!',
      );

      expect(session.userId, 'usr-supabase-uuid-1');
      expect(session.name, 'Municipal Supervisor Rao');
      expect(session.role, UserRole.municipality);
      expect(session.token, accessToken);
      expect(session.refreshToken, 'jwt-mock-refresh-token');
      expect(session.isAuthenticated, isTrue);
      expect(session.isDemo, isFalse);

      authService.setSupabaseClientForTesting(null);
      await client.dispose();
    });

    test('refreshes an expired Supabase session before protected API use', () async {
      ApiConfig.supabaseUrl = 'https://mock.supabase.co';
      ApiConfig.supabaseAnonKey = 'mock-publishable-key';
      final nowSeconds = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      String tokenWithExp(int exp) {
        final payload = base64Url.encode(
          utf8.encode(jsonEncode({'exp': exp})),
        ).replaceAll('=', '');
        return 'eyJhbGciOiJub25lIn0.$payload.signature';
      }

      final expiredToken = tokenWithExp(nowSeconds - 60);
      final freshToken = tokenWithExp(nowSeconds + 3600);
      var refreshRequested = false;
      final now = DateTime.now().toUtc();
      final mockClient = MockClient((request) async {
        final grantType = request.url.queryParameters['grant_type'];
        if (request.url.path.endsWith('/token') &&
            (grantType == 'password' || grantType == 'refresh_token')) {
          final expired = grantType == 'password';
          if (!expired) refreshRequested = true;
          final exp = expired ? nowSeconds - 60 : nowSeconds + 3600;
          return http.Response(
            jsonEncode({
              'access_token': expired ? expiredToken : freshToken,
              'refresh_token': expired ? 'old-refresh-token' : 'rotated-refresh-token',
              'token_type': 'bearer',
              'expires_in': expired ? 0 : 3600,
              'expires_at': exp,
              'user': {
                'id': 'usr-refresh-test',
                'aud': 'authenticated',
                'created_at': now.toIso8601String(),
                'email': 'worker@drainx.gov',
                'app_metadata': {'role': 'worker', 'team': 'Team Alpha'},
                'user_metadata': {'full_name': 'Field Worker'},
              },
            }),
            200,
            headers: {'Content-Type': 'application/json'},
          );
        }
        return http.Response('Not Found', 404);
      });

      final client = supabase.SupabaseClient(
        'https://mock.supabase.co',
        'mock-publishable-key',
        authOptions: const supabase.AuthClientOptions(autoRefreshToken: false),
        httpClient: mockClient,
      );
      authService.setSupabaseClientForTesting(client);
      final session = await authService.loginWithCredentials(
        email: 'worker@drainx.gov',
        password: 'Secret123!',
      );
      expect(session.isTokenExpired, isTrue);

      await authService.ensureValidSession();

      expect(refreshRequested, isTrue);
      expect(authService.currentToken, freshToken);
      expect(authService.currentSession?.refreshToken, 'rotated-refresh-token');
      expect(authService.currentSession?.isTokenExpired, isFalse);

      authService.setSupabaseClientForTesting(null);
      await client.dispose();
    });
  });
}
