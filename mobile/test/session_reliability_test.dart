import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:drainx_mobile/core/auth/auth_service.dart';
import 'package:drainx_mobile/core/network/api_client.dart';
import 'package:drainx_mobile/models/user_session.dart';

/// Helper to craft a valid structural JWT with standard 3-part base64url encoding.
String craftTestJwt({required Map<String, dynamic> payload}) {
  final header = {'alg': 'HS256', 'typ': 'JWT'};
  final h64 = base64Url.encode(utf8.encode(jsonEncode(header))).replaceAll('=', '');
  final p64 = base64Url.encode(utf8.encode(jsonEncode(payload))).replaceAll('=', '');
  return '$h64.$p64.mock_test_signature';
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late AuthService authService;

  setUp(() {
    authService = AuthService();
    authService.logout();
  });

  tearDown(() {
    authService.logout();
  });

  group('P1.3.4 Mobile JWT Expiry & Session Reliability', () {
    test('1. expired JWT is rejected before network request is dispatched', () async {
      // Craft a JWT that expired 5 minutes ago
      final pastExp = (DateTime.now().millisecondsSinceEpoch ~/ 1000) - 300;
      final expiredToken = craftTestJwt(payload: {
        'sub': 'worker-user-01',
        'exp': pastExp,
        'app_metadata': {'role': 'worker', 'team': 'Team Alpha'},
      });

      final expiredSession = UserSession(
        userId: 'worker-user-01',
        name: 'Field Worker Expired',
        role: UserRole.fieldWorker,
        authType: AuthType.authenticated,
        token: expiredToken,
      );

      authService.setSessionForTesting(expiredSession);
      expect(expiredSession.isTokenExpired, isTrue);
      expect(authService.isLoggedIn, isTrue);

      int networkCalls = 0;
      final mockClient = MockClient((request) async {
        networkCalls++;
        return http.Response(jsonEncode([]), 200);
      });

      final apiClient = ApiClient(httpClient: mockClient, authService: authService);

      await expectLater(
        apiClient.getIncidents(),
        throwsA(predicate((e) =>
            e is ApiException &&
            e.statusCode == 401 &&
            e.message.contains('expired'))),
      );

      // Verify zero network requests were made over the wire
      expect(networkCalls, 0);

      // Verify session was centrally invalidated and credentials cleared
      expect(authService.isLoggedIn, isFalse);
      expect(authService.currentSession, isNull);
      expect(authService.currentToken, isNull);
    });

    test('2. HTTP 401 centrally invalidates authenticated session and clears credentials', () async {
      // Craft an unexpired token (valid for another 1 hour)
      final futureExp = (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 3600;
      final validToken = craftTestJwt(payload: {
        'sub': 'muni-officer-01',
        'exp': futureExp,
        'app_metadata': {'role': 'municipality'},
      });

      final activeSession = UserSession(
        userId: 'muni-officer-01',
        name: 'Officer Rao',
        role: UserRole.municipality,
        authType: AuthType.authenticated,
        token: validToken,
      );

      authService.setSessionForTesting(activeSession);
      expect(activeSession.isTokenExpired, isFalse);
      expect(authService.isLoggedIn, isTrue);

      // Mock backend returning 401 Unauthorized (e.g. token revoked or session terminated on server)
      final mockClient = MockClient((request) async {
        return http.Response(jsonEncode({'detail': 'Token signature revoked or session terminated'}), 401);
      });

      final apiClient = ApiClient(httpClient: mockClient, authService: authService);

      await expectLater(
        apiClient.getIncidents(),
        throwsA(predicate((e) => e is ApiException && e.statusCode == 401)),
      );

      // Verify central invalidation
      expect(authService.isLoggedIn, isFalse);
      expect(authService.currentSession, isNull);
      expect(authService.currentToken, isNull);
    });

    test('3. HTTP 403 preserves session and does NOT automatically log out valid user', () async {
      final futureExp = (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 3600;
      final validToken = craftTestJwt(payload: {
        'sub': 'worker-beta-01',
        'exp': futureExp,
        'app_metadata': {'role': 'worker', 'team': 'Team Beta'},
      });

      final workerSession = UserSession(
        userId: 'worker-beta-01',
        name: 'Worker Beta',
        role: UserRole.fieldWorker,
        authType: AuthType.authenticated,
        token: validToken,
        assignedTeam: 'Team Beta',
      );

      authService.setSessionForTesting(workerSession);
      expect(authService.isLoggedIn, isTrue);

      // Mock backend returning 403 Forbidden (e.g. worker updating incident assigned to Team Alpha)
      final mockClient = MockClient((request) async {
        return http.Response(
          jsonEncode({'detail': 'Field workers may only update incidents assigned to their crew.'}),
          403,
        );
      });

      final apiClient = ApiClient(httpClient: mockClient, authService: authService);

      await expectLater(
        apiClient.updateIncident('INC-DEMO-01', status: 'INVESTIGATING'),
        throwsA(predicate((e) =>
            e is ApiException &&
            e.statusCode == 403 &&
            e.message.contains('Permission denied'))),
      );

      // Crucial: 403 must preserve the valid user session!
      expect(authService.isLoggedIn, isTrue);
      expect(authService.currentSession, isNotNull);
      expect(authService.currentRole, UserRole.fieldWorker);
      expect(authService.currentToken, validToken);
    });

    test('4. demo session strictly sends no bearer token across all endpoints', () async {
      String? capturedAuthHeader;

      final mockClient = MockClient((request) async {
        capturedAuthHeader = request.headers['Authorization'];
        if (request.method == 'GET') {
          return http.Response(jsonEncode([]), 200);
        } else if (request.method == 'POST') {
          return http.Response(
            jsonEncode({
              'id': 'INC-NEW-01',
              'category': 'WATERLOGGING',
              'description': 'Demo report',
              'latitude': 15.5,
              'longitude': 73.8,
              'severity': 'MEDIUM',
              'status': 'REPORTED',
              'source': 'CITIZEN',
              'reporter_name': 'Demo User',
              'created_at': DateTime.now().toIso8601String(),
              'updated_at': DateTime.now().toIso8601String(),
            }),
            201,
          );
        }
        return http.Response('OK', 200);
      });

      // Login as demo citizen
      authService.loginDemo(role: UserRole.citizen, displayName: 'Demo Maria');
      expect(authService.isDemo, isTrue);
      expect(authService.currentToken, isNull);

      final apiClient = ApiClient(httpClient: mockClient, authService: authService);

      // Call GET /incidents
      await apiClient.getIncidents();
      expect(capturedAuthHeader, isNull);

      // Call POST /incidents
      await apiClient.createIncident(
        category: 'WATERLOGGING',
        description: 'Flooding near market',
        latitude: 15.49,
        longitude: 73.82,
        severity: 'MEDIUM',
      );
      expect(capturedAuthHeader, isNull);
    });

    test('5. logout completely clears in-memory session, tokens, and role state', () {
      final token = craftTestJwt(payload: {
        'sub': 'admin-01',
        'exp': (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 3600,
        'app_metadata': {'role': 'municipality'},
      });

      authService.setSessionForTesting(UserSession(
        userId: 'admin-01',
        name: 'Supervisor',
        role: UserRole.municipality,
        authType: AuthType.authenticated,
        token: token,
      ));

      expect(authService.isLoggedIn, isTrue);
      expect(authService.currentToken, isNotNull);
      expect(authService.currentRole, UserRole.municipality);

      // Execute logout
      authService.logout();

      expect(authService.isLoggedIn, isFalse);
      expect(authService.currentSession, isNull);
      expect(authService.currentToken, isNull);
      expect(authService.currentRole, isNull);
      expect(authService.isDemo, isTrue);
    });

    test('6. valid authenticated request continues working and attaches Bearer header', () async {
      final futureExp = (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 1800;
      final validToken = craftTestJwt(payload: {
        'sub': 'worker-valid-01',
        'exp': futureExp,
        'app_metadata': {'role': 'worker', 'team': 'Team Alpha'},
      });

      authService.setSessionForTesting(UserSession(
        userId: 'worker-valid-01',
        name: 'Worker Valid',
        role: UserRole.fieldWorker,
        authType: AuthType.authenticated,
        token: validToken,
      ));

      String? sentAuthHeader;
      final mockClient = MockClient((request) async {
        sentAuthHeader = request.headers['Authorization'];
        return http.Response(
          jsonEncode([
            {
              'id': 'INC-DEMO-01',
              'category': 'DRAIN_BLOCKAGE',
              'description': 'Culvert blocked',
              'latitude': 15.49,
              'longitude': 73.82,
              'severity': 'HIGH',
              'status': 'INVESTIGATING',
              'source': 'DEMO',
              'created_at': DateTime.now().toIso8601String(),
              'updated_at': DateTime.now().toIso8601String(),
            }
          ]),
          200,
        );
      });

      final apiClient = ApiClient(httpClient: mockClient, authService: authService);
      final incidents = await apiClient.getIncidents();

      expect(incidents.length, 1);
      expect(incidents.first.id, 'INC-DEMO-01');
      expect(sentAuthHeader, 'Bearer $validToken');
      expect(authService.isLoggedIn, isTrue);
    });

    test('7. invalid or unknown role strings default strictly to citizen least-privilege', () {
      expect(UserRole.fromString(null), UserRole.citizen);
      expect(UserRole.fromString(''), UserRole.citizen);
      expect(UserRole.fromString('unknown_role'), UserRole.citizen);
      expect(UserRole.fromString('superadmin'), UserRole.citizen);
      expect(UserRole.fromString('root'), UserRole.citizen);
      expect(UserRole.fromString('hacker'), UserRole.citizen);

      // Verify access boundary on session constructed with unknown role string
      final fallbackSession = UserSession(
        userId: 'guest-01',
        name: 'Guest User',
        role: UserRole.fromString('untrusted_role_claim'),
      );

      expect(fallbackSession.role, UserRole.citizen);
      expect(fallbackSession.canAccess(UserRole.citizen), isTrue);
      expect(fallbackSession.canAccess(UserRole.municipality), isFalse);
      expect(fallbackSession.canAccess(UserRole.fieldWorker), isFalse);
    });
  });
}
