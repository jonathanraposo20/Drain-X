import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'package:drainx_mobile/core/auth/auth_service.dart';
import 'package:drainx_mobile/core/auth/secure_session_store.dart';
import 'package:drainx_mobile/core/config/api_config.dart';
import 'package:drainx_mobile/core/network/api_client.dart';
import 'package:drainx_mobile/models/user_session.dart';

class MemorySessionStore implements SecureSessionStore {
  String? value;
  int writes = 0;
  int clears = 0;

  @override
  Future<String?> readSession() async => value;

  @override
  Future<void> writeSession(String value) async {
    this.value = value;
    writes++;
  }

  @override
  Future<void> clearSession() async {
    value = null;
    clears++;
  }
}

String testJwt({required int expiresAt}) {
  final header = base64Url.encode(utf8.encode(jsonEncode({'alg': 'none'}))).replaceAll('=', '');
  final payload = base64Url
      .encode(utf8.encode(jsonEncode({'exp': expiresAt})))
      .replaceAll('=', '');
  return '$header.$payload.signature';
}

Map<String, dynamic> authResponse({
  required String accessToken,
  required String refreshToken,
  String role = 'citizen',
  String userId = 'user-1',
}) {
  return {
    'access_token': accessToken,
    'refresh_token': refreshToken,
    'expires_in': 3600,
    'user': {
      'id': userId,
      'email': 'user@example.com',
      'app_metadata': {'role': role},
      'user_metadata': {'full_name': 'DRAIN-X User', 'role': 'admin'},
    },
  };
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late AuthService auth;
  late MemorySessionStore store;

  setUp(() {
    auth = AuthService();
    store = MemorySessionStore();
    auth.sessionStoreForTesting = store;
    auth.logout();
    ApiConfig.supabaseUrl = 'https://project.supabase.co';
    ApiConfig.supabaseAnonKey = 'test-publishable-key';
  });

  tearDown(() {
    auth.logout();
    ApiConfig.supabaseUrl = null;
    ApiConfig.supabaseAnonKey = null;
  });

  test('password login persists the Supabase session in secure store', () async {
    auth.httpClient = MockClient((request) async {
      expect(request.url.queryParameters['grant_type'], 'password');
      return http.Response(
        jsonEncode(authResponse(
          accessToken: 'access-1',
          refreshToken: 'refresh-1',
          role: 'municipality',
        )),
        200,
      );
    });

    final session = await auth.loginWithCredentials(
      email: 'user@example.com',
      password: 'secret',
    );

    expect(session.role, UserRole.municipality);
    expect(session.refreshToken, 'refresh-1');
    expect(store.writes, 1);
    expect(jsonDecode(store.value!)['refresh_token'], 'refresh-1');
    // Editable user_metadata.role must not elevate privileges.
    expect(session.role, UserRole.municipality);
  });

  test('refresh rotates tokens and persists the replacement refresh token', () async {
    final expiry = (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 60;
    auth.setSessionForTesting(UserSession(
      userId: 'user-1',
      name: 'DRAIN-X User',
      email: 'user@example.com',
      role: UserRole.citizen,
      authType: AuthType.authenticated,
      token: testJwt(expiresAt: expiry),
      refreshToken: 'refresh-old',
    ));

    auth.httpClient = MockClient((request) async {
      expect(request.url.queryParameters['grant_type'], 'refresh_token');
      expect(jsonDecode(request.body)['refresh_token'], 'refresh-old');
      return http.Response(
        jsonEncode(authResponse(
          accessToken: 'access-new',
          refreshToken: 'refresh-new',
        )),
        200,
      );
    });

    final refreshed = await auth.refreshSession();

    expect(refreshed.token, 'access-new');
    expect(refreshed.refreshToken, 'refresh-new');
    expect(auth.currentToken, 'access-new');
    expect(jsonDecode(store.value!)['refresh_token'], 'refresh-new');
  });

  test('concurrent refresh calls share one rotating refresh request', () async {
    final expiry = (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 60;
    auth.setSessionForTesting(UserSession(
      userId: 'user-1',
      name: 'DRAIN-X User',
      role: UserRole.citizen,
      authType: AuthType.authenticated,
      token: testJwt(expiresAt: expiry),
      refreshToken: 'refresh-once',
    ));

    final gate = Completer<http.Response>();
    var calls = 0;
    auth.httpClient = MockClient((request) async {
      calls++;
      return gate.future;
    });

    final first = auth.refreshSession();
    final second = auth.refreshSession();
    await Future<void>.delayed(Duration.zero);
    expect(calls, 1);

    gate.complete(http.Response(
      jsonEncode(authResponse(
        accessToken: 'access-shared',
        refreshToken: 'refresh-rotated',
      )),
      200,
    ));

    final results = await Future.wait([first, second]);
    expect(results[0].token, 'access-shared');
    expect(results[1].refreshToken, 'refresh-rotated');
    expect(calls, 1);
  });

  test('restoreSession reloads a valid persisted session', () async {
    final expires = (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 3600;
    store.value = jsonEncode(UserSession(
      userId: 'restored-user',
      name: 'Restored User',
      email: 'restored@example.com',
      role: UserRole.fieldWorker,
      authType: AuthType.authenticated,
      token: testJwt(expiresAt: expires),
      refreshToken: 'refresh-restored',
    ).toJson());

    final restored = await auth.restoreSession();

    expect(restored?.userId, 'restored-user');
    expect(auth.currentRole, UserRole.fieldWorker);
    expect(auth.currentSession?.refreshToken, 'refresh-restored');
  });

  test('invalid refresh token clears persisted and in-memory session', () async {
    final expiry = (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 60;
    auth.setSessionForTesting(UserSession(
      userId: 'user-1',
      name: 'DRAIN-X User',
      role: UserRole.citizen,
      authType: AuthType.authenticated,
      token: testJwt(expiresAt: expiry),
      refreshToken: 'revoked-refresh',
    ));
    store.value = 'persisted-session';

    auth.httpClient = MockClient((request) async =>
        http.Response(jsonEncode({'msg': 'Invalid Refresh Token'}), 400));

    await expectLater(
      auth.refreshSession(),
      throwsA(isA<AuthException>()),
    );

    await Future<void>.delayed(Duration.zero);
    expect(auth.currentSession, isNull);
    expect(store.value, isNull);
    expect(store.clears, greaterThan(0));
  });

  test('transient refresh failure preserves the refresh token for retry', () async {
    final expiry = (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 60;
    final session = UserSession(
      userId: 'user-1',
      name: 'DRAIN-X User',
      role: UserRole.citizen,
      authType: AuthType.authenticated,
      token: testJwt(expiresAt: expiry),
      refreshToken: 'refresh-retryable',
    );
    auth.setSessionForTesting(session);
    store.value = jsonEncode(session.toJson());

    auth.httpClient = MockClient((request) async =>
        http.Response('Service unavailable', 503));

    await expectLater(
      auth.refreshSession(),
      throwsA(isA<AuthException>()),
    );

    expect(auth.currentSession, isNotNull);
    expect(auth.currentSession?.refreshToken, 'refresh-retryable');
    expect(store.value, isNotNull);
  });
  test('API GET refreshes after a server 401 and retries once with the new token', () async {
    final expiry = (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 3600;
    auth.setSessionForTesting(UserSession(
      userId: 'user-1',
      name: 'DRAIN-X User',
      role: UserRole.citizen,
      authType: AuthType.authenticated,
      token: testJwt(expiresAt: expiry),
      refreshToken: 'refresh-before-401',
    ));

    var apiCalls = 0;
    final mockClient = MockClient((request) async {
      if (request.url.path == '/auth/v1/token') {
        return http.Response(
          jsonEncode(authResponse(
            accessToken: 'access-after-refresh',
            refreshToken: 'refresh-after-refresh',
          )),
          200,
        );
      }
      apiCalls++;
      if (apiCalls == 1) {
        return http.Response('expired access token', 401);
      }
      expect(request.headers['Authorization'], 'Bearer access-after-refresh');
      return http.Response('[]', 200);
    });

    auth.httpClient = mockClient;
    final api = ApiClient(httpClient: mockClient, authService: auth);
    final incidents = await api.getIncidents();

    expect(incidents, isEmpty);
    expect(apiCalls, 2);
    expect(auth.currentToken, 'access-after-refresh');
  });

  test('API mutation refreshes on 401 but is not replayed automatically', () async {
    final expiry = (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 3600;
    auth.setSessionForTesting(UserSession(
      userId: 'user-1',
      name: 'DRAIN-X User',
      role: UserRole.citizen,
      authType: AuthType.authenticated,
      token: testJwt(expiresAt: expiry),
      refreshToken: 'refresh-before-mutation',
    ));

    var mutationCalls = 0;
    final mutationClient = MockClient((request) async {
      if (request.url.path == '/auth/v1/token') {
        return http.Response(
          jsonEncode(authResponse(
            accessToken: 'access-after-refresh',
            refreshToken: 'refresh-after-refresh',
          )),
          200,
        );
      }
      mutationCalls++;
      return http.Response('unauthorized', 401);
    });

    auth.httpClient = mutationClient;
    final api = ApiClient(httpClient: mutationClient, authService: auth);
    await expectLater(
      api.createIncident(
        category: 'DRAIN_BLOCKAGE',
        description: 'Blocked drain near road',
        latitude: 15.5,
        longitude: 73.8,
        severity: 'MEDIUM',
      ),
      throwsA(predicate((error) =>
          error is ApiException &&
          error.statusCode == 401 &&
          error.message.contains('not replayed'))),
    );

    expect(mutationCalls, 1);
    expect(auth.currentToken, 'access-after-refresh');
  });


}
