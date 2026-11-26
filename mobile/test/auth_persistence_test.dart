import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('Supabase restores persisted session after client reinitialization', () async {
    SharedPreferences.setMockInitialValues({});
    final now = DateTime.now().toUtc();
    final exp = now.millisecondsSinceEpoch ~/ 1000 + 3600;
    final payload = base64Url.encode(
      utf8.encode(jsonEncode({'exp': exp})),
    ).replaceAll('=', '');
    final accessToken = 'eyJhbGciOiJub25lIn0.$payload.signature';

    MockClient authClient() => MockClient((request) async {
      if (request.url.path.endsWith('/token') &&
          request.url.queryParameters['grant_type'] == 'password') {
        return http.Response(
          jsonEncode({
            'access_token': accessToken,
            'refresh_token': 'persisted-refresh-token',
            'token_type': 'bearer',
            'expires_in': 3600,
            'expires_at': exp,
            'user': {
              'id': 'persisted-user-1',
              'aud': 'authenticated',
              'created_at': now.toIso8601String(),
              'email': 'persisted@drainx.gov',
              'app_metadata': {'role': 'worker'},
              'user_metadata': {'full_name': 'Persisted Worker'},
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

    await Supabase.initialize(
      url: 'https://mock.supabase.co',
      publishableKey: 'mock-publishable-key',
      httpClient: authClient(),
      authOptions: const FlutterAuthClientOptions(
        autoRefreshToken: false,
        persistSession: true,
      ),
    );

    await Supabase.instance.client.auth.signInWithPassword(
      email: 'persisted@drainx.gov',
      password: 'Secret123!',
    );

    final preferences = await SharedPreferences.getInstance();
    expect(preferences.getString('sb-mock-auth-token'), isNotNull);
    await Supabase.instance.dispose();

    await Supabase.initialize(
      url: 'https://mock.supabase.co',
      publishableKey: 'mock-publishable-key',
      httpClient: authClient(),
      authOptions: const FlutterAuthClientOptions(
        autoRefreshToken: false,
        persistSession: true,
      ),
    );

    final restored = Supabase.instance.client.auth.currentSession;
    expect(restored, isNotNull);
    expect(restored!.user.id, 'persisted-user-1');
    expect(restored.accessToken, accessToken);
    expect(restored.refreshToken, 'persisted-refresh-token');

    // Local sign-out must also remove the persisted refresh token so a reload
    // cannot silently restore a user who explicitly logged out.
    await Supabase.instance.dispose();
  });
}
