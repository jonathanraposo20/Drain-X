import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Narrow persistence contract so authentication logic can be tested without
/// platform channels and production tokens never enter ordinary preferences.
abstract interface class SecureSessionStore {
  Future<String?> readSession();
  Future<void> writeSession(String value);
  Future<void> clearSession();
}

class FlutterSecureSessionStore implements SecureSessionStore {
  FlutterSecureSessionStore({FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  static const _sessionKey = 'drainx.auth.session.v1';
  final FlutterSecureStorage _storage;

  @override
  Future<String?> readSession() => _storage.read(key: _sessionKey);

  @override
  Future<void> writeSession(String value) =>
      _storage.write(key: _sessionKey, value: value);

  @override
  Future<void> clearSession() => _storage.delete(key: _sessionKey);
}
