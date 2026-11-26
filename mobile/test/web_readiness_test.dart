import 'package:flutter_test/flutter_test.dart';
import 'package:drainx_mobile/core/config/api_config.dart';

void main() {
  group('Flutter Web & Cross-Platform Config Readiness', () {
    test('ApiConfig resolves endpoints cleanly without hardcoded secrets', () {
      expect(ApiConfig.baseUrl, isNotEmpty);
      expect(
        ApiConfig.presetEnvironments['Production Render Backend'],
        'https://drainx-backend.onrender.com',
      );
      expect(
        ApiConfig.resolvePhotoUrl('/api/v1/incidents/photos/test.jpg'),
        '${ApiConfig.baseUrl}/api/v1/incidents/photos/test.jpg',
      );
      expect(
        ApiConfig.resolvePhotoUrl('https://example.supabase.co/storage/v1/object/sign/test.jpg'),
        'https://example.supabase.co/storage/v1/object/sign/test.jpg',
      );
    });
  });
}
