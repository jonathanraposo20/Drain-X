import 'package:flutter/foundation.dart';

class ApiConfig {
  static const String _envBaseUrl = String.fromEnvironment(
    'DRAINX_API_BASE_URL',
    defaultValue: '',
  );
  static const String _envSupabaseUrl = String.fromEnvironment(
    'SUPABASE_URL',
    defaultValue: '',
  );
  static const String _envSupabaseAnonKey = String.fromEnvironment(
    'SUPABASE_ANON_KEY',
    defaultValue: '',
  );

  // Default to localhost on Web, Android Emulator host IP (10.0.2.2) on mobile,
  // or compile-time --dart-define=DRAINX_API_BASE_URL when provided.
  static String baseUrl = _envBaseUrl.isNotEmpty
      ? _envBaseUrl
      : (kIsWeb ? 'http://localhost:8000' : 'http://10.0.2.2:8000');

  // Optional Supabase endpoints for live authentication (never store service-role key)
  static String? supabaseUrl = _envSupabaseUrl.isNotEmpty ? _envSupabaseUrl : null;
  static String? supabaseAnonKey = _envSupabaseAnonKey.isNotEmpty ? _envSupabaseAnonKey : null;

  static const String apiV1Prefix = '/api/v1';

  static String get incidentsUrl => '$baseUrl$apiV1Prefix/incidents';
  static String get municipalKpisUrl => '$incidentsUrl/municipal/kpis';
  static String get municipalQueueUrl => '$incidentsUrl/municipal/queue';
  static String get fieldTeamsUrl => '$incidentsUrl/field-teams';

  static String incidentDetailUrl(String id) => '$incidentsUrl/$id';
  static String incidentPhotosUploadUrl(String id) => '$incidentsUrl/$id/photos';
  static String incidentVerifyUrl(String id) => '$incidentsUrl/$id/verify';
  static String incidentAssignUrl(String id) => '$incidentsUrl/$id/assign';
  static String incidentReassignUrl(String id) => '$incidentsUrl/$id/reassign';
  static String incidentUnassignUrl(String id) => '$incidentsUrl/$id/unassign';
  static String incidentRejectUrl(String id) => '$incidentsUrl/$id/reject';
  static String incidentAuditUrl(String id) => '$incidentsUrl/$id/audit';

  static String resolvePhotoUrl(String photoPath) {
    if (photoPath.startsWith('http://') || photoPath.startsWith('https://')) {
      return photoPath;
    }
    // Relative photo path like /api/v1/incidents/photos/xxxx.jpg
    final cleanPath = photoPath.startsWith('/') ? photoPath : '/$photoPath';
    return '$baseUrl$cleanPath';
  }

  // Pre-configured environments for easy switching in demo mode
  static const Map<String, String> presetEnvironments = {
    'Production Render Backend': 'https://drainx-backend.onrender.com',
    'Android Emulator (10.0.2.2:8000)': 'http://10.0.2.2:8000',
    'Localhost (Desktop/Web 8000)': 'http://localhost:8000',
    'Local Loopback (127.0.0.1:8000)': 'http://127.0.0.1:8000',
  };
}
