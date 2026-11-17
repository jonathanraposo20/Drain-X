class ApiConfig {
  // Default to Android Emulator host IP (10.0.2.2).
  // Can be adjusted at runtime to 'localhost' or computer LAN IP (e.g. 192.168.1.15:8000).
  static String baseUrl = 'http://10.0.2.2:8000';

  // Optional Supabase endpoints for live authentication (never store service-role key)
  static String? supabaseUrl;
  static String? supabaseAnonKey;

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
    'Android Emulator (10.0.2.2:8000)': 'http://10.0.2.2:8000',
    'Localhost (Desktop/Web 8000)': 'http://localhost:8000',
    'Local Loopback (127.0.0.1:8000)': 'http://127.0.0.1:8000',
  };
}
