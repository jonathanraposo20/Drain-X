import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:http_parser/http_parser.dart';
import '../config/api_config.dart';
import '../auth/auth_service.dart';
import '../../models/incident.dart';

class PhotoUploadItem {
  final String filename;
  final Uint8List bytes;
  final String mimeType;

  PhotoUploadItem({
    required this.filename,
    required this.bytes,
    this.mimeType = 'image/jpeg',
  });
}

class ApiException implements Exception {
  final int statusCode;
  final String message;

  ApiException(this.statusCode, this.message);

  @override
  String toString() => 'ApiException ($statusCode): $message';
}

class ApiClient {
  final http.Client _httpClient;
  final AuthService _authService;

  ApiClient({
    http.Client? httpClient,
    AuthService? authService,
  })  : _httpClient = httpClient ?? http.Client(),
        _authService = authService ?? AuthService();

  Map<String, String> _buildHeaders([Map<String, String>? extra]) {
    final headers = <String, String>{
      'Content-Type': 'application/json',
    };
    final token = _authService.currentToken;
    if (token != null && token.isNotEmpty) {
      headers['Authorization'] = 'Bearer $token';
    }
    if (extra != null) {
      headers.addAll(extra);
    }
    return headers;
  }

  /// Validates session expiry prior to initiating an authenticated request.
  /// Detects expired JWTs before placing bytes on the network.
  Future<void> _preflightSessionCheck() async {
    try {
      await _authService.ensureValidSession();
    } on AuthException catch (error) {
      throw ApiException(error.statusCode ?? 0, error.message);
    }
  }

  /// Centralized response inspection for 401/403 status codes.
  /// Enforces:
  /// - 401 Unauthorized: Invalidates session and clears credentials centrally.
  /// - 403 Forbidden: Preserves valid user session (do NOT log out).
  void _handleResponseStatus(int statusCode, String responseBody) {
    if (statusCode == 401) {
      _authService.handleUnauthorized();
      throw ApiException(401, 'Session unauthorized or expired (HTTP 401). Stale session invalidated.');
    }
    if (statusCode == 403) {
      // HTTP 403 Forbidden strictly does NOT invalidate the user session.
      // The user is authenticated but lacks permission for this action.
      throw ApiException(403, 'Permission denied (HTTP 403): $responseBody');
    }
  }

  // 1. GET /api/v1/incidents
  Future<List<Incident>> getIncidents({
    String? status,
    String? category,
    String? severity,
    String? source,
  }) async {
    await _preflightSessionCheck();

    final queryParams = <String, String>{};
    if (status != null && status != 'ALL') queryParams['status'] = status;
    if (category != null && category != 'ALL') queryParams['category'] = category;
    if (severity != null && severity != 'ALL') queryParams['severity'] = severity;
    if (source != null && source != 'ALL') queryParams['source'] = source;

    final uri = Uri.parse(ApiConfig.incidentsUrl).replace(queryParameters: queryParams.isEmpty ? null : queryParams);

    try {
      final response = await _httpClient
          .get(uri, headers: _buildHeaders())
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final List<dynamic> data = jsonDecode(response.body) as List<dynamic>;
        return data.map((json) => Incident.fromJson(json as Map<String, dynamic>)).toList();
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Failed to fetch incidents: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Unable to connect to DRAIN-X backend at ${ApiConfig.baseUrl}. Please check network connection.');
    }
  }

  // 2. GET /api/v1/incidents/{id}
  Future<Incident> getIncident(String id) async {
    await _preflightSessionCheck();

    final uri = Uri.parse(ApiConfig.incidentDetailUrl(id));
    try {
      final response = await _httpClient
          .get(uri, headers: _buildHeaders())
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final Map<String, dynamic> data = jsonDecode(response.body) as Map<String, dynamic>;
        return Incident.fromJson(data);
      } else if (response.statusCode == 404) {
        throw ApiException(404, 'Incident with ID $id not found.');
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Failed to retrieve incident: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Connection error: ${e.toString()}');
    }
  }

  // 3. POST /api/v1/incidents
  Future<Incident> createIncident({
    required String category,
    required String description,
    required double latitude,
    required double longitude,
    required String severity,
    String source = 'CITIZEN',
    String? reporterName,
  }) async {
    await _preflightSessionCheck();

    final uri = Uri.parse(ApiConfig.incidentsUrl);
    final payload = {
      'category': category,
      'description': description,
      'latitude': latitude,
      'longitude': longitude,
      'severity': severity,
      'source': source,
      'reporter_name': reporterName ?? 'Citizen Anonymous',
    };

    try {
      final response = await _httpClient
          .post(
            uri,
            headers: _buildHeaders(),
            body: jsonEncode(payload),
          )
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 201) {
        final Map<String, dynamic> data = jsonDecode(response.body) as Map<String, dynamic>;
        return Incident.fromJson(data);
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Failed to create report: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Connection error: ${e.toString()}');
    }
  }

  // 4. POST /api/v1/incidents/{id}/photos
  Future<Incident> uploadIncidentPhotos(String incidentId, List<PhotoUploadItem> photos) async {
    if (photos.isEmpty) {
      return getIncident(incidentId);
    }

    await _preflightSessionCheck();

    final uri = Uri.parse(ApiConfig.incidentPhotosUploadUrl(incidentId));
    final request = http.MultipartRequest('POST', uri);

    final token = _authService.currentToken;
    if (token != null && token.isNotEmpty) {
      request.headers['Authorization'] = 'Bearer $token';
    }

    for (final photo in photos) {
      final mediaParts = photo.mimeType.split('/');
      final mediaType = MediaType(mediaParts[0], mediaParts.length > 1 ? mediaParts[1] : 'jpeg');

      final multipartFile = http.MultipartFile.fromBytes(
        'files',
        photo.bytes,
        filename: photo.filename,
        contentType: mediaType,
      );
      request.files.add(multipartFile);
    }

    try {
      final streamedResponse = await _httpClient.send(request).timeout(const Duration(seconds: 25));
      final response = await http.Response.fromStream(streamedResponse);

      if (response.statusCode == 200) {
        final Map<String, dynamic> data = jsonDecode(response.body) as Map<String, dynamic>;
        return Incident.fromJson(data);
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Photo upload error: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Failed to upload photo evidence: ${e.toString()}');
    }
  }

  // 5. PATCH /api/v1/incidents/{id}
  Future<Incident> updateIncident(
    String id, {
    String? status,
    String? assignedTo,
    String? municipalNotes,
  }) async {
    await _preflightSessionCheck();

    final uri = Uri.parse(ApiConfig.incidentDetailUrl(id));
    final payload = <String, dynamic>{};

    if (status != null) payload['status'] = status;
    if (assignedTo != null) payload['assigned_to'] = assignedTo;
    if (municipalNotes != null) payload['municipal_notes'] = municipalNotes;

    try {
      final response = await _httpClient
          .patch(
            uri,
            headers: _buildHeaders(),
            body: jsonEncode(payload),
          )
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final Map<String, dynamic> data = jsonDecode(response.body) as Map<String, dynamic>;
        return Incident.fromJson(data);
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Failed to update ticket: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Failed to update incident: ${e.toString()}');
    }
  }

  // 6. GET /api/v1/incidents/municipal/kpis
  Future<Map<String, dynamic>> getMunicipalKpis() async {
    await _preflightSessionCheck();

    final uri = Uri.parse(ApiConfig.municipalKpisUrl);
    try {
      final response = await _httpClient
          .get(uri, headers: _buildHeaders())
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        return jsonDecode(response.body) as Map<String, dynamic>;
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Failed to fetch municipal KPIs: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Unable to connect to DRAIN-X backend at ${ApiConfig.baseUrl}. Please check network connection.');
    }
  }

  // 7. GET /api/v1/incidents/municipal/queue
  Future<Map<String, dynamic>> getMunicipalQueue({
    String? status,
    String? category,
    String? severity,
    String? source,
    String? assignedTo,
    String? search,
    int limit = 50,
    int offset = 0,
  }) async {
    await _preflightSessionCheck();

    final queryParams = <String, String>{
      'limit': limit.toString(),
      'offset': offset.toString(),
    };
    if (status != null && status != 'ALL') queryParams['status'] = status;
    if (category != null && category != 'ALL') queryParams['category'] = category;
    if (severity != null && severity != 'ALL') queryParams['severity'] = severity;
    if (source != null && source != 'ALL') queryParams['source'] = source;
    if (assignedTo != null && assignedTo != 'ALL') queryParams['assigned_to'] = assignedTo;
    if (search != null && search.trim().isNotEmpty) queryParams['search'] = search.trim();

    final uri = Uri.parse(ApiConfig.municipalQueueUrl).replace(queryParameters: queryParams);
    try {
      final response = await _httpClient
          .get(uri, headers: _buildHeaders())
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final Map<String, dynamic> data = jsonDecode(response.body) as Map<String, dynamic>;
        final itemsList = (data['items'] as List<dynamic>?)
            ?.map((json) => Incident.fromJson(json as Map<String, dynamic>))
            .toList() ?? [];
        return {
          'total': data['total'] ?? 0,
          'items': itemsList,
          'limit': data['limit'] ?? limit,
          'offset': data['offset'] ?? offset,
        };
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Failed to fetch operations queue: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Failed to fetch operations queue: ${e.toString()}');
    }
  }

  // 8. GET /api/v1/incidents/field-teams
  Future<List<FieldTeam>> getFieldTeams() async {
    await _preflightSessionCheck();

    final uri = Uri.parse(ApiConfig.fieldTeamsUrl);
    try {
      final response = await _httpClient
          .get(uri, headers: _buildHeaders())
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final List<dynamic> data = jsonDecode(response.body) as List<dynamic>;
        return data.map((j) => FieldTeam.fromJson(j as Map<String, dynamic>)).toList();
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Failed to fetch field teams: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Failed to fetch field teams: ${e.toString()}');
    }
  }

  // 9. POST /api/v1/incidents/{id}/verify
  Future<Incident> verifyIncident(
    String id, {
    String? notes,
    String? severity,
    String? internalNotes,
  }) async {
    await _preflightSessionCheck();

    final uri = Uri.parse(ApiConfig.incidentVerifyUrl(id));
    final payload = <String, dynamic>{};
    if (notes != null && notes.isNotEmpty) payload['notes'] = notes;
    if (severity != null) payload['severity'] = severity;
    if (internalNotes != null && internalNotes.isNotEmpty) payload['internal_notes'] = internalNotes;

    try {
      final response = await _httpClient
          .post(
            uri,
            headers: _buildHeaders(),
            body: jsonEncode(payload),
          )
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final Map<String, dynamic> data = jsonDecode(response.body) as Map<String, dynamic>;
        return Incident.fromJson(data);
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Verification failed: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Failed to verify incident: ${e.toString()}');
    }
  }

  // 10. POST /api/v1/incidents/{id}/assign
  Future<Incident> assignIncident(
    String id, {
    required String assignedTo,
    String? reason,
    String? internalNotes,
  }) async {
    await _preflightSessionCheck();

    final uri = Uri.parse(ApiConfig.incidentAssignUrl(id));
    final payload = <String, dynamic>{
      'assigned_to': assignedTo,
    };
    if (reason != null && reason.isNotEmpty) payload['reason'] = reason;
    if (internalNotes != null && internalNotes.isNotEmpty) payload['internal_notes'] = internalNotes;

    try {
      final response = await _httpClient
          .post(
            uri,
            headers: _buildHeaders(),
            body: jsonEncode(payload),
          )
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final Map<String, dynamic> data = jsonDecode(response.body) as Map<String, dynamic>;
        return Incident.fromJson(data);
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Assignment failed: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Failed to assign incident: ${e.toString()}');
    }
  }

  // 11. POST /api/v1/incidents/{id}/reassign
  Future<Incident> reassignIncident(
    String id, {
    required String assignedTo,
    required String reason,
    String? internalNotes,
  }) async {
    await _preflightSessionCheck();

    final uri = Uri.parse(ApiConfig.incidentReassignUrl(id));
    final payload = <String, dynamic>{
      'assigned_to': assignedTo,
      'reason': reason,
    };
    if (internalNotes != null && internalNotes.isNotEmpty) payload['internal_notes'] = internalNotes;

    try {
      final response = await _httpClient
          .post(
            uri,
            headers: _buildHeaders(),
            body: jsonEncode(payload),
          )
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final Map<String, dynamic> data = jsonDecode(response.body) as Map<String, dynamic>;
        return Incident.fromJson(data);
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Reassignment failed: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Failed to reassign incident: ${e.toString()}');
    }
  }

  // 12. POST /api/v1/incidents/{id}/unassign
  Future<Incident> unassignIncident(
    String id, {
    required String reason,
    String? internalNotes,
  }) async {
    await _preflightSessionCheck();

    final uri = Uri.parse(ApiConfig.incidentUnassignUrl(id));
    final payload = <String, dynamic>{
      'reason': reason,
    };
    if (internalNotes != null && internalNotes.isNotEmpty) payload['internal_notes'] = internalNotes;

    try {
      final response = await _httpClient
          .post(
            uri,
            headers: _buildHeaders(),
            body: jsonEncode(payload),
          )
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final Map<String, dynamic> data = jsonDecode(response.body) as Map<String, dynamic>;
        return Incident.fromJson(data);
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Unassignment failed: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Failed to unassign incident: ${e.toString()}');
    }
  }

  // 13. POST /api/v1/incidents/{id}/reject
  Future<Incident> rejectIncident(
    String id, {
    required String reason,
    String? internalNotes,
  }) async {
    await _preflightSessionCheck();

    final uri = Uri.parse(ApiConfig.incidentRejectUrl(id));
    final payload = <String, dynamic>{
      'reason': reason,
    };
    if (internalNotes != null && internalNotes.isNotEmpty) payload['internal_notes'] = internalNotes;

    try {
      final response = await _httpClient
          .post(
            uri,
            headers: _buildHeaders(),
            body: jsonEncode(payload),
          )
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final Map<String, dynamic> data = jsonDecode(response.body) as Map<String, dynamic>;
        return Incident.fromJson(data);
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Rejection failed: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Failed to reject incident: ${e.toString()}');
    }
  }

  // 14. GET /api/v1/incidents/{id}/audit
  Future<List<IncidentAudit>> getIncidentAudits(String id) async {
    await _preflightSessionCheck();

    final uri = Uri.parse(ApiConfig.incidentAuditUrl(id));
    try {
      final response = await _httpClient
          .get(uri, headers: _buildHeaders())
          .timeout(const Duration(seconds: 10));

      if (response.statusCode == 200) {
        final List<dynamic> data = jsonDecode(response.body) as List<dynamic>;
        return data.map((j) => IncidentAudit.fromJson(j as Map<String, dynamic>)).toList();
      } else {
        _handleResponseStatus(response.statusCode, response.body);
        throw ApiException(response.statusCode, 'Failed to fetch incident audit trail: ${response.body}');
      }
    } catch (e) {
      if (e is ApiException) rethrow;
      throw ApiException(0, 'Failed to fetch incident audit trail: ${e.toString()}');
    }
  }
}
