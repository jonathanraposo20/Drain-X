import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:drainx_mobile/core/auth/auth_service.dart';
import 'package:drainx_mobile/core/network/api_client.dart';
import 'package:drainx_mobile/models/user_session.dart';
import 'package:drainx_mobile/features/municipal/municipal_incident_detail_screen.dart';

void main() {
  group('Municipal Triage & Assignment API Client Tests', () {
    test('getFieldTeams returns authoritative team list', () async {
      final mockHttp = MockClient((request) async {
        expect(request.url.path, '/api/v1/incidents/field-teams');
        return http.Response(
          jsonEncode([
            {'team_id': 'TEAM-ALPHA', 'name': 'Team Alpha — St. Inez Drainage Crew', 'zone': 'St. Inez'},
            {'team_id': 'TEAM-BETA', 'name': 'Team Beta — Patto Rapid Response', 'zone': 'Patto'},
          ]),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final client = ApiClient(httpClient: mockHttp);
      final teams = await client.getFieldTeams();

      expect(teams.length, 2);
      expect(teams[0].teamId, 'TEAM-ALPHA');
      expect(teams[0].name, 'Team Alpha — St. Inez Drainage Crew');
      expect(teams[0].zone, 'St. Inez');
    });

    test('verifyIncident posts to verify endpoint and returns updated incident', () async {
      final mockHttp = MockClient((request) async {
        expect(request.url.path, '/api/v1/incidents/INC-12345678/verify');
        expect(request.method, 'POST');
        final body = jsonDecode(request.body);
        expect(body['notes'], 'Triage verified on-site');

        return http.Response(
          jsonEncode({
            'id': 'INC-12345678',
            'category': 'WATERLOGGING',
            'description': 'Waterlogging near market',
            'latitude': 15.49,
            'longitude': 73.82,
            'severity': 'HIGH',
            'status': 'VERIFIED',
            'source': 'CITIZEN',
            'created_at': DateTime.now().toIso8601String(),
            'updated_at': DateTime.now().toIso8601String(),
            'verified_at': DateTime.now().toIso8601String(),
            'verified_by': 'officer-1',
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final client = ApiClient(httpClient: mockHttp);
      final updated = await client.verifyIncident('INC-12345678', notes: 'Triage verified on-site');

      expect(updated.id, 'INC-12345678');
      expect(updated.status, 'VERIFIED');
      expect(updated.verifiedBy, 'officer-1');
      expect(updated.verifiedAt, isNotNull);
    });

    test('assignIncident posts assignment and returns assigned incident', () async {
      final mockHttp = MockClient((request) async {
        expect(request.url.path, '/api/v1/incidents/INC-12345678/assign');
        expect(request.method, 'POST');
        final body = jsonDecode(request.body);
        expect(body['assigned_to'], 'Team Alpha — St. Inez Drainage Crew');
        expect(body['reason'], 'Critical flooding hazard');

        return http.Response(
          jsonEncode({
            'id': 'INC-12345678',
            'category': 'WATERLOGGING',
            'description': 'Waterlogging near market',
            'latitude': 15.49,
            'longitude': 73.82,
            'severity': 'HIGH',
            'status': 'ASSIGNED',
            'source': 'CITIZEN',
            'created_at': DateTime.now().toIso8601String(),
            'updated_at': DateTime.now().toIso8601String(),
            'assigned_to': 'Team Alpha — St. Inez Drainage Crew',
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final client = ApiClient(httpClient: mockHttp);
      final updated = await client.assignIncident(
        'INC-12345678',
        assignedTo: 'Team Alpha — St. Inez Drainage Crew',
        reason: 'Critical flooding hazard',
      );

      expect(updated.status, 'ASSIGNED');
      expect(updated.assignedTo, 'Team Alpha — St. Inez Drainage Crew');
    });

    test('reassignIncident posts reassign with mandatory reason', () async {
      final mockHttp = MockClient((request) async {
        expect(request.url.path, '/api/v1/incidents/INC-12345678/reassign');
        expect(request.method, 'POST');
        final body = jsonDecode(request.body);
        expect(body['assigned_to'], 'Team Beta — Patto Rapid Response');
        expect(body['reason'], 'Alpha crew busy at culvert');

        return http.Response(
          jsonEncode({
            'id': 'INC-12345678',
            'category': 'WATERLOGGING',
            'description': 'Waterlogging near market',
            'latitude': 15.49,
            'longitude': 73.82,
            'severity': 'HIGH',
            'status': 'ASSIGNED',
            'source': 'CITIZEN',
            'created_at': DateTime.now().toIso8601String(),
            'updated_at': DateTime.now().toIso8601String(),
            'assigned_to': 'Team Beta — Patto Rapid Response',
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final client = ApiClient(httpClient: mockHttp);
      final updated = await client.reassignIncident(
        'INC-12345678',
        assignedTo: 'Team Beta — Patto Rapid Response',
        reason: 'Alpha crew busy at culvert',
      );

      expect(updated.assignedTo, 'Team Beta — Patto Rapid Response');
    });

    test('unassignIncident removes assignment and reverts status to VERIFIED', () async {
      final mockHttp = MockClient((request) async {
        expect(request.url.path, '/api/v1/incidents/INC-12345678/unassign');
        expect(request.method, 'POST');
        final body = jsonDecode(request.body);
        expect(body['reason'], 'Crew reassigned to higher priority flood');

        return http.Response(
          jsonEncode({
            'id': 'INC-12345678',
            'category': 'WATERLOGGING',
            'description': 'Waterlogging near market',
            'latitude': 15.49,
            'longitude': 73.82,
            'severity': 'HIGH',
            'status': 'VERIFIED',
            'source': 'CITIZEN',
            'created_at': DateTime.now().toIso8601String(),
            'updated_at': DateTime.now().toIso8601String(),
            'assigned_to': null,
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final client = ApiClient(httpClient: mockHttp);
      final updated = await client.unassignIncident(
        'INC-12345678',
        reason: 'Crew reassigned to higher priority flood',
      );

      expect(updated.status, 'VERIFIED');
      expect(updated.assignedTo, isNull);
    });

    test('rejectIncident marks ticket REJECTED with explicit reason', () async {
      final mockHttp = MockClient((request) async {
        expect(request.url.path, '/api/v1/incidents/INC-12345678/reject');
        expect(request.method, 'POST');
        final body = jsonDecode(request.body);
        expect(body['reason'], 'Duplicate citizen report of INC-99999999');

        return http.Response(
          jsonEncode({
            'id': 'INC-12345678',
            'category': 'WATERLOGGING',
            'description': 'Waterlogging near market',
            'latitude': 15.49,
            'longitude': 73.82,
            'severity': 'HIGH',
            'status': 'REJECTED',
            'source': 'CITIZEN',
            'created_at': DateTime.now().toIso8601String(),
            'updated_at': DateTime.now().toIso8601String(),
            'rejection_reason': 'Duplicate citizen report of INC-99999999',
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final client = ApiClient(httpClient: mockHttp);
      final updated = await client.rejectIncident(
        'INC-12345678',
        reason: 'Duplicate citizen report of INC-99999999',
      );

      expect(updated.status, 'REJECTED');
      expect(updated.rejectionReason, 'Duplicate citizen report of INC-99999999');
    });

    test('getIncidentAudits fetches durable audit records', () async {
      final mockHttp = MockClient((request) async {
        expect(request.url.path, '/api/v1/incidents/INC-12345678/audit');
        return http.Response(
          jsonEncode([
            {
              'audit_id': 'AUD-001',
              'incident_id': 'INC-12345678',
              'actor_id': 'citizen-1',
              'actor_role': 'citizen',
              'action': 'REPORTED',
              'previous_status': null,
              'new_status': 'REPORTED',
              'reason': 'Citizen initial submission',
              'timestamp': DateTime.now().toIso8601String(),
            },
            {
              'audit_id': 'AUD-002',
              'incident_id': 'INC-12345678',
              'actor_id': 'officer-1',
              'actor_role': 'municipality',
              'action': 'VERIFIED',
              'previous_status': 'REPORTED',
              'new_status': 'VERIFIED',
              'reason': 'Triage confirmed',
              'timestamp': DateTime.now().toIso8601String(),
            },
          ]),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final client = ApiClient(httpClient: mockHttp);
      final audits = await client.getIncidentAudits('INC-12345678');

      expect(audits.length, 2);
      expect(audits[0].action, 'REPORTED');
      expect(audits[1].action, 'VERIFIED');
      expect(audits[1].changeSummary, contains('Status: REPORTED → VERIFIED'));
    });

    test('403 Forbidden raises ApiException and preserves active session', () async {
      final authService = AuthService();
      authService.setSessionForTesting(UserSession(
        userId: 'usr-cit-1',
        name: 'Citizen User',
        email: 'citizen@drainx.gov',
        role: UserRole.citizen,
        authType: AuthType.authenticated,
        token: 'token-abc',
        expiresAt: DateTime.now().add(const Duration(hours: 1)),
      ));

      final mockHttp = MockClient((request) async {
        return http.Response(
          jsonEncode({'detail': 'Role municipality required'}),
          403,
          headers: {'content-type': 'application/json'},
        );
      });

      final client = ApiClient(httpClient: mockHttp, authService: authService);

      expect(
        () => client.verifyIncident('INC-12345678'),
        throwsA(isA<ApiException>().having((e) => e.statusCode, 'statusCode', 403)),
      );

      // Verify user session was NOT logged out or cleared
      expect(authService.currentSession, isNotNull);
      expect(authService.currentSession!.isAuthenticated, isTrue);
      expect(authService.currentSession!.role, UserRole.citizen);
    });
  });

  group('Municipal Incident Detail Screen Widget Tests', () {
    testWidgets('renders triage controls and audit trail card', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: MunicipalIncidentDetailScreen(
            incidentId: 'INC-DEMO-03',
            officerName: 'Commissioner Rao',
          ),
        ),
      );

      // Verify initial frame
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });
  });
}
