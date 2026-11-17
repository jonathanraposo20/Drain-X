import 'package:flutter_test/flutter_test.dart';
import 'package:drainx_mobile/models/incident.dart';

void main() {
  group('Incident Model & Lifecycle Transitions', () {
    test('parses Incident from backend JSON contract', () {
      final json = {
        'id': 'INC-TEST-01',
        'category': 'DRAIN_BLOCKAGE',
        'description': 'Culvert choked with debris and plastics.',
        'latitude': 15.4925,
        'longitude': 73.8240,
        'severity': 'HIGH',
        'status': 'REPORTED',
        'source': 'CITIZEN',
        'created_at': '2026-11-07T10:00:00Z',
        'updated_at': '2026-11-07T10:00:00Z',
        'reporter_name': 'P. Fernandes',
        'assigned_to': null,
        'municipal_notes': null,
        'photos': ['/api/v1/incidents/photos/INC-TEST-01_abcd1234.jpg'],
      };

      final incident = Incident.fromJson(json);

      expect(incident.id, 'INC-TEST-01');
      expect(incident.category, 'DRAIN_BLOCKAGE');
      expect(incident.severity, 'HIGH');
      expect(incident.status, 'REPORTED');
      expect(incident.source, 'CITIZEN');
      expect(incident.photos.length, 1);
      expect(incident.photos[0], contains('INC-TEST-01'));
    });

    test('enforces legal municipal status transitions', () {
      final allowedFromReported = IncidentConstants.getAllowedNextStatuses('REPORTED');
      expect(allowedFromReported, contains('REPORTED'));
      expect(allowedFromReported, contains('VERIFIED'));
      expect(allowedFromReported, contains('ASSIGNED'));
      expect(allowedFromReported, contains('REJECTED'));
      // Direct jump from REPORTED to INVESTIGATING or RESOLVED is NOT allowed
      expect(allowedFromReported.contains('INVESTIGATING'), isFalse);
      expect(allowedFromReported.contains('RESOLVED'), isFalse);

      final allowedFromInvestigating = IncidentConstants.getAllowedNextStatuses('INVESTIGATING');
      expect(allowedFromInvestigating, contains('RESOLVED'));
      expect(allowedFromInvestigating, contains('ASSIGNED'));
      expect(allowedFromInvestigating, contains('REJECTED'));
    });

    test('serializes Incident to JSON', () {
      final incident = Incident(
        id: 'INC-TEST-02',
        category: 'WATERLOGGING',
        description: 'Road submerged under 20cm water.',
        latitude: 15.4989,
        longitude: 73.8342,
        severity: 'MEDIUM',
        status: 'ASSIGNED',
        source: 'CITIZEN',
        createdAt: DateTime.parse('2026-11-07T10:30:00Z'),
        updatedAt: DateTime.parse('2026-11-07T11:00:00Z'),
        assignedTo: 'Team Beta — Patto Rapid Response',
        municipalNotes: 'Suction tanker deployed.',
        reporterName: 'R. Naik',
        photos: ['/api/v1/incidents/photos/photo1.jpg', '/api/v1/incidents/photos/photo2.jpg'],
      );

      final json = incident.toJson();
      expect(json['id'], 'INC-TEST-02');
      expect(json['assigned_to'], 'Team Beta — Patto Rapid Response');
      expect((json['photos'] as List).length, 2);
    });
  });
}
