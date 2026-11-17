import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:drainx_mobile/core/network/api_client.dart';
import 'package:drainx_mobile/features/municipal/municipal_dashboard_screen.dart';
import 'package:drainx_mobile/models/incident.dart';
import 'package:drainx_mobile/widgets/incident_card.dart';

void main() {
  final testIncidents = [
    Incident(
      id: 'INC-DEMO-01',
      category: 'DRAIN_OVERFLOW',
      description: 'Severe storm runoff overflowing culvert near St. Inez Church',
      latitude: 15.492,
      longitude: 73.8185,
      severity: 'CRITICAL',
      status: 'INVESTIGATING',
      source: 'DEMO',
      createdAt: DateTime.now().subtract(const Duration(hours: 2)),
      updatedAt: DateTime.now().subtract(const Duration(hours: 1)),
      assignedTo: 'Team Alpha — St. Inez Drainage Crew',
    ),
    Incident(
      id: 'INC-DEMO-02',
      category: 'WATERLOGGING',
      description: 'Street waterlogging near Patto Plaza commercial district',
      latitude: 15.4989,
      longitude: 73.8342,
      severity: 'HIGH',
      status: 'ASSIGNED',
      source: 'DEMO',
      createdAt: DateTime.now().subtract(const Duration(hours: 4)),
      updatedAt: DateTime.now().subtract(const Duration(hours: 2)),
      assignedTo: 'Team Beta — Patto Rapid Response',
    ),
    Incident(
      id: 'INC-DEMO-03',
      category: 'DRAIN_BLOCKAGE',
      description: 'Accumulation of debris blocking culvert inlet',
      latitude: 15.4965,
      longitude: 73.8305,
      severity: 'MEDIUM',
      status: 'REPORTED',
      source: 'CITIZEN',
      createdAt: DateTime.now().subtract(const Duration(hours: 6)),
      updatedAt: DateTime.now().subtract(const Duration(hours: 5)),
      assignedTo: null,
    ),
    Incident(
      id: 'INC-DEMO-04',
      category: 'INFRASTRUCTURE_DAMAGE',
      description: 'Displaced concrete grating slab over main drain box',
      latitude: 15.4835,
      longitude: 73.8078,
      severity: 'LOW',
      status: 'RESOLVED',
      source: 'DEMO',
      createdAt: DateTime.now().subtract(const Duration(days: 1)),
      updatedAt: DateTime.now().subtract(const Duration(hours: 12)),
      assignedTo: 'Team Delta — Miramar Outfall Sluice Unit',
    ),
  ];

  final testKpis = {
    'total_incidents': 4,
    'open_incidents': 3,
    'critical_or_high_incidents': 2,
    'unassigned_incidents': 1,
    'assigned_incidents': 2,
    'investigating_incidents': 1,
    'resolved_incidents': 1,
    'rejected_incidents': 0,
    'by_category': {
      'DRAIN_OVERFLOW': 1,
      'WATERLOGGING': 1,
      'DRAIN_BLOCKAGE': 1,
    },
    'by_severity': {
      'CRITICAL': 1,
      'HIGH': 1,
      'MEDIUM': 1,
    },
    'by_status': {
      'REPORTED': 1,
      'ASSIGNED': 1,
      'INVESTIGATING': 1,
      'RESOLVED': 1,
    },
  };

  group('Municipal Operations Dashboard Tests', () {
    testWidgets('renders officer banner and authoritative KPIs', (tester) async {
      final mockClient = MockClient((request) async {
        if (request.url.path.contains('/municipal/kpis')) {
          return http.Response(jsonEncode(testKpis), 200, headers: {'content-type': 'application/json'});
        }
        return http.Response(
          jsonEncode({
            'items': testIncidents.map((i) => i.toJson()).toList(),
            'total_count': testIncidents.length,
            'limit': 50,
            'offset': 0,
            'has_more': false,
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final apiClient = ApiClient(httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: MunicipalDashboardScreen(
            officerName: 'Inspector Rajesh Naik',
            apiClient: apiClient,
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Officer Identity
      expect(find.text('Inspector Rajesh Naik'), findsOneWidget);
      expect(find.text('PANAJI BASIN'), findsOneWidget);

      // KPI Titles (rendered in uppercase by KpiCard)
      expect(find.text('TOTAL TICKETS'), findsOneWidget);
      expect(find.text('ACTIVE OPEN'), findsOneWidget);
      expect(find.text('CRITICAL/HIGH'), findsOneWidget);
      expect(find.text('CREWS DISPATCHED'), findsOneWidget);
      expect(find.text('RESOLVED'), findsAtLeastNWidgets(1));

      // KPI Values from backend
      expect(find.text('4'), findsWidgets); // Total
      expect(find.text('3'), findsWidgets); // Open
      expect(find.text('2'), findsWidgets); // Critical/High & Dispatched
      expect(find.text('1'), findsWidgets); // Resolved
    });

    testWidgets('renders queue items and supports search filtering', (tester) async {
      final mockClient = MockClient((request) async {
        if (request.url.path.contains('/municipal/kpis')) {
          return http.Response(jsonEncode(testKpis), 200, headers: {'content-type': 'application/json'});
        }
        return http.Response(
          jsonEncode({
            'items': testIncidents.map((i) => i.toJson()).toList(),
            'total_count': testIncidents.length,
            'limit': 50,
            'offset': 0,
            'has_more': false,
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final apiClient = ApiClient(httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: MunicipalDashboardScreen(
            officerName: 'Inspector Rajesh Naik',
            apiClient: apiClient,
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('INC-DEMO-01'), findsOneWidget);
      expect(find.text('INC-DEMO-02'), findsOneWidget);
      expect(find.text('INC-DEMO-03'), findsOneWidget);
      expect(find.text('INC-DEMO-04'), findsOneWidget);

      // Filter by search query
      await tester.enterText(find.byType(TextField), 'Patto');
      await tester.pumpAndSettle();

      expect(find.text('INC-DEMO-02'), findsOneWidget);
      expect(find.text('INC-DEMO-01'), findsNothing);
      expect(find.text('INC-DEMO-03'), findsNothing);
    });

    testWidgets('status filter chips narrow displayed incidents', (tester) async {
      final mockClient = MockClient((request) async {
        if (request.url.path.contains('/municipal/kpis')) {
          return http.Response(jsonEncode(testKpis), 200, headers: {'content-type': 'application/json'});
        }
        return http.Response(
          jsonEncode({
            'items': testIncidents.map((i) => i.toJson()).toList(),
            'total_count': testIncidents.length,
            'limit': 50,
            'offset': 0,
            'has_more': false,
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final apiClient = ApiClient(httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: MunicipalDashboardScreen(
            officerName: 'Inspector Rajesh Naik',
            apiClient: apiClient,
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Tap 'RESOLVED' filter chip
      await tester.tap(find.widgetWithText(FilterChip, 'RESOLVED'));
      await tester.pumpAndSettle();

      expect(find.text('INC-DEMO-04'), findsOneWidget);
      expect(find.text('INC-DEMO-01'), findsNothing);
    });

    testWidgets('source filter chips filter demo vs genuine records and displays audit transparency', (tester) async {
      final mockClient = MockClient((request) async {
        if (request.url.path.contains('/municipal/kpis')) {
          return http.Response(jsonEncode({
            ...testKpis,
            'demo_incidents_count': 3,
            'genuine_incidents_count': 1,
          }), 200, headers: {'content-type': 'application/json'});
        }
        return http.Response(
          jsonEncode({
            'items': testIncidents.map((i) => i.toJson()).toList(),
            'total_count': testIncidents.length,
            'limit': 50,
            'offset': 0,
            'has_more': false,
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final apiClient = ApiClient(httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: MunicipalDashboardScreen(
            officerName: 'Inspector Rajesh Naik',
            apiClient: apiClient,
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Data Integrity Audit breakdown banner
      expect(find.text('Genuine: 1'), findsOneWidget);
      expect(find.text('Demo Seeds: 3'), findsOneWidget);

      // Verify badges on cards
      expect(find.descendant(of: find.byType(IncidentCard), matching: find.text('DEMO SEED')), findsNWidgets(3));
      expect(find.descendant(of: find.byType(IncidentCard), matching: find.text('CITIZEN')), findsOneWidget);

      // Verify simulated coordinate formatting
      expect(find.textContaining('(Simulated)'), findsWidgets);

      // Tap 'CITIZEN' source filter chip
      await tester.tap(find.widgetWithText(FilterChip, 'CITIZEN'));
      await tester.pumpAndSettle();

      expect(find.text('INC-DEMO-03'), findsOneWidget);
      expect(find.text('INC-DEMO-01'), findsNothing);
      expect(find.text('INC-DEMO-02'), findsNothing);
      expect(find.text('INC-DEMO-04'), findsNothing);
    });

    testWidgets('shows empty state view when no tickets match filters', (tester) async {
      final mockClient = MockClient((request) async {
        if (request.url.path.contains('/municipal/kpis')) {
          return http.Response(jsonEncode(testKpis), 200, headers: {'content-type': 'application/json'});
        }
        return http.Response(
          jsonEncode({
            'items': testIncidents.map((i) => i.toJson()).toList(),
            'total_count': testIncidents.length,
            'limit': 50,
            'offset': 0,
            'has_more': false,
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      });

      final apiClient = ApiClient(httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: MunicipalDashboardScreen(
            officerName: 'Inspector Rajesh Naik',
            apiClient: apiClient,
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Search non-existent string
      await tester.enterText(find.byType(TextField), 'NONEXISTENT_QUERY_XYZ');
      await tester.pumpAndSettle();

      expect(find.text('No Matching Tickets'), findsOneWidget);
      expect(find.text('0 shown'), findsOneWidget);
    });

    testWidgets('handles HTTP 403 Forbidden with municipal access restricted banner', (tester) async {
      final mockClient = MockClient((request) async {
        return http.Response('Forbidden', 403);
      });

      final apiClient = ApiClient(httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: MunicipalDashboardScreen(
            officerName: 'Inspector Rajesh Naik',
            apiClient: apiClient,
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('Municipal Access Restricted (HTTP 403)'), findsOneWidget);
      expect(find.textContaining('requires municipal officer or administrator credentials'), findsOneWidget);
    });

    testWidgets('handles HTTP 401 Unauthorized with session expired banner', (tester) async {
      final mockClient = MockClient((request) async {
        return http.Response('Unauthorized', 401);
      });

      final apiClient = ApiClient(httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: MunicipalDashboardScreen(
            officerName: 'Inspector Rajesh Naik',
            apiClient: apiClient,
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('Session Expired (HTTP 401)'), findsOneWidget);
      expect(find.text('Return to Login'), findsOneWidget);
    });
  });
}
