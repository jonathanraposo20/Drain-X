import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:drainx_mobile/core/auth/auth_service.dart';
import 'package:drainx_mobile/core/network/api_client.dart';
import 'package:drainx_mobile/core/services/location_service.dart';
import 'package:drainx_mobile/core/services/media_service.dart';
import 'package:drainx_mobile/core/utils/validators.dart';
import 'package:drainx_mobile/features/citizen/citizen_dashboard_screen.dart';
import 'package:drainx_mobile/features/citizen/citizen_report_detail_screen.dart';
import 'package:drainx_mobile/features/citizen/citizen_report_screen.dart';
import 'package:drainx_mobile/models/incident.dart';

class MockLocationService implements LocationService {
  final LocationResult result;
  bool appSettingsOpened = false;
  bool locationSettingsOpened = false;

  MockLocationService({
    this.result = const LocationResult.success(
      latitude: 15.4925,
      longitude: 73.8240,
      accuracyMeters: 4.8,
    ),
  });

  @override
  Future<LocationResult> getCurrentLocation({Duration timeout = const Duration(seconds: 12)}) async {
    return result;
  }

  @override
  Future<bool> openAppSettings() async {
    appSettingsOpened = true;
    return true;
  }

  @override
  Future<bool> openLocationSettings() async {
    locationSettingsOpened = true;
    return true;
  }
}

class MockMediaService implements MediaService {
  final PhotoUploadItem? photoToReturn;

  MockMediaService({this.photoToReturn});

  @override
  Future<PhotoUploadItem?> pickImageFromCamera() async {
    return photoToReturn ??
        PhotoUploadItem(
          filename: 'camera_evidence.jpg',
          bytes: Uint8List.fromList([0xFF, 0xD8, 0xFF, 0xE0, ...List.filled(100, 0x12)]),
          mimeType: 'image/jpeg',
        );
  }

  @override
  Future<PhotoUploadItem?> pickImageFromGallery() async {
    return photoToReturn ??
        PhotoUploadItem(
          filename: 'gallery_evidence.png',
          bytes: Uint8List.fromList([0x89, 0x50, 0x4E, 0x47, ...List.filled(100, 0x34)]),
          mimeType: 'image/png',
        );
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    AuthService().logout();
  });

  tearDown(() {
    AuthService().logout();
  });

  group('Citizen Reporting Workflow — Validation Rules', () {
    test('validates description min length, max length, and empty inputs', () {
      expect(Validators.validateDescription(null), isNotNull);
      expect(Validators.validateDescription(''), isNotNull);
      expect(Validators.validateDescription('  '), isNotNull);
      expect(Validators.validateDescription('ab'), isNotNull);
      expect(Validators.validateDescription('abc'), isNull); // 3 chars minimum
      expect(Validators.validateDescription('Culvert blocked near market with plastic bags'), isNull);

      final overLength = 'A' * 1001;
      expect(Validators.validateDescription(overLength), isNotNull);
    });

    test('validates latitude coordinate boundaries (-90 to 90)', () {
      expect(Validators.validateLatitude(null), isNotNull);
      expect(Validators.validateLatitude(''), isNotNull);
      expect(Validators.validateLatitude('not-a-number'), isNotNull);
      expect(Validators.validateLatitude('-90.1'), isNotNull);
      expect(Validators.validateLatitude('90.1'), isNotNull);
      expect(Validators.validateLatitude('15.4925'), isNull);
      expect(Validators.validateLatitude('-15.4925'), isNull);
      expect(Validators.validateLatitude('0.0'), isNull);
    });

    test('validates longitude coordinate boundaries (-180 to 180)', () {
      expect(Validators.validateLongitude(null), isNotNull);
      expect(Validators.validateLongitude(''), isNotNull);
      expect(Validators.validateLongitude('xyz'), isNotNull);
      expect(Validators.validateLongitude('-180.1'), isNotNull);
      expect(Validators.validateLongitude('180.1'), isNotNull);
      expect(Validators.validateLongitude('73.8240'), isNull);
      expect(Validators.validateLongitude('-73.8240'), isNull);
      expect(Validators.validateLongitude('0.0'), isNull);
    });
  });

  group('Citizen Reporting Form — Reality & Geolocation', () {
    testWidgets('renders all 7 backend hazard categories in card grid', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: CitizenReportScreen(reporterName: 'Maria Fernandes'),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('1. SELECT HAZARD CATEGORY *'), findsOneWidget);
      expect(find.text('Drain Blockage'), findsOneWidget);
      expect(find.text('Urban Flooding'), findsOneWidget);
      expect(find.text('Street Waterlogging'), findsOneWidget);
      expect(find.text('Drain Overflow'), findsOneWidget);
      expect(find.text('Manhole Lid Damage'), findsOneWidget);
      expect(find.text('Infrastructure Damage'), findsOneWidget);
      expect(find.text('Other Drainage Issue'), findsOneWidget);
    });

    testWidgets('real device location permission granted updates coordinates and actual accuracy', (tester) async {
      final mockLocation = MockLocationService(
        result: const LocationResult.success(
          latitude: 15.4988,
          longitude: 73.8277,
          accuracyMeters: 6.2,
        ),
      );

      await tester.pumpWidget(
        MaterialApp(
          home: CitizenReportScreen(
            reporterName: 'Citizen Tester',
            locationService: mockLocation,
          ),
        ),
      );
      await tester.pumpAndSettle();

      final gpsBtn = find.text('Acquire GPS');
      await tester.ensureVisible(gpsBtn);
      await tester.tap(gpsBtn);
      await tester.pumpAndSettle();

      expect(find.text('15.498800'), findsOneWidget);
      expect(find.text('73.827700'), findsOneWidget);
      expect(find.textContaining('Accuracy: ±6.2m'), findsWidgets);
    });

    testWidgets('permission denied displays honest warning and prompts manual entry', (tester) async {
      final mockLocation = MockLocationService(
        result: const LocationResult.failure(
          errorMessage: 'Location permission was denied. You may enter coordinates manually or retry.',
          isPermissionDenied: true,
        ),
      );

      await tester.pumpWidget(
        MaterialApp(
          home: CitizenReportScreen(
            reporterName: 'Citizen Tester',
            locationService: mockLocation,
          ),
        ),
      );
      await tester.pumpAndSettle();

      final gpsBtn = find.text('Acquire GPS');
      await tester.ensureVisible(gpsBtn);
      await tester.tap(gpsBtn);
      await tester.pumpAndSettle();

      expect(find.textContaining('Location permission was denied'), findsWidgets);
    });

    testWidgets('GPS timeout displays honest failure and offers manual coordinate entry', (tester) async {
      final mockLocation = MockLocationService(
        result: const LocationResult.failure(
          errorMessage: 'GPS acquisition timed out waiting for satellite fix.',
          isTimeout: true,
        ),
      );

      await tester.pumpWidget(
        MaterialApp(
          home: CitizenReportScreen(
            reporterName: 'Citizen Tester',
            locationService: mockLocation,
          ),
        ),
      );
      await tester.pumpAndSettle();

      final gpsBtn = find.text('Acquire GPS');
      await tester.ensureVisible(gpsBtn);
      await tester.tap(gpsBtn);
      await tester.pumpAndSettle();

      expect(find.textContaining('GPS acquisition timed out'), findsWidgets);
    });

    testWidgets('selecting preset landmark clearly marks manual reference preset', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: CitizenReportScreen(reporterName: 'Citizen Anonymous'),
        ),
      );
      await tester.pumpAndSettle();

      // Tap on preset landmark "Fontainhas Heritage Drain"
      final presetChip = find.text('Fontainhas Heritage Drain');
      await tester.ensureVisible(presetChip);
      await tester.tap(presetChip);
      await tester.pumpAndSettle();

      expect(find.text('15.4965'), findsOneWidget);
      expect(find.text('73.8305'), findsOneWidget);
      expect(find.textContaining('Reference Preset: Fontainhas Heritage Drain'), findsOneWidget);
    });

    testWidgets('manual coordinate fallback allows direct text input and validation', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: CitizenReportScreen(reporterName: 'Manual Operator'),
        ),
      );
      await tester.pumpAndSettle();

      final latField = find.widgetWithText(TextFormField, 'Latitude (°N)');
      final lngField = find.widgetWithText(TextFormField, 'Longitude (°E)');

      await tester.enterText(latField, '15.4910');
      await tester.enterText(lngField, '73.8205');
      await tester.pumpAndSettle();

      expect(find.text('15.4910'), findsOneWidget);
      expect(find.text('73.8205'), findsOneWidget);
    });
  });

  group('Citizen Reporting Form — Photo Pipeline & Integrity', () {
    testWidgets('attaching photographic evidence via media service respects 3 photo limit', (tester) async {
      final mockMedia = MockMediaService();

      await tester.pumpWidget(
        MaterialApp(
          home: CitizenReportScreen(
            reporterName: 'Citizen Tester',
            mediaService: mockMedia,
          ),
        ),
      );
      await tester.pumpAndSettle();

      final cameraButton = find.text('Capture Camera');
      await tester.ensureVisible(cameraButton);

      // Attach 1st photo
      await tester.tap(cameraButton);
      await tester.pumpAndSettle();
      expect(find.text('1/3 photos (Max 5MB ea)'), findsOneWidget);
      expect(find.text('camera_evidence.jpg'), findsOneWidget);

      // Attach 2nd photo
      final galleryButton = find.text('Device Gallery');
      await tester.tap(galleryButton);
      await tester.pumpAndSettle();
      expect(find.text('2/3 photos (Max 5MB ea)'), findsOneWidget);
      expect(find.text('gallery_evidence.png'), findsOneWidget);

      // Attach 3rd photo
      await tester.tap(cameraButton);
      await tester.pumpAndSettle();
      expect(find.text('3/3 photos (Max 5MB ea)'), findsOneWidget);

      // Remove 1st photo
      final removeIcon = find.byIcon(Icons.close).first;
      await tester.tap(removeIcon);
      await tester.pumpAndSettle();
      expect(find.text('2/3 photos (Max 5MB ea)'), findsOneWidget);
    });

    testWidgets('successful incident submission pipeline with photos triggers confirmation dialog', (tester) async {
      tester.view.physicalSize = const Size(800, 2400);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      bool incidentCreated = false;
      bool photosUploaded = false;
      String? capturedCategory;
      String? capturedSource;
      String? capturedReporterName;

      final mockClient = MockClient((request) async {
        if (request.method == 'POST' && request.url.path == '/api/v1/incidents') {
          incidentCreated = true;
          final body = jsonDecode(request.body) as Map<String, dynamic>;
          capturedCategory = body['category'] as String?;
          capturedSource = body['source'] as String?;
          capturedReporterName = body['reporter_name'] as String?;
          return http.Response(
            jsonEncode({
              'id': 'INC-WORKFLOW-01',
              'category': 'DRAIN_BLOCKAGE',
              'description': body['description'],
              'latitude': body['latitude'],
              'longitude': body['longitude'],
              'severity': body['severity'],
              'status': 'REPORTED',
              'source': 'CITIZEN',
              'reporter_name': 'Maria Fernandes',
              'created_at': DateTime.now().toIso8601String(),
              'updated_at': DateTime.now().toIso8601String(),
              'photos': [],
            }),
            201,
            headers: {'content-type': 'application/json; charset=utf-8'},
          );
        } else if (request.method == 'POST' && request.url.path.contains('/photos')) {
          photosUploaded = true;
          return http.Response(
            jsonEncode({
              'id': 'INC-WORKFLOW-01',
              'category': 'DRAIN_BLOCKAGE',
              'description': 'Culvert blocked',
              'latitude': 15.4925,
              'longitude': 73.8240,
              'severity': 'HIGH',
              'status': 'REPORTED',
              'source': 'CITIZEN',
              'reporter_name': 'Maria Fernandes',
              'created_at': DateTime.now().toIso8601String(),
              'updated_at': DateTime.now().toIso8601String(),
              'photos': ['/api/v1/incidents/photos/camera_evidence.jpg'],
            }),
            200,
            headers: {'content-type': 'application/json; charset=utf-8'},
          );
        }
        return http.Response('Not Found', 404);
      });

      final apiClient = ApiClient(httpClient: mockClient);
      final mockLocation = MockLocationService();
      final mockMedia = MockMediaService();

      await tester.pumpWidget(
        MaterialApp(
          home: CitizenReportScreen(
            reporterName: 'Maria Fernandes',
            apiClient: apiClient,
            locationService: mockLocation,
            mediaService: mockMedia,
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Acquire location via mock
      final gpsBtn = find.text('Acquire GPS');
      await tester.ensureVisible(gpsBtn);
      await tester.tap(gpsBtn);
      await tester.pumpAndSettle();

      // Enter description via Key
      final descField = find.byKey(const Key('description_field'));
      await tester.ensureVisible(descField);
      await tester.enterText(descField, 'Culvert grating completely submerged under storm debris.');
      await tester.pumpAndSettle();

      // Attach 1 photo via media service
      final cameraBtn = find.text('Capture Camera');
      await tester.ensureVisible(cameraBtn);
      await tester.tap(cameraBtn);
      await tester.pumpAndSettle();

      // Submit
      final submitBtnFinder = find.byKey(const Key('submit_report_button'));
      await tester.ensureVisible(submitBtnFinder);
      final submitBtn = tester.widget<ElevatedButton>(submitBtnFinder);
      expect(submitBtn.onPressed, isNotNull);
      submitBtn.onPressed!();
      await tester.pumpAndSettle();

      expect(incidentCreated, isTrue);
      expect(capturedCategory, 'DRAIN_BLOCKAGE');
      expect(capturedSource, 'CITIZEN');
      expect(capturedReporterName, 'Maria Fernandes');
      expect(photosUploaded, isTrue);
      expect(find.text('Incident Reported Successfully'), findsOneWidget);
      expect(find.text('INC-WORKFLOW-01'), findsOneWidget);
    });

    testWidgets('photo upload failure allows retry without creating duplicate incident', (tester) async {
      tester.view.physicalSize = const Size(800, 2400);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(() {
        tester.view.resetPhysicalSize();
        tester.view.resetDevicePixelRatio();
      });

      int incidentCreationCount = 0;
      int photoUploadAttempts = 0;

      final mockClient = MockClient((request) async {
        if (request.method == 'POST' && request.url.path == '/api/v1/incidents') {
          incidentCreationCount++;
          return http.Response(
            jsonEncode({
              'id': 'INC-RETRY-01',
              'category': 'WATERLOGGING',
              'description': 'Waterlogging across avenue',
              'latitude': 15.4925,
              'longitude': 73.8240,
              'severity': 'MEDIUM',
              'status': 'REPORTED',
              'source': 'CITIZEN',
              'reporter_name': 'Citizen Anonymous',
              'created_at': DateTime.now().toIso8601String(),
              'updated_at': DateTime.now().toIso8601String(),
              'photos': [],
            }),
            201,
            headers: {'content-type': 'application/json; charset=utf-8'},
          );
        } else if (request.method == 'POST' && request.url.path.contains('/photos')) {
          photoUploadAttempts++;
          if (photoUploadAttempts == 1) {
            // First attempt fails
            return http.Response(
              jsonEncode({'detail': 'Storage service temporarily busy'}),
              503,
              headers: {'content-type': 'application/json; charset=utf-8'},
            );
          } else {
            // Second attempt succeeds
            return http.Response(
              jsonEncode({
                'id': 'INC-RETRY-01',
                'category': 'WATERLOGGING',
                'description': 'Waterlogging across avenue',
                'latitude': 15.4925,
                'longitude': 73.8240,
                'severity': 'MEDIUM',
                'status': 'REPORTED',
                'source': 'CITIZEN',
                'reporter_name': 'Citizen Anonymous',
                'created_at': DateTime.now().toIso8601String(),
                'updated_at': DateTime.now().toIso8601String(),
                'photos': ['/api/v1/incidents/photos/camera_evidence.jpg'],
              }),
              200,
              headers: {'content-type': 'application/json; charset=utf-8'},
            );
          }
        }
        return http.Response('Not Found', 404);
      });

      final apiClient = ApiClient(httpClient: mockClient);
      final mockLocation = MockLocationService();
      final mockMedia = MockMediaService();

      await tester.pumpWidget(
        MaterialApp(
          home: CitizenReportScreen(
            reporterName: 'Citizen Anonymous',
            apiClient: apiClient,
            locationService: mockLocation,
            mediaService: mockMedia,
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Acquire location
      final gpsBtn = find.text('Acquire GPS');
      await tester.ensureVisible(gpsBtn);
      await tester.tap(gpsBtn);
      await tester.pumpAndSettle();

      // Enter description
      final descField = find.byKey(const Key('description_field'));
      await tester.ensureVisible(descField);
      await tester.enterText(descField, 'Waterlogging across main avenue near shop.');
      await tester.pumpAndSettle();

      // Attach photo
      final cameraBtn = find.text('Capture Camera');
      await tester.ensureVisible(cameraBtn);
      await tester.tap(cameraBtn);
      await tester.pumpAndSettle();

      // Submit
      final submitBtnFinder = find.byKey(const Key('submit_report_button'));
      await tester.ensureVisible(submitBtnFinder);
      final submitBtn = tester.widget<ElevatedButton>(submitBtnFinder);
      submitBtn.onPressed!();
      await tester.pumpAndSettle();

      // Warning dialog appears
      expect(find.text('Report Registered with Photo Warning'), findsOneWidget);
      expect(photoUploadAttempts, 1);
      expect(incidentCreationCount, 1);

      // Tap Retry Photo Upload
      final retryBtn = find.text('Retry Photo Upload');
      expect(retryBtn, findsOneWidget);
      await tester.tap(retryBtn);
      await tester.pumpAndSettle();

      // Photo upload succeeded on second attempt; incident was NOT duplicated
      expect(photoUploadAttempts, 2);
      expect(incidentCreationCount, 1); // Crucial: Still only 1 incident created!
      expect(find.text('Incident Reported Successfully'), findsOneWidget);
      expect(find.text('INC-RETRY-01'), findsOneWidget);
    });
  });

  group('Citizen Dashboard & Data Integrity', () {
    final testIncidents = [
      Incident(
        id: 'INC-FEED-01',
        category: 'DRAIN_BLOCKAGE',
        description: 'Major tree trunk blocking culvert flow',
        latitude: 15.4925,
        longitude: 73.8240,
        severity: 'HIGH',
        status: 'INVESTIGATING',
        source: 'CITIZEN',
        createdAt: DateTime.now().subtract(const Duration(hours: 2)),
        updatedAt: DateTime.now().subtract(const Duration(hours: 1)),
        reporterName: 'Maria Fernandes',
        assignedTo: 'Team Alpha - St. Inez Drainage Crew',
      ),
      Incident(
        id: 'INC-FEED-02',
        category: 'WATERLOGGING',
        description: 'Puddle in front of medical store',
        latitude: 15.4989,
        longitude: 73.8342,
        severity: 'LOW',
        status: 'RESOLVED',
        source: 'CITIZEN',
        createdAt: DateTime.now().subtract(const Duration(days: 1)),
        updatedAt: DateTime.now().subtract(const Duration(hours: 5)),
        reporterName: 'Dr. Coutinho',
        assignedTo: 'Team Bravo',
      ),
      Incident(
        id: 'INC-FEED-03',
        category: 'FLOODING',
        description: 'Water overtopping river embankment',
        latitude: 15.4835,
        longitude: 73.8078,
        severity: 'CRITICAL',
        status: 'REPORTED',
        source: 'CITIZEN',
        createdAt: DateTime.now().subtract(const Duration(hours: 1)),
        updatedAt: DateTime.now().subtract(const Duration(hours: 1)),
        reporterName: 'Citizen Anonymous',
        assignedTo: null, // No crew assigned yet
      ),
    ];

    testWidgets('calculates KPIs strictly from API data without fake inference', (tester) async {
      final mockClient = MockClient((request) async {
        return http.Response(
          jsonEncode(testIncidents.map((i) => i.toJson()).toList()),
          200,
          headers: {'content-type': 'application/json; charset=utf-8'},
        );
      });
      final apiClient = ApiClient(httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: CitizenDashboardScreen(
            reporterName: 'Maria Fernandes',
            apiClient: apiClient,
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Active Hazards = 2 (INC-FEED-01 INVESTIGATING, INC-FEED-03 REPORTED)
      // Crew Assigned = 1 (INC-FEED-01 is INVESTIGATING with assignedTo; INC-FEED-03 has null assignedTo)
      // Resolved = 1 (INC-FEED-02)
      expect(find.text('ACTIVE HAZARDS'), findsOneWidget);
      expect(find.text('CREW ASSIGNED'), findsOneWidget);
      expect(find.text('RESOLVED'), findsAtLeastNWidgets(1));

      expect(find.text('2'), findsWidgets); // Active count
      expect(find.text('1'), findsWidgets); // Crew assigned & resolved counts
    });

    testWidgets('empty API response displays truthful empty state and 0 counts', (tester) async {
      final mockClient = MockClient((request) async {
        return http.Response(
          '[]',
          200,
          headers: {'content-type': 'application/json; charset=utf-8'},
        );
      });
      final apiClient = ApiClient(httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: CitizenDashboardScreen(
            reporterName: 'Maria Fernandes',
            apiClient: apiClient,
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('No Incidents in System'), findsOneWidget);
      expect(find.text('All Reports'), findsOneWidget);
    });

    testWidgets('API error displays retry UI without substituting fake incidents', (tester) async {
      final mockClient = MockClient((request) async {
        return http.Response(
          jsonEncode({'detail': 'Database connection failure'}),
          500,
          headers: {'content-type': 'application/json; charset=utf-8'},
        );
      });
      final apiClient = ApiClient(httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: CitizenDashboardScreen(
            reporterName: 'Maria Fernandes',
            apiClient: apiClient,
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Shows error message and retry button
      expect(find.text('Retry Connection'), findsOneWidget);
      // No fake incidents displayed
      expect(find.text('INC-FEED-01'), findsNothing);
      expect(find.text('INC-FEED-02'), findsNothing);
      // KPIs show unavailable indicator
      expect(find.text('--'), findsWidgets);
    });

    testWidgets('anonymous reports in MINE tab displays unlinked privacy explanation', (tester) async {
      final mockClient = MockClient((request) async {
        return http.Response(
          jsonEncode(testIncidents.map((i) => i.toJson()).toList()),
          200,
          headers: {'content-type': 'application/json; charset=utf-8'},
        );
      });
      final apiClient = ApiClient(httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: CitizenDashboardScreen(
            reporterName: 'Citizen Anonymous',
            apiClient: apiClient,
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Tap MINE tab
      final mineChip = find.text('My Submissions');
      await tester.tap(mineChip);
      await tester.pumpAndSettle();

      // Explains that anonymous reports are unlinked
      expect(find.text('Anonymous Reports Are Unlinked'), findsOneWidget);
      expect(find.textContaining('To protect civic privacy'), findsOneWidget);
    });
  });

  group('Citizen Report Detail Screen — Privacy & Field Filtering', () {
    testWidgets('renders public triage information and suppresses internal secrets', (tester) async {
      final sampleIncident = Incident(
        id: 'INC-DETAIL-01',
        category: 'FLOODING',
        description: 'Road completely submerged under 40cm stormwater',
        latitude: 15.4950,
        longitude: 73.8210,
        severity: 'CRITICAL',
        status: 'INVESTIGATING',
        source: 'CITIZEN',
        createdAt: DateTime.now().subtract(const Duration(hours: 3)),
        updatedAt: DateTime.now().subtract(const Duration(minutes: 30)),
        reporterName: 'Sunil Rao',
        assignedTo: 'Team Alpha - St. Inez Drainage Crew',
        municipalNotes: 'Submersible pump truck on-site. Grate clearing in progress.',
        photos: [],
      );

      final mockClient = MockClient((request) async {
        if (request.url.path.contains('/api/v1/incidents/INC-DETAIL-01')) {
          return http.Response(
            jsonEncode(sampleIncident.toJson()),
            200,
            headers: {'content-type': 'application/json; charset=utf-8'},
          );
        }
        return http.Response('Not Found', 404);
      });
      final apiClient = ApiClient(httpClient: mockClient);

      await tester.pumpWidget(
        MaterialApp(
          home: CitizenReportDetailScreen(
            incidentId: 'INC-DETAIL-01',
            apiClient: apiClient,
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('Ticket: INC-DETAIL-01'), findsOneWidget);
      expect(find.text('Urban Flooding'), findsOneWidget);
      expect(find.text('Stage: INVESTIGATING'), findsOneWidget);
      expect(find.text('MUNICIPAL WORKFLOW LIFECYCLE'), findsOneWidget);
      expect(find.textContaining('Road completely submerged'), findsOneWidget);
      expect(find.textContaining('15.4950° N, 73.8210° E'), findsOneWidget);
      expect(find.text('Copy Coords'), findsOneWidget);
      expect(find.text('Team Alpha - St. Inez Drainage Crew'), findsOneWidget);
      expect(find.text('Submersible pump truck on-site. Grate clearing in progress.'), findsOneWidget);

      // Verify personal citizen reporter name is not leaked publicly on the detail view
      expect(find.text('Sunil Rao'), findsNothing);
    });
  });
}
