import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../../core/network/api_client.dart';
import '../../core/services/location_service.dart';
import '../../core/services/media_service.dart';
import '../../core/theme/app_theme.dart';
import '../../core/utils/validators.dart';
import '../../models/incident.dart';
import '../../widgets/severity_badge.dart';
import 'citizen_report_detail_screen.dart';

class CitizenReportScreen extends StatefulWidget {
  final String reporterName;
  final ApiClient? apiClient;
  final LocationService? locationService;
  final MediaService? mediaService;

  const CitizenReportScreen({
    super.key,
    required this.reporterName,
    this.apiClient,
    this.locationService,
    this.mediaService,
  });

  @override
  State<CitizenReportScreen> createState() => _CitizenReportScreenState();
}

class _CitizenReportScreenState extends State<CitizenReportScreen> {
  final _formKey = GlobalKey<FormState>();
  late final ApiClient _apiClient;
  late final LocationService _locationService;
  late final MediaService _mediaService;

  String _selectedCategory = 'DRAIN_BLOCKAGE';
  String _selectedSeverity = 'HIGH';
  final TextEditingController _descController = TextEditingController();
  final TextEditingController _landmarkController = TextEditingController();
  final TextEditingController _latController = TextEditingController();
  final TextEditingController _lngController = TextEditingController();

  final List<PhotoUploadItem> _attachedPhotos = [];
  bool _isAcquiringLocation = false;
  String _locationStatus = 'No location set (Acquire GPS or choose a reference preset)';
  bool _isSubmitting = false;
  String? _submissionStatusMessage;

  final List<Map<String, dynamic>> _quickLocations = [
    {'name': 'St. Inez Creek Culvert', 'lat': 15.4925, 'lng': 73.8240},
    {'name': 'Patto Plaza Junction', 'lat': 15.4989, 'lng': 73.8342},
    {'name': 'Fontainhas Heritage Drain', 'lat': 15.4965, 'lng': 73.8305},
    {'name': 'Miramar Outfall Sluice', 'lat': 15.4835, 'lng': 73.8078},
    {'name': 'Panaji Bus Terminus', 'lat': 15.4912, 'lng': 73.8210},
    {'name': 'Ribandar Causeway Bridge', 'lat': 15.5034, 'lng': 73.8541},
  ];

  @override
  void initState() {
    super.initState();
    _apiClient = widget.apiClient ?? ApiClient();
    _locationService = widget.locationService ?? const GeolocatorLocationService();
    _mediaService = widget.mediaService ?? DeviceMediaService();
  }

  @override
  void dispose() {
    _descController.dispose();
    _landmarkController.dispose();
    _latController.dispose();
    _lngController.dispose();
    super.dispose();
  }

  IconData _getCategoryIcon(String category) {
    switch (category) {
      case 'DRAIN_BLOCKAGE':
        return Icons.delete_sweep_rounded;
      case 'FLOODING':
        return Icons.flood_rounded;
      case 'WATERLOGGING':
        return Icons.water_damage_rounded;
      case 'DRAIN_OVERFLOW':
        return Icons.waves_rounded;
      case 'MANHOLE_DAMAGE':
        return Icons.warning_amber_rounded;
      case 'INFRASTRUCTURE_DAMAGE':
        return Icons.construction_rounded;
      case 'OTHER':
      default:
        return Icons.report_problem_outlined;
    }
  }

  Future<void> _acquireGpsLocation() async {
    setState(() {
      _isAcquiringLocation = true;
      _locationStatus = 'Acquiring GPS fix from device sensors...';
    });

    final result = await _locationService.getCurrentLocation();

    if (!mounted) return;

    setState(() {
      _isAcquiringLocation = false;
      if (result.isSuccess) {
        _latController.text = result.latitude!.toStringAsFixed(6);
        _lngController.text = result.longitude!.toStringAsFixed(6);
        final accuracyStr = result.accuracyMeters != null
            ? ' (Accuracy: ±${result.accuracyMeters!.toStringAsFixed(1)}m)'
            : '';
        _locationStatus = 'Device GPS Fixed$accuracyStr';
      } else {
        _locationStatus = result.errorMessage ?? 'GPS Acquisition Failed';
      }
    });

    if (result.isSuccess) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(_locationStatus),
          duration: const Duration(seconds: 2),
        ),
      );
    } else {
      if (result.isPermissionPermanentlyDenied) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(result.errorMessage ?? 'Location permission permanently denied.'),
            backgroundColor: const Color(0xFFDC2626),
            action: SnackBarAction(
              label: 'Settings',
              textColor: Colors.white,
              onPressed: () => _locationService.openAppSettings(),
            ),
          ),
        );
      } else if (result.isServiceDisabled) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(result.errorMessage ?? 'Location services disabled.'),
            backgroundColor: const Color(0xFFDC2626),
            action: SnackBarAction(
              label: 'Enable',
              textColor: Colors.white,
              onPressed: () => _locationService.openLocationSettings(),
            ),
          ),
        );
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(result.errorMessage ?? 'GPS Acquisition Failed. You can enter coordinates manually.'),
            backgroundColor: const Color(0xFFDC2626),
          ),
        );
      }
    }
  }

  Future<void> _addEvidencePhoto({required bool isCamera}) async {
    if (_attachedPhotos.length >= 3) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Maximum 3 photographic evidence files per incident permitted.'),
          backgroundColor: Color(0xFFDC2626),
        ),
      );
      return;
    }

    try {
      final item = isCamera
          ? await _mediaService.pickImageFromCamera()
          : await _mediaService.pickImageFromGallery();

      if (item == null) {
        // User cancelled photo selection
        return;
      }

      // Check size limit: 5MB (5242880 bytes)
      if (item.bytes.lengthInBytes > 5 * 1024 * 1024) {
        final mb = (item.bytes.lengthInBytes / (1024 * 1024)).toStringAsFixed(2);
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Selected image exceeds 5 MB limit ($mb MB). Please choose a smaller photo.'),
            backgroundColor: const Color(0xFFDC2626),
          ),
        );
        return;
      }

      if (!mounted) return;
      setState(() {
        _attachedPhotos.add(item);
      });

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Photo attached: ${item.filename} (${(item.bytes.lengthInBytes / 1024).toStringAsFixed(0)} KB)'),
          duration: const Duration(seconds: 2),
        ),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Failed to access device camera/gallery: $e'),
          backgroundColor: const Color(0xFFDC2626),
        ),
      );
    }
  }

  void _removePhoto(int index) {
    setState(() {
      _attachedPhotos.removeAt(index);
    });
  }

  Future<void> _submitReport() async {
    if (!_formKey.currentState!.validate()) {
      return;
    }

    setState(() {
      _isSubmitting = true;
      _submissionStatusMessage = 'Registering hazard report with DRAIN-X...';
    });

    try {
      final lat = double.parse(_latController.text.trim());
      final lng = double.parse(_lngController.text.trim());

      String description = _descController.text.trim();
      final landmark = _landmarkController.text.trim();
      if (landmark.isNotEmpty) {
        description = '$description (Landmark: $landmark)';
      }

      // Step 1: Create incident record via backend API
      final createdIncident = await _apiClient.createIncident(
        category: _selectedCategory,
        description: description,
        latitude: lat,
        longitude: lng,
        severity: _selectedSeverity,
        source: 'CITIZEN',
        reporterName: widget.reporterName.isEmpty ? 'Citizen Anonymous' : widget.reporterName,
      );

      final incidentId = createdIncident.id;

      // Step 2: Upload attached photos if present
      bool photoUploadFailed = false;
      String photoErrorMessage = '';

      if (_attachedPhotos.isNotEmpty) {
        setState(() {
          _submissionStatusMessage = 'Uploading ${_attachedPhotos.length} photographic evidence file(s)...';
        });

        try {
          await _apiClient.uploadIncidentPhotos(incidentId, _attachedPhotos);
        } catch (photoErr) {
          photoUploadFailed = true;
          photoErrorMessage = photoErr.toString();
        }
      }

      setState(() {
        _isSubmitting = false;
      });

      if (!mounted) return;

      // Handle Partial Failure (Incident Created, but Photos Failed)
      if (photoUploadFailed) {
        await _showPhotoUploadFailureDialog(incidentId, photoErrorMessage);
        return;
      }

      // Complete Success Dialog
      await _showSuccessDialog(incidentId, lat, lng);
    } catch (e) {
      setState(() {
        _isSubmitting = false;
      });
      if (!mounted) return;
      showDialog(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Submission Failed', style: TextStyle(color: Color(0xFFDC2626))),
          content: Text(e.toString(), style: const TextStyle(fontSize: 12)),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('OK'),
            ),
          ],
        ),
      );
    }
  }

  Future<void> _retryPhotoUpload(String incidentId) async {
    setState(() {
      _isSubmitting = true;
      _submissionStatusMessage = 'Retrying upload of ${_attachedPhotos.length} photo(s)...';
    });

    bool photoUploadFailed = false;
    String photoErrorMessage = '';

    try {
      await _apiClient.uploadIncidentPhotos(incidentId, _attachedPhotos);
    } catch (photoErr) {
      photoUploadFailed = true;
      photoErrorMessage = photoErr.toString();
    }

    setState(() {
      _isSubmitting = false;
    });

    if (!mounted) return;

    if (photoUploadFailed) {
      await _showPhotoUploadFailureDialog(incidentId, photoErrorMessage);
    } else {
      final lat = double.tryParse(_latController.text.trim()) ?? 0.0;
      final lng = double.tryParse(_lngController.text.trim()) ?? 0.0;
      await _showSuccessDialog(incidentId, lat, lng);
    }
  }

  Future<void> _showPhotoUploadFailureDialog(String incidentId, String photoErrorMessage) async {
    await showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        icon: const Icon(Icons.warning_amber_rounded, size: 44, color: Color(0xFFF59E0B)),
        title: const Text('Report Registered with Photo Warning'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Your incident was successfully recorded as tracking ID $incidentId, but uploading attached photos failed:',
              style: const TextStyle(fontSize: 12, color: Color(0xFF334155)),
            ),
            const SizedBox(height: 8),
            Text(
              photoErrorMessage,
              style: const TextStyle(fontSize: 11, color: Color(0xFFDC2626), fontFamily: 'monospace'),
            ),
            const SizedBox(height: 12),
            const Text(
              'You do NOT need to submit the report again. The municipal triage team can already view your report.',
              style: TextStyle(fontSize: 11, color: Color(0xFF64748B)),
            ),
          ],
        ),
        actions: [
          OutlinedButton(
            onPressed: () {
              Navigator.pop(ctx);
              Navigator.pop(context, true);
            },
            child: const Text('Return to Dashboard'),
          ),
          ElevatedButton.icon(
            icon: const Icon(Icons.refresh, size: 16),
            label: const Text('Retry Photo Upload'),
            onPressed: () {
              Navigator.pop(ctx);
              _retryPhotoUpload(incidentId);
            },
          ),
        ],
      ),
    );
  }

  Future<void> _showSuccessDialog(String incidentId, double lat, double lng) async {
    await showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        icon: const Icon(Icons.check_circle_rounded, size: 48, color: Color(0xFF16A34A)),
        title: const Text('Incident Reported Successfully', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Your drainage hazard report has been recorded and queued for municipal triage and field response crew dispatch.',
              style: TextStyle(fontSize: 12, color: Color(0xFF475569)),
            ),
            const SizedBox(height: 14),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0xFFF1F5F9),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFFE2E8F0)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text('Tracking Reference:', style: TextStyle(fontSize: 11, color: Color(0xFF64748B))),
                      Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Text(incidentId, style: const TextStyle(fontFamily: 'monospace', fontWeight: FontWeight.bold, fontSize: 13, color: Color(0xFF0284C7))),
                          const SizedBox(width: 4),
                          IconButton(
                            icon: const Icon(Icons.copy, size: 14, color: Color(0xFF0284C7)),
                            tooltip: 'Copy Tracking ID',
                            padding: EdgeInsets.zero,
                            constraints: const BoxConstraints(),
                            onPressed: () {
                              Clipboard.setData(ClipboardData(text: incidentId));
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(content: Text('Tracking ID $incidentId copied to clipboard.')),
                              );
                            },
                          ),
                        ],
                      ),
                    ],
                  ),
                  const Divider(height: 14, color: Color(0xFFCBD5E1)),
                  Text('Category: ${IncidentConstants.getCategoryDisplayName(_selectedCategory)}', style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600)),
                  Text('Severity: $_selectedSeverity', style: const TextStyle(fontSize: 11)),
                  Text('Coordinates: $lat° N, $lng° E', style: const TextStyle(fontSize: 11)),
                  if (_attachedPhotos.isNotEmpty)
                    Text('Evidence: ${_attachedPhotos.length} photo(s) attached', style: const TextStyle(fontSize: 11, color: Color(0xFF16A34A), fontWeight: FontWeight.bold)),
                ],
              ),
            ),
            const SizedBox(height: 10),
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: const Color(0xFFEFF6FF),
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: const Color(0xFFDBEAFE)),
              ),
              child: const Text(
                'Notice: Anonymous reports are not linked to a user account. Please retain your Tracking Reference to monitor resolution progress in the Citizen Portal. Unlinked reports will not automatically persist across device sessions.',
                style: TextStyle(fontSize: 10, color: Color(0xFF1E40AF)),
              ),
            ),
          ],
        ),
        actions: [
          OutlinedButton(
            onPressed: () {
              Navigator.pop(ctx);
              Navigator.pop(context, true);
            },
            child: const Text('Dashboard'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(ctx);
              Navigator.pushReplacement(
                context,
                MaterialPageRoute(
                  builder: (_) => CitizenReportDetailScreen(incidentId: incidentId),
                ),
              );
            },
            child: const Text('View Ticket'),
          ),
        ],
      ),
    );
  }

  Future<bool> _onWillPop() async {
    if (_descController.text.trim().isNotEmpty || _attachedPhotos.isNotEmpty) {
      final shouldPop = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Discard Unfinished Report?'),
          content: const Text('You have unsaved report observations. Are you sure you want to abandon this report?'),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Continue Editing'),
            ),
            ElevatedButton(
              style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFDC2626)),
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Discard'),
            ),
          ],
        ),
      );
      return shouldPop ?? false;
    }
    return true;
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, result) async {
        if (didPop) return;
        final shouldPop = await _onWillPop();
        if (shouldPop && context.mounted) {
          Navigator.pop(context);
        }
      },
      child: Scaffold(
        appBar: AppBar(
          title: const Text('Report Drainage Hazard'),
        ),
        body: SingleChildScrollView(
          padding: const EdgeInsets.all(20),
          child: Form(
            key: _formKey,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // SECTION 1: Incident Category
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(6),
                      decoration: BoxDecoration(
                        color: AppTheme.primaryNavy,
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: const Icon(Icons.category_rounded, size: 16, color: AppTheme.accentCyan),
                    ),
                    const SizedBox(width: 8),
                    const Text(
                      '1. SELECT HAZARD CATEGORY *',
                      style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Color(0xFF1E293B), letterSpacing: 0.5),
                    ),
                  ],
                ),
                const SizedBox(height: 10),

                // Category Card Grid
                GridView.builder(
                  shrinkWrap: true,
                  physics: const NeverScrollableScrollPhysics(),
                  gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: 2,
                    childAspectRatio: 2.2,
                    crossAxisSpacing: 10,
                    mainAxisSpacing: 10,
                  ),
                  itemCount: IncidentConstants.categories.length,
                  itemBuilder: (ctx, idx) {
                    final cat = IncidentConstants.categories[idx];
                    final isSelected = _selectedCategory == cat;
                    return InkWell(
                      onTap: () => setState(() => _selectedCategory = cat),
                      borderRadius: BorderRadius.circular(10),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                        decoration: BoxDecoration(
                          color: isSelected ? const Color(0xFFE0F2FE) : Colors.white,
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(
                            color: isSelected ? const Color(0xFF0284C7) : const Color(0xFFCBD5E1),
                            width: isSelected ? 2 : 1,
                          ),
                        ),
                        child: Row(
                          children: [
                            Icon(
                              _getCategoryIcon(cat),
                              color: isSelected ? const Color(0xFF0284C7) : const Color(0xFF64748B),
                              size: 24,
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Column(
                                mainAxisAlignment: MainAxisAlignment.center,
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    IncidentConstants.getCategoryDisplayName(cat),
                                    style: TextStyle(
                                      fontSize: 11,
                                      fontWeight: isSelected ? FontWeight.bold : FontWeight.w600,
                                      color: isSelected ? const Color(0xFF0369A1) : const Color(0xFF1E293B),
                                    ),
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                  Text(
                                    IncidentConstants.getCategoryDescription(cat),
                                    style: const TextStyle(fontSize: 9, color: Color(0xFF64748B)),
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                    );
                  },
                ),

                const SizedBox(height: 24),

                // SECTION 2: Perceived Severity
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(6),
                      decoration: BoxDecoration(
                        color: AppTheme.primaryNavy,
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: const Icon(Icons.speed_rounded, size: 16, color: AppTheme.accentTeal),
                    ),
                    const SizedBox(width: 8),
                    const Text(
                      '2. PERCEIVED SEVERITY *',
                      style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Color(0xFF1E293B), letterSpacing: 0.5),
                    ),
                  ],
                ),
                const SizedBox(height: 8),

                Row(
                  children: IncidentConstants.severities.map((sev) {
                    final isSelected = _selectedSeverity == sev;
                    return Expanded(
                      child: Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 3),
                        child: InkWell(
                          onTap: () => setState(() => _selectedSeverity = sev),
                          borderRadius: BorderRadius.circular(8),
                          child: Container(
                            padding: const EdgeInsets.symmetric(vertical: 10),
                            decoration: BoxDecoration(
                              color: isSelected ? AppTheme.primaryNavy : Colors.white,
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(
                                color: isSelected ? AppTheme.accentCyan : const Color(0xFFCBD5E1),
                                width: isSelected ? 1.8 : 1,
                              ),
                            ),
                            alignment: Alignment.center,
                            child: SeverityBadge(severity: sev, isCompact: true),
                          ),
                        ),
                      ),
                    );
                  }).toList(),
                ),
                const SizedBox(height: 4),
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 4),
                  child: Text(
                    IncidentConstants.getSeveritySubtitle(_selectedSeverity),
                    style: const TextStyle(fontSize: 10, color: Color(0xFF64748B), fontStyle: FontStyle.italic),
                  ),
                ),

                const SizedBox(height: 24),

                // SECTION 3: Incident Location
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(6),
                      decoration: BoxDecoration(
                        color: AppTheme.primaryNavy,
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: const Icon(Icons.my_location_rounded, size: 16, color: Color(0xFF38BDF8)),
                    ),
                    const SizedBox(width: 8),
                    const Text(
                      '3. INCIDENT LOCATION *',
                      style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Color(0xFF1E293B), letterSpacing: 0.5),
                    ),
                  ],
                ),
                const SizedBox(height: 8),

                // GPS Acquisition Button + Status Banner
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: const Color(0xFFF8FAFC),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: const Color(0xFFE2E8F0)),
                  ),
                  child: Column(
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Expanded(
                            child: Row(
                              children: [
                                const Icon(Icons.satellite_alt_rounded, size: 16, color: Color(0xFF0284C7)),
                                const SizedBox(width: 6),
                                Expanded(
                                  child: Text(
                                    _locationStatus,
                                    style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600, color: Color(0xFF334155)),
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                ),
                              ],
                            ),
                          ),
                          ElevatedButton.icon(
                            style: ElevatedButton.styleFrom(
                              backgroundColor: const Color(0xFF0284C7),
                              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                              minimumSize: Size.zero,
                            ),
                            icon: _isAcquiringLocation
                                ? const SizedBox(width: 12, height: 12, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                                : const Icon(Icons.gps_fixed_rounded, size: 14),
                            label: const Text('Acquire GPS', style: TextStyle(fontSize: 11)),
                            onPressed: _isAcquiringLocation ? null : _acquireGpsLocation,
                          ),
                        ],
                      ),
                      const SizedBox(height: 10),
                      Row(
                        children: [
                          Expanded(
                            child: TextFormField(
                              controller: _latController,
                              keyboardType: const TextInputType.numberWithOptions(decimal: true),
                              validator: Validators.validateLatitude,
                              decoration: const InputDecoration(labelText: 'Latitude (°N)', contentPadding: EdgeInsets.symmetric(horizontal: 10, vertical: 8)),
                              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: TextFormField(
                              controller: _lngController,
                              keyboardType: const TextInputType.numberWithOptions(decimal: true),
                              validator: Validators.validateLongitude,
                              decoration: const InputDecoration(labelText: 'Longitude (°E)', contentPadding: EdgeInsets.symmetric(horizontal: 10, vertical: 8)),
                              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 10),
                      TextFormField(
                        controller: _landmarkController,
                        decoration: const InputDecoration(
                          hintText: 'Landmark reference (e.g. Near St. Inez Bridge, opposite bank)',
                          labelText: 'Optional Landmark / Cross Street',
                          contentPadding: EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                        ),
                        style: const TextStyle(fontSize: 12),
                      ),
                    ],
                  ),
                ),

                const SizedBox(height: 10),

                // Common Panaji Basin Hotspots
                const Text('Reference Location Presets (Panaji Basin Hotspots):', style: TextStyle(fontSize: 10, color: Color(0xFF64748B), fontWeight: FontWeight.w600)),
                const Text('Selecting a preset enters reference hotspot coordinates (not a live GPS reading).', style: TextStyle(fontSize: 9, color: Color(0xFF94A3B8), fontStyle: FontStyle.italic)),
                const SizedBox(height: 6),
                Wrap(
                  spacing: 6,
                  runSpacing: 6,
                  children: _quickLocations.map((loc) {
                    return ActionChip(
                      avatar: const Icon(Icons.place, size: 14, color: AppTheme.accentTeal),
                      label: Text(loc['name'] as String, style: const TextStyle(fontSize: 10)),
                      backgroundColor: Colors.white,
                      side: const BorderSide(color: Color(0xFFCBD5E1)),
                      onPressed: () {
                        setState(() {
                          _latController.text = (loc['lat'] as double).toStringAsFixed(4);
                          _lngController.text = (loc['lng'] as double).toStringAsFixed(4);
                          _locationStatus = 'Reference Preset: ${loc['name']} (Manual Selection)';
                        });
                      },
                    );
                  }).toList(),
                ),

                const SizedBox(height: 24),

                // SECTION 4: Observations & Description
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Row(
                      children: [
                        Container(
                          padding: const EdgeInsets.all(6),
                          decoration: BoxDecoration(
                            color: AppTheme.primaryNavy,
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: const Icon(Icons.edit_note_rounded, size: 16, color: Color(0xFF38BDF8)),
                        ),
                        const SizedBox(width: 8),
                        const Text(
                          '4. HAZARD OBSERVATIONS *',
                          style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Color(0xFF1E293B), letterSpacing: 0.5),
                        ),
                      ],
                    ),
                    Text(
                      '${_descController.text.length}/1000',
                      style: const TextStyle(fontSize: 10, color: Color(0xFF64748B), fontFamily: 'monospace'),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                TextFormField(
                  key: const Key('description_field'),
                  controller: _descController,
                  maxLines: 4,
                  maxLength: 1000,
                  validator: Validators.validateDescription,
                  onChanged: (_) => setState(() {}),
                  decoration: const InputDecoration(
                    hintText: 'Describe the blockage, debris, estimated flood depth (e.g. 20cm), culvert status, or any imminent risk to homes or vehicles...',
                    counterText: '',
                  ),
                ),

                const SizedBox(height: 24),

                // SECTION 5: Photo Evidence
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Row(
                      children: [
                        Container(
                          padding: const EdgeInsets.all(6),
                          decoration: BoxDecoration(
                            color: AppTheme.primaryNavy,
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: const Icon(Icons.camera_alt_rounded, size: 16, color: AppTheme.accentCyan),
                        ),
                        const SizedBox(width: 8),
                        const Text(
                          '5. PHOTO EVIDENCE',
                          style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Color(0xFF1E293B), letterSpacing: 0.5),
                        ),
                      ],
                    ),
                    Text(
                      '${_attachedPhotos.length}/3 photos (Max 5MB ea)',
                      style: const TextStyle(fontSize: 11, color: Color(0xFF64748B), fontWeight: FontWeight.w600),
                    ),
                  ],
                ),
                const SizedBox(height: 10),

                // Photo Capture Actions
                Row(
                  children: [
                    Expanded(
                      child: OutlinedButton.icon(
                        icon: const Icon(Icons.camera_alt_outlined, size: 16),
                        label: const Text('Capture Camera', style: TextStyle(fontSize: 11)),
                        onPressed: _attachedPhotos.length >= 3 ? null : () => _addEvidencePhoto(isCamera: true),
                      ),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: OutlinedButton.icon(
                        icon: const Icon(Icons.photo_library_outlined, size: 16),
                        label: const Text('Device Gallery', style: TextStyle(fontSize: 11)),
                        onPressed: _attachedPhotos.length >= 3 ? null : () => _addEvidencePhoto(isCamera: false),
                      ),
                    ),
                  ],
                ),

                // Attached Photo Previews
                if (_attachedPhotos.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  SizedBox(
                    height: 100,
                    child: ListView.builder(
                      scrollDirection: Axis.horizontal,
                      itemCount: _attachedPhotos.length,
                      itemBuilder: (ctx, idx) {
                        final photo = _attachedPhotos[idx];
                        final kbSize = (photo.bytes.lengthInBytes / 1024).toStringAsFixed(0);
                        return Container(
                          width: 130,
                          margin: const EdgeInsets.only(right: 10),
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                            color: const Color(0xFF0F172A),
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: const Color(0xFF0284C7)),
                          ),
                          child: Stack(
                            children: [
                              Column(
                                mainAxisAlignment: MainAxisAlignment.center,
                                crossAxisAlignment: CrossAxisAlignment.center,
                                children: [
                                  const Icon(Icons.image_rounded, color: Color(0xFF38BDF8), size: 30),
                                  const SizedBox(height: 4),
                                  Text(
                                    photo.filename,
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                    style: const TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.bold),
                                  ),
                                  Text(
                                    '$kbSize KB • JPEG',
                                    style: const TextStyle(color: Colors.white60, fontSize: 9),
                                  ),
                                ],
                              ),
                              Positioned(
                                top: 0,
                                right: 0,
                                child: GestureDetector(
                                  onTap: () => _removePhoto(idx),
                                  child: Container(
                                    padding: const EdgeInsets.all(2),
                                    decoration: const BoxDecoration(
                                      color: Color(0xFFDC2626),
                                      shape: BoxShape.circle,
                                    ),
                                    child: const Icon(Icons.close, size: 12, color: Colors.white),
                                  ),
                                ),
                              ),
                            ],
                          ),
                        );
                      },
                    ),
                  ),
                ],

                const SizedBox(height: 36),

                // SUBMIT BUTTON
                SizedBox(
                  width: double.infinity,
                  height: 48,
                  child: ElevatedButton(
                    key: const Key('submit_report_button'),
                    onPressed: _isSubmitting ? null : _submitReport,
                    child: _isSubmitting
                        ? Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              const SizedBox(
                                width: 18,
                                height: 18,
                                child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                              ),
                              const SizedBox(width: 14),
                              Text(
                                _submissionStatusMessage ?? 'Submitting report...',
                                style: const TextStyle(fontSize: 12),
                              ),
                            ],
                          )
                        : const Text(
                            'SUBMIT DRAINAGE REPORT',
                            style: TextStyle(fontWeight: FontWeight.bold, letterSpacing: 0.8),
                          ),
                  ),
                ),
                const SizedBox(height: 20),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
