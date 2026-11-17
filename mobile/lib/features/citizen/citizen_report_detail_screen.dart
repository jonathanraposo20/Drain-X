import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:intl/intl.dart';
import '../../core/config/api_config.dart';
import '../../core/network/api_client.dart';
import '../../models/incident.dart';
import '../../widgets/severity_badge.dart';
import '../../widgets/status_badge.dart';

class CitizenReportDetailScreen extends StatefulWidget {
  final String incidentId;
  final ApiClient? apiClient;

  const CitizenReportDetailScreen({
    super.key,
    required this.incidentId,
    this.apiClient,
  });

  @override
  State<CitizenReportDetailScreen> createState() => _CitizenReportDetailScreenState();
}

class _CitizenReportDetailScreenState extends State<CitizenReportDetailScreen> {
  late final ApiClient _apiClient;
  Incident? _incident;
  bool _isLoading = true;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _apiClient = widget.apiClient ?? ApiClient();
    _fetchDetails();
  }

  Future<void> _fetchDetails() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final incident = await _apiClient.getIncident(widget.incidentId);
      setState(() {
        _incident = incident;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
        _isLoading = false;
      });
    }
  }

  void _copyCoordinatesToClipboard() {
    if (_incident == null) return;
    final coordStr = '${_incident!.latitude}, ${_incident!.longitude}';
    Clipboard.setData(ClipboardData(text: coordStr));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Coordinates "$coordStr" copied to clipboard.'),
        duration: const Duration(seconds: 2),
      ),
    );
  }

  void _showPhotoDialog(String photoPath, int index) {
    final photoUrl = ApiConfig.resolvePhotoUrl(photoPath);
    showDialog(
      context: context,
      builder: (ctx) => Dialog(
        backgroundColor: const Color(0xFF0F172A),
        insetPadding: const EdgeInsets.all(16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            AppBar(
              backgroundColor: Colors.transparent,
              elevation: 0,
              title: Text('Evidence Photo #${index + 1}', style: const TextStyle(fontSize: 14)),
              actions: [
                IconButton(
                  icon: const Icon(Icons.close),
                  onPressed: () => Navigator.pop(ctx),
                ),
              ],
            ),
            Container(
              constraints: const BoxConstraints(maxHeight: 380),
              color: Colors.black,
              child: Image.network(
                photoUrl,
                fit: BoxFit.contain,
                errorBuilder: (context, error, stackTrace) => const Center(
                  child: Padding(
                    padding: EdgeInsets.all(32),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.broken_image, size: 48, color: Colors.white54),
                        SizedBox(height: 8),
                        Text('Image preview unavailable or network offline.', style: TextStyle(color: Colors.white70, fontSize: 11)),
                      ],
                    ),
                  ),
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(12),
              child: Text(
                'Source: $photoPath',
                style: const TextStyle(color: Colors.white54, fontSize: 10, fontFamily: 'monospace'),
                textAlign: TextAlign.center,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildLifecycleProgress(String currentStatus) {
    if (currentStatus == 'REJECTED') {
      return Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: const Color(0xFFFEF2F2),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: const Color(0xFFFECACA)),
        ),
        child: const Row(
          children: [
            Icon(Icons.cancel_outlined, color: Color(0xFFDC2626), size: 24),
            SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('STATUS: REJECTED BY SUPERVISOR', style: TextStyle(fontWeight: FontWeight.bold, fontSize: 12, color: Color(0xFF991B1B))),
                  SizedBox(height: 2),
                  Text('This report was reviewed by municipal triage and determined to be out of scope or invalid.', style: TextStyle(fontSize: 11, color: Color(0xFF7F1D1D))),
                ],
              ),
            ),
          ],
        ),
      );
    }

    final stages = ['REPORTED', 'VERIFIED', 'ASSIGNED', 'INVESTIGATING', 'RESOLVED'];
    final currentIndex = stages.indexOf(currentStatus);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 16),
      decoration: BoxDecoration(
        color: const Color(0xFFF8FAFC),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: const Color(0xFFE2E8F0)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text(
                'MUNICIPAL WORKFLOW LIFECYCLE',
                style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF64748B), letterSpacing: 0.5),
              ),
              Text(
                'Stage: $currentStatus',
                style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: Color(0xFF0284C7)),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Row(
            children: List.generate(stages.length * 2 - 1, (index) {
              if (index.isOdd) {
                final stageBeforeIndex = index ~/ 2;
                final isPassed = currentIndex > stageBeforeIndex;
                return Expanded(
                  child: Container(
                    height: 2,
                    color: isPassed ? const Color(0xFF16A34A) : const Color(0xFFCBD5E1),
                  ),
                );
              }

              final stageIndex = index ~/ 2;
              final isCompleted = currentIndex >= stageIndex;
              final isCurrent = currentIndex == stageIndex;

              return Column(
                children: [
                  Container(
                    width: 24,
                    height: 24,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: isCurrent
                          ? const Color(0xFF0284C7)
                          : isCompleted
                              ? const Color(0xFF16A34A)
                              : const Color(0xFFE2E8F0),
                      border: Border.all(
                        color: isCurrent ? const Color(0xFF38BDF8) : Colors.transparent,
                        width: 2,
                      ),
                    ),
                    child: Center(
                      child: isCompleted
                          ? const Icon(Icons.check, size: 13, color: Colors.white)
                          : Text(
                              '${stageIndex + 1}',
                              style: const TextStyle(fontSize: 10, color: Color(0xFF64748B), fontWeight: FontWeight.bold),
                            ),
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    stages[stageIndex].substring(0, 3),
                    style: TextStyle(
                      fontSize: 9,
                      fontWeight: isCurrent ? FontWeight.bold : FontWeight.normal,
                      color: isCurrent ? const Color(0xFF0284C7) : const Color(0xFF64748B),
                    ),
                  ),
                ],
              );
            }),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final dateFormat = DateFormat('yyyy-MM-dd HH:mm');

    return Scaffold(
      appBar: AppBar(
        title: Text(_incident != null ? 'Ticket: ${_incident!.id}' : 'Incident Details'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh Status',
            onPressed: _fetchDetails,
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : _errorMessage != null
              ? Center(
                  child: Padding(
                    padding: const EdgeInsets.all(24),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(Icons.error_outline, color: Color(0xFFDC2626), size: 40),
                        const SizedBox(height: 12),
                        Text(_errorMessage!, textAlign: TextAlign.center, style: const TextStyle(color: Color(0xFF991B1B), fontSize: 13)),
                        const SizedBox(height: 16),
                        ElevatedButton.icon(
                          icon: const Icon(Icons.refresh, size: 16),
                          label: const Text('Retry'),
                          onPressed: _fetchDetails,
                        ),
                      ],
                    ),
                  ),
                )
              : _incident == null
                  ? const Center(child: Text('Incident not found'))
                  : RefreshIndicator(
                      onRefresh: _fetchDetails,
                      child: SingleChildScrollView(
                        physics: const AlwaysScrollableScrollPhysics(),
                        padding: const EdgeInsets.all(16),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            // Status & Severity Header Card
                            Container(
                              padding: const EdgeInsets.all(16),
                              decoration: BoxDecoration(
                                color: Colors.white,
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(color: const Color(0xFFE2E8F0)),
                                boxShadow: [
                                  BoxShadow(
                                    color: Colors.black.withValues(alpha: 0.04),
                                    blurRadius: 6,
                                    offset: const Offset(0, 2),
                                  ),
                                ],
                              ),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Row(
                                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                    children: [
                                      Text(
                                        _incident!.id,
                                        style: const TextStyle(
                                          fontFamily: 'monospace',
                                          fontSize: 16,
                                          fontWeight: FontWeight.bold,
                                          color: Color(0xFF0284C7),
                                        ),
                                      ),
                                      Row(
                                        children: [
                                          SeverityBadge(severity: _incident!.severity),
                                          const SizedBox(width: 6),
                                          StatusBadge(status: _incident!.status),
                                        ],
                                      ),
                                    ],
                                  ),
                                  const SizedBox(height: 12),
                                  Text(
                                    IncidentConstants.formatCategory(_incident!.category),
                                    style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Color(0xFF0F172A)),
                                  ),
                                  const SizedBox(height: 6),
                                  Row(
                                    children: [
                                      Container(
                                        padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                                        decoration: BoxDecoration(
                                          color: const Color(0xFFDCFCE7),
                                          borderRadius: BorderRadius.circular(4),
                                          border: Border.all(color: const Color(0xFF86EFAC)),
                                        ),
                                        child: Text(
                                          _incident!.source,
                                          style: const TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Color(0xFF166534)),
                                        ),
                                      ),
                                      const SizedBox(width: 8),
                                      Text(
                                        'Reported by ${_incident!.reporterName ?? 'Citizen Anonymous'} • ${dateFormat.format(_incident!.createdAt.toLocal())}',
                                        style: const TextStyle(fontSize: 11, color: Color(0xFF64748B)),
                                      ),
                                    ],
                                  ),
                                ],
                              ),
                            ),

                            const SizedBox(height: 16),

                            // Lifecycle Progress Tracker
                            _buildLifecycleProgress(_incident!.status),

                            const SizedBox(height: 16),

                            // Observations & Location Card
                            Container(
                              width: double.infinity,
                              padding: const EdgeInsets.all(16),
                              decoration: BoxDecoration(
                                color: Colors.white,
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(color: const Color(0xFFE2E8F0)),
                              ),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  const Text(
                                    'CITIZEN OBSERVATIONS',
                                    style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF64748B)),
                                  ),
                                  const SizedBox(height: 8),
                                  Text(
                                    _incident!.description,
                                    style: const TextStyle(fontSize: 13, color: Color(0xFF1E293B), height: 1.4),
                                  ),
                                  const Divider(height: 24, color: Color(0xFFE2E8F0)),
                                  Row(
                                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                    children: [
                                      Expanded(
                                        child: Row(
                                          children: [
                                            const Icon(Icons.place, size: 16, color: Color(0xFF0891B2)),
                                            const SizedBox(width: 6),
                                            Expanded(
                                              child: Text(
                                                '${_incident!.latitude.toStringAsFixed(4)}° N, ${_incident!.longitude.toStringAsFixed(4)}° E',
                                                style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: Color(0xFF334155), fontWeight: FontWeight.w600),
                                              ),
                                            ),
                                          ],
                                        ),
                                      ),
                                      TextButton.icon(
                                        icon: const Icon(Icons.copy_rounded, size: 14),
                                        label: const Text('Copy Coords', style: TextStyle(fontSize: 11)),
                                        onPressed: _copyCoordinatesToClipboard,
                                      ),
                                    ],
                                  ),
                                ],
                              ),
                            ),

                            const SizedBox(height: 16),

                            // Photographic Evidence Gallery
                            Container(
                              width: double.infinity,
                              padding: const EdgeInsets.all(16),
                              decoration: BoxDecoration(
                                color: Colors.white,
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(color: const Color(0xFFE2E8F0)),
                              ),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Row(
                                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                    children: [
                                      const Text(
                                        'PHOTOGRAPHIC EVIDENCE',
                                        style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF64748B)),
                                      ),
                                      Text(
                                        '${_incident!.photos.length} image(s)',
                                        style: const TextStyle(fontSize: 11, color: Color(0xFF64748B), fontWeight: FontWeight.w600),
                                      ),
                                    ],
                                  ),
                                  const SizedBox(height: 12),
                                  if (_incident!.photos.isEmpty)
                                    const Text(
                                      'No photographic evidence attached to this report.',
                                      style: TextStyle(fontSize: 12, color: Color(0xFF94A3B8), fontStyle: FontStyle.italic),
                                    )
                                  else
                                    SizedBox(
                                      height: 120,
                                      child: ListView.builder(
                                        scrollDirection: Axis.horizontal,
                                        itemCount: _incident!.photos.length,
                                        itemBuilder: (ctx, idx) {
                                          final photoPath = _incident!.photos[idx];
                                          final photoUrl = ApiConfig.resolvePhotoUrl(photoPath);
                                          return InkWell(
                                            onTap: () => _showPhotoDialog(photoPath, idx),
                                            borderRadius: BorderRadius.circular(8),
                                            child: Container(
                                              width: 140,
                                              margin: const EdgeInsets.only(right: 12),
                                              decoration: BoxDecoration(
                                                color: const Color(0xFF0F172A),
                                                borderRadius: BorderRadius.circular(8),
                                                border: Border.all(color: const Color(0xFF0284C7)),
                                              ),
                                              clipBehavior: Clip.antiAlias,
                                              child: Stack(
                                                fit: StackFit.expand,
                                                children: [
                                                  Image.network(
                                                    photoUrl,
                                                    fit: BoxFit.cover,
                                                    errorBuilder: (context, error, stackTrace) {
                                                      return const Center(
                                                        child: Column(
                                                          mainAxisAlignment: MainAxisAlignment.center,
                                                          children: [
                                                            Icon(Icons.broken_image_rounded, color: Colors.white54, size: 28),
                                                            SizedBox(height: 4),
                                                            Text('Photo Offline', style: TextStyle(fontSize: 9, color: Colors.white70)),
                                                          ],
                                                        ),
                                                      );
                                                    },
                                                  ),
                                                  Positioned(
                                                    bottom: 4,
                                                    right: 4,
                                                    child: Container(
                                                      padding: const EdgeInsets.all(3),
                                                      decoration: BoxDecoration(
                                                        color: Colors.black.withValues(alpha: 0.6),
                                                        borderRadius: BorderRadius.circular(4),
                                                      ),
                                                      child: const Icon(Icons.zoom_in, color: Colors.white, size: 14),
                                                    ),
                                                  ),
                                                ],
                                              ),
                                            ),
                                          );
                                        },
                                      ),
                                    ),
                                ],
                              ),
                            ),

                            const SizedBox(height: 16),

                            // Municipal Response & Dispatch Notes
                            Container(
                              width: double.infinity,
                              padding: const EdgeInsets.all(16),
                              decoration: BoxDecoration(
                                color: Colors.white,
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(color: const Color(0xFFE2E8F0)),
                              ),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  const Text(
                                    'MUNICIPAL FIELD RESPONSE',
                                    style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF64748B)),
                                  ),
                                  const SizedBox(height: 12),
                                  Row(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      const Icon(Icons.groups_outlined, size: 18, color: Color(0xFF4F46E5)),
                                      const SizedBox(width: 8),
                                      Expanded(
                                        child: Column(
                                          crossAxisAlignment: CrossAxisAlignment.start,
                                          children: [
                                            const Text('Assigned Response Crew:', style: TextStyle(fontSize: 11, color: Color(0xFF64748B))),
                                            Text(
                                              _incident!.assignedTo ?? 'Awaiting municipal crew assignment',
                                              style: TextStyle(
                                                fontSize: 13,
                                                fontWeight: FontWeight.bold,
                                                color: _incident!.assignedTo != null ? const Color(0xFF4F46E5) : const Color(0xFF94A3B8),
                                              ),
                                            ),
                                          ],
                                        ),
                                      ),
                                    ],
                                  ),
                                  const SizedBox(height: 12),
                                  Row(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      const Icon(Icons.note_alt_outlined, size: 18, color: Color(0xFF059669)),
                                      const SizedBox(width: 8),
                                      Expanded(
                                        child: Column(
                                          crossAxisAlignment: CrossAxisAlignment.start,
                                          children: [
                                            const Text('Municipal Dispatch Notes:', style: TextStyle(fontSize: 11, color: Color(0xFF64748B))),
                                            Text(
                                              (_incident!.municipalNotes?.trim().isNotEmpty ?? false)
                                                  ? _incident!.municipalNotes!
                                                  : 'No municipal notes logged yet.',
                                              style: const TextStyle(fontSize: 12, color: Color(0xFF1E293B)),
                                            ),
                                          ],
                                        ),
                                      ),
                                    ],
                                  ),
                                ],
                              ),
                            ),

                            const SizedBox(height: 32),
                          ],
                        ),
                      ),
                    ),
    );
  }
}
