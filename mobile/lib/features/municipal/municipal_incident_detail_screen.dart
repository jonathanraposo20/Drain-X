import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../../core/config/api_config.dart';
import '../../core/network/api_client.dart';
import '../../models/incident.dart';
import '../../widgets/severity_badge.dart';
import '../../widgets/status_badge.dart';

class MunicipalIncidentDetailScreen extends StatefulWidget {
  final String incidentId;
  final String officerName;

  const MunicipalIncidentDetailScreen({
    super.key,
    required this.incidentId,
    required this.officerName,
  });

  @override
  State<MunicipalIncidentDetailScreen> createState() => _MunicipalIncidentDetailScreenState();
}

class _MunicipalIncidentDetailScreenState extends State<MunicipalIncidentDetailScreen> {
  final ApiClient _apiClient = ApiClient();
  Incident? _incident;
  bool _isLoading = true;
  String? _errorMessage;

  String? _selectedNextStatus;
  String? _selectedAssignedTeam;
  final TextEditingController _notesController = TextEditingController();
  bool _isSaving = false;

  List<FieldTeam> _fieldTeams = [];
  List<IncidentAudit> _audits = [];
  bool _isLoadingAudits = false;

  @override
  void initState() {
    super.initState();
    _fetchDetails();
  }

  Future<void> _fetchDetails() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final incident = await _apiClient.getIncident(widget.incidentId);
      List<FieldTeam> teams = [];
      try {
        teams = await _apiClient.getFieldTeams();
      } catch (_) {
        teams = IncidentConstants.fieldTeams.map((name) => FieldTeam(
          teamId: name.split(' ')[1],
          name: name,
          zone: 'Panaji',
        )).toList();
      }

      List<IncidentAudit> audits = [];
      try {
        audits = await _apiClient.getIncidentAudits(widget.incidentId);
      } catch (_) {
        audits = [];
      }

      setState(() {
        _incident = incident;
        _fieldTeams = teams;
        _audits = audits;
        _selectedNextStatus = incident.status;
        _selectedAssignedTeam = incident.assignedTo;
        _notesController.text = incident.municipalNotes ?? '';
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _errorMessage = e.toString();
        _isLoading = false;
      });
    }
  }

  Future<void> _loadAudits() async {
    setState(() => _isLoadingAudits = true);
    try {
      final audits = await _apiClient.getIncidentAudits(widget.incidentId);
      setState(() {
        _audits = audits;
        _isLoadingAudits = false;
      });
    } catch (_) {
      setState(() => _isLoadingAudits = false);
    }
  }

  Future<void> _verifyIncident() async {
    if (_incident == null) return;
    setState(() => _isSaving = true);
    try {
      final updated = await _apiClient.verifyIncident(
        _incident!.id,
        notes: _notesController.text.trim().isNotEmpty ? _notesController.text.trim() : null,
      );
      setState(() {
        _incident = updated;
        _selectedNextStatus = updated.status;
        _isSaving = false;
      });
      _loadAudits();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          backgroundColor: Color(0xFF7E22CE),
          content: Text('Incident verified successfully.'),
        ),
      );
    } catch (e) {
      setState(() => _isSaving = false);
      _showErrorDialog('Verification Failed', e.toString());
    }
  }

  Future<void> _assignCrew(String teamName) async {
    if (_incident == null) return;
    setState(() => _isSaving = true);
    try {
      final updated = await _apiClient.assignIncident(
        _incident!.id,
        assignedTo: teamName,
        reason: 'Municipal crew assignment',
      );
      setState(() {
        _incident = updated;
        _selectedAssignedTeam = updated.assignedTo;
        _selectedNextStatus = updated.status;
        _isSaving = false;
      });
      _loadAudits();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          backgroundColor: const Color(0xFF16A34A),
          content: Text('Assigned to $teamName successfully.'),
        ),
      );
    } catch (e) {
      setState(() => _isSaving = false);
      _showErrorDialog('Assignment Failed', e.toString());
    }
  }

  Future<void> _promptReassign(String newTeamName) async {
    final reasonController = TextEditingController();
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Reassign Field Crew', style: TextStyle(fontSize: 15, fontWeight: FontWeight.bold)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Reassigning ticket to: $newTeamName', style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600)),
            const SizedBox(height: 12),
            const Text('Mandatory Operational Reason:', style: TextStyle(fontSize: 11, color: Color(0xFF475569))),
            const SizedBox(height: 4),
            TextField(
              controller: reasonController,
              decoration: const InputDecoration(
                hintText: 'e.g. Traffic delay, closer proximity...',
                border: OutlineInputBorder(),
              ),
              style: const TextStyle(fontSize: 12),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Reassign'),
          ),
        ],
      ),
    );

    if (confirmed == true && reasonController.text.trim().isNotEmpty) {
      setState(() => _isSaving = true);
      try {
        final updated = await _apiClient.reassignIncident(
          _incident!.id,
          assignedTo: newTeamName,
          reason: reasonController.text.trim(),
        );
        setState(() {
          _incident = updated;
          _selectedAssignedTeam = updated.assignedTo;
          _isSaving = false;
        });
        _loadAudits();
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(backgroundColor: const Color(0xFF16A34A), content: Text('Reassigned to $newTeamName.')),
        );
      } catch (e) {
        setState(() => _isSaving = false);
        _showErrorDialog('Reassignment Failed', e.toString());
      }
    }
  }

  Future<void> _promptUnassign() async {
    final reasonController = TextEditingController();
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Remove Crew Assignment', style: TextStyle(fontSize: 15, fontWeight: FontWeight.bold)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('This will remove the current crew and revert the status to VERIFIED.', style: TextStyle(fontSize: 12)),
            const SizedBox(height: 12),
            const Text('Mandatory Operational Reason:', style: TextStyle(fontSize: 11, color: Color(0xFF475569))),
            const SizedBox(height: 4),
            TextField(
              controller: reasonController,
              decoration: const InputDecoration(
                hintText: 'e.g. Crew called off, emergency elsewhere...',
                border: OutlineInputBorder(),
              ),
              style: const TextStyle(fontSize: 12),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: Colors.amber[800]),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Unassign'),
          ),
        ],
      ),
    );

    if (confirmed == true && reasonController.text.trim().isNotEmpty) {
      setState(() => _isSaving = true);
      try {
        final updated = await _apiClient.unassignIncident(
          _incident!.id,
          reason: reasonController.text.trim(),
        );
        setState(() {
          _incident = updated;
          _selectedAssignedTeam = null;
          _selectedNextStatus = updated.status;
          _isSaving = false;
        });
        _loadAudits();
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(backgroundColor: Color(0xFFD97706), content: Text('Crew assignment removed.')),
        );
      } catch (e) {
        setState(() => _isSaving = false);
        _showErrorDialog('Unassignment Failed', e.toString());
      }
    }
  }

  Future<void> _promptReject() async {
    final reasonController = TextEditingController();
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Reject Incident Report', style: TextStyle(fontSize: 15, fontWeight: FontWeight.bold, color: Colors.red)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Rejection marks this ticket invalid or out-of-scope and is finalized.', style: TextStyle(fontSize: 12)),
            const SizedBox(height: 12),
            const Text('Mandatory Rejection Reason:', style: TextStyle(fontSize: 11, color: Color(0xFF475569))),
            const SizedBox(height: 4),
            TextField(
              controller: reasonController,
              decoration: const InputDecoration(
                hintText: 'e.g. Duplicate report, false alarm, private drain...',
                border: OutlineInputBorder(),
              ),
              style: const TextStyle(fontSize: 12),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red[700]),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Confirm Rejection'),
          ),
        ],
      ),
    );

    if (confirmed == true && reasonController.text.trim().isNotEmpty) {
      setState(() => _isSaving = true);
      try {
        final updated = await _apiClient.rejectIncident(
          _incident!.id,
          reason: reasonController.text.trim(),
        );
        setState(() {
          _incident = updated;
          _selectedNextStatus = updated.status;
          _isSaving = false;
        });
        _loadAudits();
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(backgroundColor: Color(0xFFDC2626), content: Text('Incident rejected.')),
        );
      } catch (e) {
        setState(() => _isSaving = false);
        _showErrorDialog('Rejection Failed', e.toString());
      }
    }
  }

  void _showErrorDialog(String title, String message) {
    if (!mounted) return;
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title, style: const TextStyle(color: Colors.red, fontSize: 14)),
        content: Text(message, style: const TextStyle(fontSize: 12)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('OK')),
        ],
      ),
    );
  }

  Future<void> _saveWorkflowUpdates() async {
    if (_incident == null) return;

    setState(() {
      _isSaving = true;
    });

    try {
      final updatedIncident = await _apiClient.updateIncident(
        _incident!.id,
        status: _selectedNextStatus != _incident!.status ? _selectedNextStatus : null,
        assignedTo: _selectedAssignedTeam,
        municipalNotes: _notesController.text.trim(),
      );

      setState(() {
        _incident = updatedIncident;
        _selectedNextStatus = updatedIncident.status;
        _selectedAssignedTeam = updatedIncident.assignedTo;
        _notesController.text = updatedIncident.municipalNotes ?? '';
        _isSaving = false;
      });

      _loadAudits();

      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          backgroundColor: Color(0xFF16A34A),
          content: Text('Ticket workflow updates saved successfully.'),
        ),
      );
    } catch (e) {
      setState(() {
        _isSaving = false;
      });
      _showErrorDialog('Workflow Update Failed', e.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    final dateFormat = DateFormat('yyyy-MM-dd HH:mm');

    return Scaffold(
      appBar: AppBar(
        title: Text(_incident != null ? 'Ticket: ${_incident!.id}' : 'Incident Triage'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _fetchDetails,
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : _errorMessage != null
              ? Center(child: Text(_errorMessage!, style: const TextStyle(color: Colors.red)))
              : _incident == null
                  ? const Center(child: Text('Incident not found'))
                  : SingleChildScrollView(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          // Header Card
                          Container(
                            padding: const EdgeInsets.all(16),
                            decoration: BoxDecoration(
                              color: Colors.white,
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(color: const Color(0xFFE2E8F0)),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                if (_incident!.isDemo) ...[
                                  Container(
                                    margin: const EdgeInsets.only(bottom: 12),
                                    padding: const EdgeInsets.all(10),
                                    decoration: BoxDecoration(
                                      color: const Color(0xFFF3E8FF),
                                      borderRadius: BorderRadius.circular(8),
                                      border: Border.all(color: const Color(0xFFC084FC)),
                                    ),
                                    child: const Row(
                                      children: [
                                        Icon(Icons.warning_amber_rounded, size: 18, color: Color(0xFF7E22CE)),
                                        SizedBox(width: 8),
                                        Expanded(
                                          child: Text(
                                            'SIMULATED DEMO INCIDENT: Pre-seeded demonstration record. Coordinates and reports do not represent a genuine physical event.',
                                            style: TextStyle(fontSize: 11, color: Color(0xFF6B21A8), fontWeight: FontWeight.w600),
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                ],
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
                                const SizedBox(height: 10),
                                Text(
                                  IncidentConstants.formatCategory(_incident!.category),
                                  style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Color(0xFF0F172A)),
                                ),
                                const SizedBox(height: 6),
                                Text(
                                  'Reported by ${_incident!.reporterName ?? 'Citizen Anonymous'} (${_incident!.source}) • ${dateFormat.format(_incident!.createdAt.toLocal())}',
                                  style: const TextStyle(fontSize: 11, color: Color(0xFF64748B)),
                                ),
                              ],
                            ),
                          ),

                          const SizedBox(height: 16),

                          // Incident Details Card
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
                                  'HAZARD REPORT DETAILS',
                                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF64748B)),
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  _incident!.description,
                                  style: const TextStyle(fontSize: 13, color: Color(0xFF1E293B), height: 1.4),
                                ),
                                const SizedBox(height: 12),
                                Row(
                                  children: [
                                    const Icon(Icons.place, size: 16, color: Color(0xFF0891B2)),
                                    const SizedBox(width: 4),
                                    Text(
                                      'Location: ${_incident!.formattedLocation}',
                                      style: TextStyle(
                                        fontFamily: 'monospace',
                                        fontSize: 12,
                                        fontStyle: !_incident!.hasValidCoordinates ? FontStyle.italic : FontStyle.normal,
                                        color: _incident!.isDemo ? const Color(0xFF7E22CE) : const Color(0xFF475569),
                                      ),
                                    ),
                                  ],
                                ),
                              ],
                            ),
                          ),

                          const SizedBox(height: 16),

                          // Photographic Evidence Viewer Card
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
                                      '${_incident!.photos.length} attached',
                                      style: const TextStyle(fontSize: 11, color: Color(0xFF64748B)),
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 12),
                                if (_incident!.photos.isEmpty)
                                  const Text(
                                    'No photographic evidence attached to this incident.',
                                    style: TextStyle(fontSize: 12, color: Color(0xFF94A3B8), fontStyle: FontStyle.italic),
                                  )
                                else
                                  SizedBox(
                                    height: 120,
                                    child: ListView.builder(
                                      scrollDirection: Axis.horizontal,
                                      itemCount: _incident!.photos.length,
                                      itemBuilder: (ctx, idx) {
                                        final photoUrl = ApiConfig.resolvePhotoUrl(_incident!.photos[idx]);
                                        return Container(
                                          width: 140,
                                          margin: const EdgeInsets.only(right: 12),
                                          decoration: BoxDecoration(
                                            color: const Color(0xFF0F172A),
                                            borderRadius: BorderRadius.circular(8),
                                            border: Border.all(color: const Color(0xFF06B6D4)),
                                          ),
                                          clipBehavior: Clip.antiAlias,
                                          child: Image.network(
                                            photoUrl,
                                            fit: BoxFit.cover,
                                            errorBuilder: (context, error, stackTrace) {
                                              return Center(
                                                child: Column(
                                                  mainAxisAlignment: MainAxisAlignment.center,
                                                  children: [
                                                    const Icon(Icons.broken_image, color: Colors.white60, size: 28),
                                                    const SizedBox(height: 4),
                                                    Text(
                                                      'Evidence ${idx + 1}',
                                                      style: const TextStyle(fontSize: 10, color: Colors.white70),
                                                    ),
                                                  ],
                                                ),
                                              );
                                            },
                                          ),
                                        );
                                      },
                                    ),
                                  ),
                              ],
                            ),
                          ),

                          const SizedBox(height: 16),

                          // Terminal Status Warning Banner if RESOLVED or REJECTED
                          if (_incident!.status == 'RESOLVED' || _incident!.status == 'REJECTED') ...[
                            Container(
                              width: double.infinity,
                              padding: const EdgeInsets.all(16),
                              decoration: BoxDecoration(
                                color: _incident!.status == 'RESOLVED' ? const Color(0xFFF0FDF4) : const Color(0xFFFEF2F2),
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(
                                  color: _incident!.status == 'RESOLVED' ? const Color(0xFF86EFAC) : const Color(0xFFFCA5A5),
                                ),
                              ),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Row(
                                    children: [
                                      Icon(
                                        _incident!.status == 'RESOLVED' ? Icons.check_circle_outline : Icons.cancel_outlined,
                                        color: _incident!.status == 'RESOLVED' ? const Color(0xFF16A34A) : const Color(0xFFDC2626),
                                        size: 20,
                                      ),
                                      const SizedBox(width: 8),
                                      Text(
                                        'TERMINAL STATE: ${_incident!.status}',
                                        style: TextStyle(
                                          fontWeight: FontWeight.bold,
                                          fontSize: 13,
                                          color: _incident!.status == 'RESOLVED' ? const Color(0xFF15803D) : const Color(0xFFB91C1C),
                                        ),
                                      ),
                                    ],
                                  ),
                                  const SizedBox(height: 6),
                                  Text(
                                    _incident!.status == 'RESOLVED'
                                        ? 'This incident has been fully resolved and closed. Further triage transitions and field assignments are locked.'
                                        : 'This incident was rejected. Rejection Reason: ${_incident!.rejectionReason ?? "No reason recorded."}',
                                    style: TextStyle(
                                      fontSize: 12,
                                      color: _incident!.status == 'RESOLVED' ? const Color(0xFF166534) : const Color(0xFF991B1B),
                                    ),
                                  ),
                                ],
                              ),
                            ),
                            const SizedBox(height: 16),
                          ],

                          // Municipal Actions Card (Dispatch & Lifecycle)
                          Container(
                            width: double.infinity,
                            padding: const EdgeInsets.all(16),
                            decoration: BoxDecoration(
                              color: Colors.white,
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(color: const Color(0xFF6366F1), width: 1.2),
                              boxShadow: [
                                BoxShadow(
                                  color: const Color(0xFF6366F1).withValues(alpha: 0.06),
                                  blurRadius: 8,
                                  offset: const Offset(0, 3),
                                ),
                              ],
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Row(
                                  children: [
                                    Icon(Icons.engineering_outlined, size: 18, color: Color(0xFF4F46E5)),
                                    SizedBox(width: 8),
                                    Text(
                                      'MUNICIPAL TRIAGE & ACTIONS',
                                      style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Color(0xFF1E1B4B)),
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 14),

                                // Section 1: Verification & Triage
                                if (_incident!.status == 'REPORTED') ...[
                                  Container(
                                    width: double.infinity,
                                    padding: const EdgeInsets.all(12),
                                    decoration: BoxDecoration(
                                      color: const Color(0xFFFAF5FF),
                                      borderRadius: BorderRadius.circular(8),
                                      border: Border.all(color: const Color(0xFFE9D5FF)),
                                    ),
                                    child: Column(
                                      crossAxisAlignment: CrossAxisAlignment.start,
                                      children: [
                                        const Text(
                                          'INCIDENT VERIFICATION',
                                          style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF6B21A8)),
                                        ),
                                        const SizedBox(height: 4),
                                        const Text(
                                          'Confirm this citizen report represents a valid municipal drainage hazard before assigning field crews.',
                                          style: TextStyle(fontSize: 11, color: Color(0xFF4B5563)),
                                        ),
                                        const SizedBox(height: 10),
                                        SizedBox(
                                          width: double.infinity,
                                          child: ElevatedButton.icon(
                                            style: ElevatedButton.styleFrom(
                                              backgroundColor: const Color(0xFF7E22CE),
                                            ),
                                            onPressed: _isSaving ? null : _verifyIncident,
                                            icon: const Icon(Icons.verified_outlined, size: 16),
                                            label: const Text('VERIFY INCIDENT TICKET'),
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                  const SizedBox(height: 16),
                                ] else if (_incident!.verifiedAt != null) ...[
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                                    decoration: BoxDecoration(
                                      color: const Color(0xFFF3E8FF),
                                      borderRadius: BorderRadius.circular(6),
                                      border: Border.all(color: const Color(0xFFD8B4FE)),
                                    ),
                                    child: Row(
                                      children: [
                                        const Icon(Icons.verified, size: 16, color: Color(0xFF7E22CE)),
                                        const SizedBox(width: 6),
                                        Text(
                                          'Verified at ${dateFormat.format(_incident!.verifiedAt!.toLocal())}',
                                          style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600, color: Color(0xFF6B21A8)),
                                        ),
                                      ],
                                    ),
                                  ),
                                  const SizedBox(height: 16),
                                ],

                                // Section 2: Field Crew Assignment
                                const Text(
                                  'FIELD CREW ASSIGNMENT',
                                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF475569)),
                                ),
                                const SizedBox(height: 6),

                                Container(
                                  padding: const EdgeInsets.all(8),
                                  margin: const EdgeInsets.only(bottom: 10),
                                  decoration: BoxDecoration(
                                    color: const Color(0xFFF3E8FF),
                                    borderRadius: BorderRadius.circular(6),
                                    border: Border.all(color: const Color(0xFFD8B4FE)),
                                  ),
                                  child: const Row(
                                    children: [
                                      Icon(Icons.info_outline, size: 14, color: Color(0xFF7E22CE)),
                                      SizedBox(width: 6),
                                      Expanded(
                                        child: Text(
                                          'Notice: Registered field response crews are demonstration units for operational modeling.',
                                          style: TextStyle(fontSize: 10, color: Color(0xFF6B21A8), fontWeight: FontWeight.w500),
                                        ),
                                      ),
                                    ],
                                  ),
                                ),

                                if (_incident!.assignedTo != null && _incident!.assignedTo!.isNotEmpty) ...[
                                  Container(
                                    padding: const EdgeInsets.all(12),
                                    decoration: BoxDecoration(
                                      color: const Color(0xFFF0FDF4),
                                      borderRadius: BorderRadius.circular(8),
                                      border: Border.all(color: const Color(0xFFBBF7D0)),
                                    ),
                                    child: Column(
                                      crossAxisAlignment: CrossAxisAlignment.start,
                                      children: [
                                        Row(
                                          children: [
                                            const Icon(Icons.groups_outlined, size: 18, color: Color(0xFF16A34A)),
                                            const SizedBox(width: 8),
                                            Expanded(
                                              child: Text(
                                                'Assigned Crew: ${_incident!.assignedTo}',
                                                style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13, color: Color(0xFF15803D)),
                                              ),
                                            ),
                                          ],
                                        ),
                                        if (_incident!.status != 'RESOLVED' && _incident!.status != 'REJECTED') ...[
                                          const SizedBox(height: 10),
                                          Row(
                                            children: [
                                              Expanded(
                                                child: OutlinedButton(
                                                  style: OutlinedButton.styleFrom(
                                                    foregroundColor: const Color(0xFF2563EB),
                                                    side: const BorderSide(color: Color(0xFF93C5FD)),
                                                  ),
                                                  onPressed: _isSaving
                                                      ? null
                                                      : () async {
                                                          final availableTeams = _fieldTeams.isNotEmpty
                                                              ? _fieldTeams.map((t) => t.name).toList()
                                                              : IncidentConstants.fieldTeams;
                                                          final selected = await showDialog<String>(
                                                            context: context,
                                                            builder: (ctx) => SimpleDialog(
                                                              title: const Text('Select Target Crew', style: TextStyle(fontSize: 14)),
                                                              children: availableTeams
                                                                  .where((t) => t != _incident!.assignedTo)
                                                                  .map((t) => SimpleDialogOption(
                                                                        onPressed: () => Navigator.pop(ctx, t),
                                                                        child: Text(t, style: const TextStyle(fontSize: 13)),
                                                                      ))
                                                                  .toList(),
                                                            ),
                                                          );
                                                          if (selected != null) {
                                                            _promptReassign(selected);
                                                          }
                                                        },
                                                  child: const Text('Reassign Crew', style: TextStyle(fontSize: 12)),
                                                ),
                                              ),
                                              const SizedBox(width: 8),
                                              Expanded(
                                                child: OutlinedButton(
                                                  style: OutlinedButton.styleFrom(
                                                    foregroundColor: const Color(0xFFD97706),
                                                    side: const BorderSide(color: Color(0xFFFCD34D)),
                                                  ),
                                                  onPressed: _isSaving ? null : _promptUnassign,
                                                  child: const Text('Unassign Crew', style: TextStyle(fontSize: 12)),
                                                ),
                                              ),
                                            ],
                                          ),
                                        ],
                                      ],
                                    ),
                                  ),
                                  const SizedBox(height: 16),
                                ] else if (_incident!.status != 'RESOLVED' && _incident!.status != 'REJECTED') ...[
                                  DropdownButtonFormField<String>(
                                    initialValue: _selectedAssignedTeam,
                                    decoration: const InputDecoration(
                                      hintText: 'Select authoritative field crew...',
                                    ),
                                    items: [
                                      const DropdownMenuItem<String>(
                                        value: null,
                                        child: Text('-- Select Crew --', style: TextStyle(fontSize: 13, color: Colors.grey)),
                                      ),
                                      if (_fieldTeams.isNotEmpty)
                                        ..._fieldTeams.map((t) => DropdownMenuItem(
                                              value: t.name,
                                              child: Text('${t.name} (${t.zone})', style: const TextStyle(fontSize: 12)),
                                            ))
                                      else
                                        ...IncidentConstants.fieldTeams.map((team) => DropdownMenuItem(
                                              value: team,
                                              child: Text(team, style: const TextStyle(fontSize: 12)),
                                            )),
                                    ],
                                    onChanged: (val) {
                                      setState(() => _selectedAssignedTeam = val);
                                    },
                                  ),
                                  const SizedBox(height: 8),
                                  SizedBox(
                                    width: double.infinity,
                                    child: ElevatedButton.icon(
                                      style: ElevatedButton.styleFrom(
                                        backgroundColor: const Color(0xFF16A34A),
                                      ),
                                      onPressed: (_isSaving || _selectedAssignedTeam == null || _selectedAssignedTeam!.isEmpty)
                                          ? null
                                          : () => _assignCrew(_selectedAssignedTeam!),
                                      icon: const Icon(Icons.person_add_outlined, size: 16),
                                      label: const Text('ASSIGN SELECTED CREW'),
                                    ),
                                  ),
                                  const SizedBox(height: 16),
                                ],

                                // Section 3: General State Machine & Notes (if not terminal)
                                if (_incident!.status != 'RESOLVED' && _incident!.status != 'REJECTED') ...[
                                  const Text(
                                    'LIFECYCLE STATUS TRANSITION',
                                    style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF475569)),
                                  ),
                                  const SizedBox(height: 6),
                                  DropdownButtonFormField<String>(
                                    initialValue: _selectedNextStatus,
                                    decoration: const InputDecoration(
                                      helperText: 'State machine: REPORTED ➔ VERIFIED ➔ ASSIGNED ➔ INVESTIGATING ➔ RESOLVED',
                                      helperMaxLines: 2,
                                    ),
                                    items: IncidentConstants.getAllowedNextStatuses(_incident!.status).map((st) {
                                      return DropdownMenuItem(
                                        value: st,
                                        child: Text(
                                          st == _incident!.status ? '$st (Current)' : '→ Transition to $st',
                                          style: TextStyle(
                                            fontSize: 13,
                                            fontWeight: st == _incident!.status ? FontWeight.bold : FontWeight.normal,
                                          ),
                                        ),
                                      );
                                    }).toList(),
                                    onChanged: (val) {
                                      if (val != null) setState(() => _selectedNextStatus = val);
                                    },
                                  ),
                                  const SizedBox(height: 16),

                                  // Municipal Dispatch Notes
                                  const Text(
                                    'MUNICIPAL DISPATCH & INVESTIGATION NOTES',
                                    style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF475569)),
                                  ),
                                  const SizedBox(height: 6),
                                  TextFormField(
                                    controller: _notesController,
                                    maxLines: 3,
                                    decoration: const InputDecoration(
                                      hintText: 'Log equipment dispatched, suction pump deployment, on-site findings, or resolution summary...',
                                    ),
                                    style: const TextStyle(fontSize: 12),
                                  ),

                                  const SizedBox(height: 14),

                                  // Action Buttons Row: Save & Reject
                                  Row(
                                    children: [
                                      Expanded(
                                        flex: 2,
                                        child: ElevatedButton.icon(
                                          style: ElevatedButton.styleFrom(
                                            backgroundColor: const Color(0xFF4F46E5),
                                          ),
                                          onPressed: _isSaving ? null : _saveWorkflowUpdates,
                                          icon: const Icon(Icons.save_outlined, size: 16),
                                          label: Text(_isSaving ? 'SAVING...' : 'SAVE UPDATES'),
                                        ),
                                      ),
                                      const SizedBox(width: 8),
                                      Expanded(
                                        flex: 1,
                                        child: OutlinedButton.icon(
                                          style: OutlinedButton.styleFrom(
                                            foregroundColor: const Color(0xFFDC2626),
                                            side: const BorderSide(color: Color(0xFFFCA5A5)),
                                          ),
                                          onPressed: _isSaving ? null : _promptReject,
                                          icon: const Icon(Icons.cancel_outlined, size: 16),
                                          label: const Text('REJECT'),
                                        ),
                                      ),
                                    ],
                                  ),
                                ],

                                if (_incident!.internalNotes != null && _incident!.internalNotes!.isNotEmpty) ...[
                                  const SizedBox(height: 14),
                                  Row(
                                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                    children: [
                                      const Text(
                                        'INTERNAL STAFF NOTES',
                                        style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF475569)),
                                      ),
                                      Container(
                                        padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1.5),
                                        decoration: BoxDecoration(
                                          color: const Color(0xFFFEF3C7),
                                          borderRadius: BorderRadius.circular(4),
                                          border: Border.all(color: const Color(0xFFF59E0B)),
                                        ),
                                        child: const Text(
                                          'CONFIDENTIAL STAFF ONLY',
                                          style: TextStyle(fontSize: 9, fontWeight: FontWeight.bold, color: Color(0xFFB45309)),
                                        ),
                                      ),
                                    ],
                                  ),
                                  const SizedBox(height: 6),
                                  Container(
                                    width: double.infinity,
                                    padding: const EdgeInsets.all(10),
                                    decoration: BoxDecoration(
                                      color: const Color(0xFFFFFBEB),
                                      borderRadius: BorderRadius.circular(6),
                                      border: Border.all(color: const Color(0xFFFDE68A)),
                                    ),
                                    child: Text(
                                      _incident!.internalNotes!,
                                      style: const TextStyle(fontSize: 12, color: Color(0xFF92400E)),
                                    ),
                                  ),
                                ],
                              ],
                            ),
                          ),

                          const SizedBox(height: 16),

                          // Operational Audit Timeline Card
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
                                    const Row(
                                      children: [
                                        Icon(Icons.history_edu, size: 18, color: Color(0xFF0F172A)),
                                        SizedBox(width: 8),
                                        Text(
                                          'OPERATIONAL AUDIT TRAIL',
                                          style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Color(0xFF0F172A)),
                                        ),
                                      ],
                                    ),
                                    IconButton(
                                      icon: const Icon(Icons.refresh, size: 18, color: Color(0xFF64748B)),
                                      tooltip: 'Refresh Audit Trail',
                                      onPressed: _loadAudits,
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 10),
                                if (_isLoadingAudits)
                                  const Center(
                                    child: Padding(
                                      padding: EdgeInsets.all(12),
                                      child: CircularProgressIndicator(),
                                    ),
                                  )
                                else if (_audits.isEmpty)
                                  const Padding(
                                    padding: EdgeInsets.all(8),
                                    child: Text(
                                      'No audit records found for this incident.',
                                      style: TextStyle(fontSize: 12, color: Color(0xFF94A3B8), fontStyle: FontStyle.italic),
                                    ),
                                  )
                                else
                                  ListView.separated(
                                    shrinkWrap: true,
                                    physics: const NeverScrollableScrollPhysics(),
                                    itemCount: _audits.length,
                                    separatorBuilder: (_, __) => const Divider(height: 16, color: Color(0xFFF1F5F9)),
                                    itemBuilder: (ctx, index) {
                                      final audit = _audits[index];
                                      Color badgeColor = const Color(0xFF64748B);
                                      switch (audit.action) {
                                        case 'REPORTED':
                                          badgeColor = const Color(0xFF0284C7);
                                          break;
                                        case 'VERIFIED':
                                          badgeColor = const Color(0xFF7E22CE);
                                          break;
                                        case 'ASSIGNED':
                                          badgeColor = const Color(0xFF16A34A);
                                          break;
                                        case 'REASSIGNED':
                                          badgeColor = const Color(0xFF2563EB);
                                          break;
                                        case 'UNASSIGNED':
                                          badgeColor = const Color(0xFFD97706);
                                          break;
                                        case 'REJECTED':
                                          badgeColor = const Color(0xFFDC2626);
                                          break;
                                        case 'STATUS_CHANGED':
                                          badgeColor = const Color(0xFF4F46E5);
                                          break;
                                        default:
                                          badgeColor = const Color(0xFF64748B);
                                      }

                                      return Column(
                                        crossAxisAlignment: CrossAxisAlignment.start,
                                        children: [
                                          Row(
                                            mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                            children: [
                                              Container(
                                                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                                decoration: BoxDecoration(
                                                  color: badgeColor.withValues(alpha: 0.12),
                                                  borderRadius: BorderRadius.circular(4),
                                                  border: Border.all(color: badgeColor.withValues(alpha: 0.4)),
                                                ),
                                                child: Text(
                                                  audit.action,
                                                  style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: badgeColor),
                                                ),
                                              ),
                                              Text(
                                                dateFormat.format(audit.timestamp.toLocal()),
                                                style: const TextStyle(fontSize: 10, color: Color(0xFF94A3B8)),
                                              ),
                                            ],
                                          ),
                                          const SizedBox(height: 4),
                                          Text(
                                            'Actor: ${audit.actorId} (${audit.actorRole})',
                                            style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w500, color: Color(0xFF334155)),
                                          ),
                                          if (audit.changeSummary != null) ...[
                                            const SizedBox(height: 2),
                                            Text(
                                              audit.changeSummary!,
                                              style: const TextStyle(fontSize: 11, fontFamily: 'monospace', color: Color(0xFF475569)),
                                            ),
                                          ],
                                          if (audit.reason != null && audit.reason!.isNotEmpty) ...[
                                            const SizedBox(height: 2),
                                            Text(
                                              'Reason: ${audit.reason}',
                                              style: const TextStyle(fontSize: 11, fontStyle: FontStyle.italic, color: Color(0xFF64748B)),
                                            ),
                                          ],
                                        ],
                                      );
                                    },
                                  ),
                              ],
                            ),
                          ),

                          const SizedBox(height: 24),
                        ],
                      ),
                    ),
    );
  }
}
