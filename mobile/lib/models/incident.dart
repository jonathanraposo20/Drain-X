class Incident {
  final String id;
  final String category;
  final String description;
  final double latitude;
  final double longitude;
  final String severity;
  final String status;
  final String source;
  final DateTime createdAt;
  final DateTime updatedAt;
  final String? assignedTo;
  final String assignmentType;
  final String? assignedTeamId;
  final String? assignedWorkerId;
  final String? municipalNotes;
  final String? internalNotes;
  final String? reporterName;
  final List<String> photos;
  final DateTime? verifiedAt;
  final String? verifiedBy;
  final String? rejectionReason;

  Incident({
    required this.id,
    required this.category,
    required this.description,
    required this.latitude,
    required this.longitude,
    required this.severity,
    required this.status,
    required this.source,
    required this.createdAt,
    required this.updatedAt,
    this.assignedTo,
    this.assignmentType = 'NONE',
    this.assignedTeamId,
    this.assignedWorkerId,
    this.municipalNotes,
    this.internalNotes,
    this.reporterName,
    this.photos = const [],
    this.verifiedAt,
    this.verifiedBy,
    this.rejectionReason,
  });

  bool get hasValidCoordinates {
    if (latitude.isNaN || longitude.isNaN) return false;
    if (latitude.abs() < 0.0001 && longitude.abs() < 0.0001) return false;
    if (latitude < -90.0 || latitude > 90.0 || longitude < -180.0 || longitude > 180.0) return false;
    return true;
  }

  bool get isDemo => source.toUpperCase() == 'DEMO';

  String get formattedLocation {
    if (!hasValidCoordinates) {
      return 'Location unavailable';
    }
    final latStr = latitude.toStringAsFixed(4);
    final lngStr = longitude.toStringAsFixed(4);
    if (isDemo) {
      return '$latStr, $lngStr (Simulated)';
    }
    return '$latStr, $lngStr';
  }

  factory Incident.fromJson(Map<String, dynamic> json) {
    return Incident(
      id: json['id'] as String,
      category: json['category'] as String,
      description: json['description'] as String,
      latitude: (json['latitude'] as num?)?.toDouble() ?? 0.0,
      longitude: (json['longitude'] as num?)?.toDouble() ?? 0.0,
      severity: json['severity'] as String,
      status: json['status'] as String,
      source: json['source'] as String? ?? 'CITIZEN',
      createdAt: DateTime.parse(json['created_at'] as String),
      updatedAt: DateTime.parse(json['updated_at'] as String),
      assignedTo: json['assigned_to'] as String?,
      assignmentType: json['assignment_type'] as String? ?? 'NONE',
      assignedTeamId: json['assigned_team_id'] as String?,
      assignedWorkerId: json['assigned_worker_id'] as String?,
      municipalNotes: json['municipal_notes'] as String?,
      internalNotes: json['internal_notes'] as String?,
      reporterName: json['reporter_name'] as String?,
      photos: (json['photos'] as List<dynamic>?)
              ?.map((e) => e.toString())
              .toList() ??
          const [],
      verifiedAt: json['verified_at'] != null ? DateTime.tryParse(json['verified_at'] as String) : null,
      verifiedBy: json['verified_by'] as String?,
      rejectionReason: json['rejection_reason'] as String?,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'category': category,
      'description': description,
      'latitude': latitude,
      'longitude': longitude,
      'severity': severity,
      'status': status,
      'source': source,
      'created_at': createdAt.toIso8601String(),
      'updated_at': updatedAt.toIso8601String(),
      'assigned_to': assignedTo,
      'assignment_type': assignmentType,
      'assigned_team_id': assignedTeamId,
      'assigned_worker_id': assignedWorkerId,
      'municipal_notes': municipalNotes,
      'reporter_name': reporterName,
      'photos': photos,
      'verified_at': verifiedAt?.toIso8601String(),
      'verified_by': verifiedBy,
      'rejection_reason': rejectionReason,
    };
  }
}

class FieldTeam {
  final String teamId;
  final String name;
  final String zone;
  final bool isActive;
  final bool isDemo;
  final bool isVerifiedMunicipalCrew;
  final int capacity;
  final String? contactPhone;

  FieldTeam({
    required this.teamId,
    required this.name,
    required this.zone,
    this.isActive = true,
    this.isDemo = true,
    this.isVerifiedMunicipalCrew = false,
    this.capacity = 4,
    this.contactPhone,
  });

  factory FieldTeam.fromJson(Map<String, dynamic> json) {
    return FieldTeam(
      teamId: json['team_id'] as String,
      name: json['name'] as String,
      zone: json['zone'] as String,
      isActive: json['is_active'] as bool? ?? true,
      isDemo: json['is_demo'] as bool? ?? true,
      isVerifiedMunicipalCrew: json['is_verified_municipal_crew'] as bool? ?? false,
      capacity: json['capacity'] as int? ?? 4,
      contactPhone: json['contact_phone'] as String?,
    );
  }
}

class IncidentAudit {
  final String auditId;
  final String incidentId;
  final String actorId;
  final String actorRole;
  final String action;
  final String? previousStatus;
  final String? newStatus;
  final String? previousAssignedTo;
  final String? newAssignedTo;
  final String? previousAssignmentType;
  final String? newAssignmentType;
  final String? previousAssignedTeamId;
  final String? newAssignedTeamId;
  final String? previousAssignedWorkerId;
  final String? newAssignedWorkerId;
  final String? previousSeverity;
  final String? newSeverity;
  final String? reason;
  final String? internalNotes;
  final DateTime timestamp;

  IncidentAudit({
    required this.auditId,
    required this.incidentId,
    required this.actorId,
    required this.actorRole,
    required this.action,
    this.previousStatus,
    this.newStatus,
    this.previousAssignedTo,
    this.newAssignedTo,
    this.previousAssignmentType,
    this.newAssignmentType,
    this.previousAssignedTeamId,
    this.newAssignedTeamId,
    this.previousAssignedWorkerId,
    this.newAssignedWorkerId,
    this.previousSeverity,
    this.newSeverity,
    this.reason,
    this.internalNotes,
    required this.timestamp,
  });

  factory IncidentAudit.fromJson(Map<String, dynamic> json) {
    return IncidentAudit(
      auditId: json['audit_id'] as String,
      incidentId: json['incident_id'] as String,
      actorId: json['actor_id'] as String,
      actorRole: json['actor_role'] as String,
      action: json['action'] as String,
      previousStatus: json['previous_status'] as String?,
      newStatus: json['new_status'] as String?,
      previousAssignedTo: json['previous_assigned_to'] as String?,
      newAssignedTo: json['new_assigned_to'] as String?,
      previousAssignmentType: json['previous_assignment_type'] as String?,
      newAssignmentType: json['new_assignment_type'] as String?,
      previousAssignedTeamId: json['previous_assigned_team_id'] as String?,
      newAssignedTeamId: json['new_assigned_team_id'] as String?,
      previousAssignedWorkerId: json['previous_assigned_worker_id'] as String?,
      newAssignedWorkerId: json['new_assigned_worker_id'] as String?,
      previousSeverity: json['previous_severity'] as String?,
      newSeverity: json['new_severity'] as String?,
      reason: json['reason'] as String?,
      internalNotes: json['internal_notes'] as String?,
      timestamp: DateTime.parse(json['timestamp'] as String),
    );
  }

  String? get changeSummary {
    if (previousStatus != null || newStatus != null) {
      return 'Status: ${previousStatus ?? "(none)"} → ${newStatus ?? "(none)"}';
    }
    if (previousAssignedTo != null || newAssignedTo != null) {
      return 'Assigned To: ${previousAssignedTo ?? "(none)"} → ${newAssignedTo ?? "(none)"}';
    }
    if (previousSeverity != null || newSeverity != null) {
      return 'Severity: ${previousSeverity ?? "(none)"} → ${newSeverity ?? "(none)"}';
    }
    return null;
  }
}

class IncidentConstants {
  static const List<String> categories = [
    'DRAIN_BLOCKAGE',
    'DRAIN_OVERFLOW',
    'WATERLOGGING',
    'FLOODING',
    'MANHOLE_DAMAGE',
    'INFRASTRUCTURE_DAMAGE',
    'OTHER',
  ];

  static const List<String> severities = [
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL',
  ];

  static const List<String> statuses = [
    'REPORTED',
    'VERIFIED',
    'ASSIGNED',
    'INVESTIGATING',
    'RESOLVED',
    'REJECTED',
  ];

  static const List<String> fieldTeams = [
    '[DEMO] Team Alpha — St. Inez Drainage Crew',
    '[DEMO] Team Beta — Patto Rapid Response',
    '[DEMO] Team Gamma — Fontainhas Heritage Maintenance',
    '[DEMO] Team Delta — Miramar Outfall Sluice Unit',
  ];

  static const Map<String, List<String>> validStatusTransitions = {
    'REPORTED': ['VERIFIED', 'ASSIGNED', 'REJECTED'],
    'VERIFIED': ['ASSIGNED', 'REJECTED'],
    'ASSIGNED': ['INVESTIGATING', 'VERIFIED', 'REJECTED'],
    'INVESTIGATING': ['RESOLVED', 'ASSIGNED', 'REJECTED'],
    'RESOLVED': [],
    'REJECTED': [],
  };

  static List<String> getAllowedNextStatuses(String currentStatus) {
    final next = validStatusTransitions[currentStatus] ?? [];
    return [currentStatus, ...next];
  }

  static String formatCategory(String category) {
    return getCategoryDisplayName(category);
  }

  static String getCategoryDisplayName(String category) {
    switch (category) {
      case 'DRAIN_BLOCKAGE':
        return 'Drain Blockage';
      case 'FLOODING':
        return 'Urban Flooding';
      case 'WATERLOGGING':
        return 'Street Waterlogging';
      case 'DRAIN_OVERFLOW':
        return 'Drain Overflow';
      case 'MANHOLE_DAMAGE':
        return 'Manhole Lid Damage';
      case 'INFRASTRUCTURE_DAMAGE':
        return 'Infrastructure Damage';
      case 'OTHER':
      default:
        return 'Other Drainage Issue';
    }
  }

  static String getCategoryDescription(String category) {
    switch (category) {
      case 'DRAIN_BLOCKAGE':
        return 'Culvert, grate, or pipe blocked with debris or silt';
      case 'FLOODING':
        return 'Severe standing water over roadways or properties';
      case 'WATERLOGGING':
        return 'Localized ponding water with sluggish runoff';
      case 'DRAIN_OVERFLOW':
        return 'Stormwater surcharging and overflowing ditch banks';
      case 'MANHOLE_DAMAGE':
        return 'Broken, displaced, or missing manhole cover hazard';
      case 'INFRASTRUCTURE_DAMAGE':
        return 'Collapsed channel wall, broken culvert, or eroded bank';
      case 'OTHER':
      default:
        return 'Miscellaneous stormwater or urban drainage defect';
    }
  }

  static String getSeveritySubtitle(String severity) {
    switch (severity) {
      case 'LOW':
        return 'Minor pooling, no immediate vehicle or pedestrian obstruction';
      case 'MEDIUM':
        return 'Sluggish drainage, curb-level water or visible grate block';
      case 'HIGH':
        return 'Significant water depth, traffic impediment or lane closure';
      case 'CRITICAL':
        return 'Submerged roadways, missing manhole or structural hazard';
      default:
        return '';
    }
  }
}
