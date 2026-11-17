import 'package:flutter/material.dart';
import '../core/theme/app_theme.dart';

class StatusBadge extends StatelessWidget {
  final String status;
  final bool isCompact;

  const StatusBadge({
    super.key,
    required this.status,
    this.isCompact = false,
  });

  @override
  Widget build(BuildContext context) {
    Color bg;
    Color border;
    Color text;

    switch (status.toUpperCase()) {
      case 'REPORTED':
        bg = const Color(0xFF172554);
        border = AppTheme.statusReported;
        text = const Color(0xFFBFDBFE);
        break;
      case 'VERIFIED':
        bg = const Color(0xFF3B0764);
        border = AppTheme.statusVerified;
        text = const Color(0xFFE9D5FF);
        break;
      case 'ASSIGNED':
        bg = const Color(0xFF1E1B4B);
        border = AppTheme.statusAssigned;
        text = const Color(0xFFC7D2FE);
        break;
      case 'INVESTIGATING':
        bg = const Color(0xFF422006);
        border = AppTheme.statusInvestigating;
        text = const Color(0xFFFEF08A);
        break;
      case 'RESOLVED':
        bg = const Color(0xFF022C22);
        border = AppTheme.statusResolved;
        text = const Color(0xFFA7F3D0);
        break;
      case 'REJECTED':
      default:
        bg = const Color(0xFF0F172A);
        border = AppTheme.statusRejected;
        text = const Color(0xFF94A3B8);
        break;
    }

    return Container(
      padding: EdgeInsets.symmetric(
        horizontal: isCompact ? 6 : 8,
        vertical: isCompact ? 2 : 4,
      ),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: border, width: 1),
      ),
      child: Text(
        status.toUpperCase(),
        style: TextStyle(
          color: text,
          fontSize: isCompact ? 10 : 11,
          fontWeight: FontWeight.bold,
          letterSpacing: 0.5,
        ),
      ),
    );
  }
}
