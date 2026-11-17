import 'package:flutter/material.dart';
import '../core/theme/app_theme.dart';

class SeverityBadge extends StatelessWidget {
  final String severity;
  final bool isCompact;

  const SeverityBadge({
    super.key,
    required this.severity,
    this.isCompact = false,
  });

  @override
  Widget build(BuildContext context) {
    Color bg;
    Color border;
    Color text;

    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        bg = const Color(0xFF450A0A);
        border = AppTheme.severityCritical;
        text = const Color(0xFFFECACA);
        break;
      case 'HIGH':
        bg = const Color(0xFF431407);
        border = AppTheme.severityHigh;
        text = const Color(0xFFFED7AA);
        break;
      case 'MEDIUM':
        bg = const Color(0xFF451A03);
        border = AppTheme.severityMedium;
        text = const Color(0xFFFDE68A);
        break;
      case 'LOW':
      default:
        bg = const Color(0xFF064E3B);
        border = AppTheme.severityLow;
        text = const Color(0xFFA7F3D0);
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
        severity.toUpperCase(),
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
