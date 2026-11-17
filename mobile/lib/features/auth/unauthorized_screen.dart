import 'package:flutter/material.dart';
import '../../core/auth/auth_service.dart';
import '../../core/theme/app_theme.dart';
import '../../models/user_session.dart';
import '../../app/routes.dart';

class UnauthorizedScreen extends StatelessWidget {
  final UserRole? requiredRole;
  final UserRole? userRole;

  const UnauthorizedScreen({
    super.key,
    this.requiredRole,
    this.userRole,
  });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0F172A),
      appBar: AppBar(
        title: const Text('Access Denied'),
        backgroundColor: const Color(0xFF1E293B),
        automaticallyImplyLeading: false,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: const Color(0xFF450A0A),
                  shape: BoxShape.circle,
                  border: Border.all(color: const Color(0xFFDC2626), width: 2),
                ),
                child: const Icon(
                  Icons.shield_outlined,
                  size: 56,
                  color: Color(0xFFFCA5A5),
                ),
              ),
              const SizedBox(height: 24),
              const Text(
                'Role-Based Authorization Required',
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
              ),
              const SizedBox(height: 12),
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: const Color(0xFF1E293B),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: const Color(0xFF334155)),
                ),
                child: Column(
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Text(
                          'Your Active Role:',
                          style: TextStyle(fontSize: 12, color: Color(0xFF94A3B8)),
                        ),
                        Text(
                          userRole?.displayName ?? 'Unauthenticated / Guest',
                          style: const TextStyle(
                            fontSize: 12,
                            fontWeight: FontWeight.bold,
                            color: Color(0xFF38BDF8),
                          ),
                        ),
                      ],
                    ),
                    const Divider(color: Color(0xFF334155), height: 16),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Text(
                          'Required Role:',
                          style: TextStyle(fontSize: 12, color: Color(0xFF94A3B8)),
                        ),
                        Text(
                          requiredRole?.displayName ?? 'Privileged Role',
                          style: const TextStyle(
                            fontSize: 12,
                            fontWeight: FontWeight.bold,
                            color: Color(0xFFF87171),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              const Text(
                'Anti-Privilege Escalation Notice:\nClient-side role spoofing and unauthorized parameter manipulation are rejected by backend security policies.',
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 11,
                  color: Color(0xFF64748B),
                  height: 1.4,
                ),
              ),
              const Spacer(),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppTheme.accentTeal,
                  ),
                  onPressed: () {
                    AuthService().logout();
                    Navigator.pushNamedAndRemoveUntil(
                      context,
                      AppRoutes.welcome,
                      (route) => false,
                    );
                  },
                  icon: const Icon(Icons.logout, color: Color(0xFF0F172A)),
                  label: const Text(
                    'RETURN TO WELCOME PORTAL',
                    style: TextStyle(color: Color(0xFF0F172A), fontWeight: FontWeight.bold),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
