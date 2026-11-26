import 'package:flutter/material.dart';
import '../../core/config/api_config.dart';
import '../../core/theme/app_theme.dart';
import '../../core/auth/auth_service.dart';
import '../../models/user_session.dart';
import 'citizen_login_screen.dart';
import 'municipal_login_screen.dart';
import 'worker_login_screen.dart';
import 'supabase_login_screen.dart';
import '../citizen/citizen_dashboard_screen.dart';
import '../municipal/municipal_dashboard_screen.dart';
import '../worker/worker_dashboard_screen.dart';

class WelcomeScreen extends StatefulWidget {
  const WelcomeScreen({super.key});

  @override
  State<WelcomeScreen> createState() => _WelcomeScreenState();
}

class _WelcomeScreenState extends State<WelcomeScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      final session = AuthService().currentSession;
      if (session == null || !session.isAuthenticated) return;

      final destination = switch (session.role) {
        UserRole.citizen => '/citizen/dashboard',
        UserRole.municipality => '/municipal/dashboard',
        UserRole.fieldWorker => '/worker/dashboard',
      };
      Navigator.of(context).pushReplacementNamed(destination);
    });
  }

  void _openBackendConfigDialog() {
    final controller = TextEditingController(text: ApiConfig.baseUrl);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('DRAIN-X API Configuration', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Set FastAPI backend address reachable from this device:',
              style: TextStyle(fontSize: 12, color: Color(0xFF64748B)),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: controller,
              decoration: const InputDecoration(
                labelText: 'Base URL',
                hintText: 'http://10.0.2.2:8000',
              ),
              style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
            ),
            const SizedBox(height: 12),
            const Text(
              'Presets:',
              style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF475569)),
            ),
            const SizedBox(height: 4),
            ...ApiConfig.presetEnvironments.entries.map(
              (entry) => InkWell(
                onTap: () => controller.text = entry.value,
                child: Padding(
                  padding: const EdgeInsets.symmetric(vertical: 4),
                  child: Text(
                    '• ${entry.key}',
                    style: const TextStyle(fontSize: 11, color: AppTheme.accentTeal),
                  ),
                ),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () {
              setState(() {
                ApiConfig.baseUrl = controller.text.trim();
              });
              Navigator.pop(ctx);
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text('API Base URL set to: ${ApiConfig.baseUrl}')),
              );
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.primaryNavy,
      body: SafeArea(
        child: SingleChildScrollView(
          child: Column(
            children: [
            // Top Bar with Demo Indicator and Settings
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(
                      color: const Color(0xFF083344),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: const Color(0xFF06B6D4)),
                    ),
                    child: const Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.military_tech_outlined, size: 14, color: AppTheme.accentCyan),
                        SizedBox(width: 4),
                        Text(
                          'COMPETITION MVP DEMO',
                          style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                            color: Color(0xFF67E8F9),
                            letterSpacing: 0.5,
                          ),
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.settings_outlined, color: Colors.white70),
                    onPressed: _openBackendConfigDialog,
                    tooltip: 'Configure Backend API URL',
                  ),
                ],
              ),
            ),

            const SizedBox(height: 16),

            // Hero Branding
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24),
              child: Column(
                children: [
                  Container(
                    width: 80,
                    height: 80,
                    decoration: BoxDecoration(
                      color: const Color(0xFF083344),
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(color: AppTheme.accentCyan, width: 2),
                      boxShadow: [
                        BoxShadow(
                          color: AppTheme.accentCyan.withValues(alpha: 0.3),
                          blurRadius: 20,
                          offset: const Offset(0, 4),
                        ),
                      ],
                    ),
                    child: const Icon(
                      Icons.water_damage_outlined,
                      size: 44,
                      color: AppTheme.accentCyan,
                    ),
                  ),
                  const SizedBox(height: 20),
                  const Text(
                    'DRAIN-X',
                    style: TextStyle(
                      fontSize: 32,
                      fontWeight: FontWeight.w900,
                      color: Colors.white,
                      letterSpacing: 2,
                    ),
                  ),
                  const SizedBox(height: 6),
                  const Text(
                    'Integrated Urban Flood Intelligence',
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w500,
                      color: Color(0xFF67E8F9),
                      letterSpacing: 0.5,
                    ),
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Citizen early-warning reporting & municipal field operations platform for coastal urban drainage management.',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      fontSize: 12,
                      color: Color(0xFF94A3B8),
                      height: 1.4,
                    ),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 16),

            // Active Session Resume Banner (if authenticated)
            if (AuthService().isLoggedIn) ...[
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                  decoration: BoxDecoration(
                    color: const Color(0xFF1E293B),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: AppTheme.accentTeal),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.verified_user_outlined, color: AppTheme.accentTeal, size: 20),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Active: ${AuthService().currentSession!.name}',
                              style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Colors.white),
                            ),
                            Text(
                              AuthService().currentSession!.role.displayName,
                              style: const TextStyle(fontSize: 10, color: Color(0xFF94A3B8)),
                            ),
                          ],
                        ),
                      ),
                      TextButton(
                        onPressed: () {
                          final session = AuthService().currentSession!;
                          if (session.role == UserRole.citizen) {
                            Navigator.push(context, MaterialPageRoute(builder: (_) => CitizenDashboardScreen(reporterName: session.name)));
                          } else if (session.role == UserRole.municipality) {
                            Navigator.push(context, MaterialPageRoute(builder: (_) => MunicipalDashboardScreen(officerName: session.name)));
                          } else {
                            Navigator.push(context, MaterialPageRoute(builder: (_) => WorkerDashboardScreen(workerName: session.name, assignedTeam: session.assignedTeam ?? 'Team Alpha')));
                          }
                        },
                        child: const Text('RESUME', style: TextStyle(fontSize: 11, color: AppTheme.accentTeal, fontWeight: FontWeight.bold)),
                      ),
                      IconButton(
                        icon: const Icon(Icons.close, size: 16, color: Colors.white54),
                        tooltip: 'Logout',
                        onPressed: () {
                          setState(() {
                            AuthService().logout();
                          });
                        },
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 12),
            ],

            // Real Supabase account sign-in is separate from the demo portals.
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: SizedBox(
                width: double.infinity,
                child: OutlinedButton.icon(
                  onPressed: () {
                    Navigator.push(
                      context,
                      MaterialPageRoute(builder: (_) => const SupabaseLoginScreen()),
                    );
                  },
                  icon: const Icon(Icons.lock_outline),
                  label: const Text('Sign in with DRAIN-X account'),
                  style: OutlinedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    foregroundColor: AppTheme.accentTeal,
                    side: const BorderSide(color: AppTheme.accentTeal),
                  ),
                ),
              ),
            ),
            const SizedBox(height: 12),

            // Three Distinct Entry Experience Cards (Demo Mode)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Column(
                children: [
                  // 1. Citizen Portal Card
                  InkWell(
                    onTap: () {
                      Navigator.push(
                        context,
                        MaterialPageRoute(builder: (_) => const CitizenLoginScreen()),
                      );
                    },
                    borderRadius: BorderRadius.circular(14),
                    child: Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        gradient: const LinearGradient(
                          colors: [Color(0xFF0E7490), Color(0xFF083344)],
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                        ),
                        borderRadius: BorderRadius.circular(14),
                        border: Border.all(color: const Color(0xFF22D3EE), width: 1.2),
                      ),
                      child: Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: Colors.white.withValues(alpha: 0.15),
                              borderRadius: BorderRadius.circular(10),
                            ),
                            child: const Icon(Icons.person_pin_circle_outlined, size: 28, color: Colors.white),
                          ),
                          const SizedBox(width: 14),
                          const Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  'CITIZEN PORTAL',
                                  style: TextStyle(
                                    fontSize: 15,
                                    fontWeight: FontWeight.bold,
                                    color: Colors.white,
                                    letterSpacing: 0.5,
                                  ),
                                ),
                                SizedBox(height: 3),
                                Text(
                                  'Report drainage blockage, waterlogging & track municipal resolution.',
                                  style: TextStyle(fontSize: 11, color: Color(0xFFE2E8F0)),
                                ),
                              ],
                            ),
                          ),
                          const Icon(Icons.arrow_forward_ios, size: 16, color: Colors.white70),
                        ],
                      ),
                    ),
                  ),

                  const SizedBox(height: 12),

                  // 2. Municipal Operations Card
                  InkWell(
                    onTap: () {
                      Navigator.push(
                        context,
                        MaterialPageRoute(builder: (_) => const MunicipalLoginScreen()),
                      );
                    },
                    borderRadius: BorderRadius.circular(14),
                    child: Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: const Color(0xFF1E293B),
                        borderRadius: BorderRadius.circular(14),
                        border: Border.all(color: const Color(0xFF475569)),
                      ),
                      child: Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: const Color(0xFF334155),
                              borderRadius: BorderRadius.circular(10),
                            ),
                            child: const Icon(Icons.shield_outlined, size: 28, color: Color(0xFF38BDF8)),
                          ),
                          const SizedBox(width: 14),
                          const Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  'MUNICIPAL OPERATIONS',
                                  style: TextStyle(
                                    fontSize: 15,
                                    fontWeight: FontWeight.bold,
                                    color: Colors.white,
                                    letterSpacing: 0.5,
                                  ),
                                ),
                                SizedBox(height: 3),
                                Text(
                                  'Field crew triage, work-order dispatch & incident lifecycle management.',
                                  style: TextStyle(fontSize: 11, color: Color(0xFF94A3B8)),
                                ),
                              ],
                            ),
                          ),
                          const Icon(Icons.arrow_forward_ios, size: 16, color: Color(0xFF94A3B8)),
                        ],
                      ),
                    ),
                  ),

                  const SizedBox(height: 12),

                  // 3. Field Worker Portal Card
                  InkWell(
                    onTap: () {
                      Navigator.push(
                        context,
                        MaterialPageRoute(builder: (_) => const WorkerLoginScreen()),
                      );
                    },
                    borderRadius: BorderRadius.circular(14),
                    child: Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: const Color(0xFF1E293B),
                        borderRadius: BorderRadius.circular(14),
                        border: Border.all(color: const Color(0xFFD97706), width: 1.2),
                      ),
                      child: Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: const Color(0xFF451A03),
                              borderRadius: BorderRadius.circular(10),
                            ),
                            child: const Icon(Icons.handyman_outlined, size: 28, color: Color(0xFFF59E0B)),
                          ),
                          const SizedBox(width: 14),
                          const Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  'FIELD WORKER PORTAL',
                                  style: TextStyle(
                                    fontSize: 15,
                                    fontWeight: FontWeight.bold,
                                    color: Colors.white,
                                    letterSpacing: 0.5,
                                  ),
                                ),
                                SizedBox(height: 3),
                                Text(
                                  'Drainage maintenance crew, task triage, observation logs & site evidence.',
                                  style: TextStyle(fontSize: 11, color: Color(0xFF94A3B8)),
                                ),
                              ],
                            ),
                          ),
                          const Icon(Icons.arrow_forward_ios, size: 16, color: Color(0xFFF59E0B)),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 24),

            // Active Backend Host Footer
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Text(
                'API Target: ${ApiConfig.baseUrl}',
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 11,
                  color: Color(0xFF64748B),
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
