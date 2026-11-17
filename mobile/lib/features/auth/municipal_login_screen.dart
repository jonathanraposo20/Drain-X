import 'package:flutter/material.dart';
import '../../core/auth/auth_service.dart';
import '../../models/user_session.dart';
import '../municipal/municipal_dashboard_screen.dart';

class MunicipalLoginScreen extends StatefulWidget {
  const MunicipalLoginScreen({super.key});

  @override
  State<MunicipalLoginScreen> createState() => _MunicipalLoginScreenState();
}

class _MunicipalLoginScreenState extends State<MunicipalLoginScreen> {
  final List<String> _demoOfficers = [
    'Eng. J. Coutinho (Panaji Ward Drainage Officer)',
    'Field Supv. A. Rao (St. Inez Rapid Response)',
    'Operator M. Fernandes (Miramar Outfall Unit)',
  ];

  late String _selectedOfficer;

  @override
  void initState() {
    super.initState();
    _selectedOfficer = _demoOfficers[0];
  }

  void _proceedToMunicipalDashboard() {
    AuthService().loginDemo(
      role: UserRole.municipality,
      displayName: _selectedOfficer,
    );

    Navigator.pushReplacement(
      context,
      MaterialPageRoute(
        builder: (_) => MunicipalDashboardScreen(officerName: _selectedOfficer),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Municipal Demo Login'),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header Icon and Title
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: const Color(0xFFE0E7FF),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: const Icon(Icons.shield, size: 28, color: Color(0xFF4338CA)),
                  ),
                  const SizedBox(width: 12),
                  const Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Municipal Field Console',
                        style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Color(0xFF0F172A)),
                      ),
                      Text(
                        'City Drainage Works & Dispatch Operations',
                        style: TextStyle(fontSize: 12, color: Color(0xFF64748B)),
                      ),
                    ],
                  ),
                ],
              ),

              const SizedBox(height: 20),

              // Demo Notice Banner
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: const Color(0xFFEFF6FF),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFFBFDBFE)),
                ),
                child: const Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(Icons.lock_open, size: 16, color: Color(0xFF2563EB)),
                    SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'DEMO MODE: Password authentication is disabled for evaluation. Selecting an officer role grants triage and ticket lifecycle transition authorization.',
                        style: TextStyle(fontSize: 11, color: Color(0xFF1E40AF), height: 1.4),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              const Text(
                'FIELD OPERATOR / SUPERVISOR IDENTITY',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF475569), letterSpacing: 0.5),
              ),
              const SizedBox(height: 8),

              RadioGroup<String>(
                groupValue: _selectedOfficer,
                onChanged: (val) {
                  if (val != null) {
                    setState(() {
                      _selectedOfficer = val;
                    });
                  }
                },
                child: Column(
                  children: _demoOfficers.map((officer) {
                    final isSelected = _selectedOfficer == officer;
                    return Padding(
                      padding: const EdgeInsets.only(bottom: 8),
                      child: Material(
                        color: isSelected ? const Color(0xFFEEF2FF) : Colors.white,
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(10),
                          side: BorderSide(
                            color: isSelected ? const Color(0xFF4F46E5) : const Color(0xFFE2E8F0),
                            width: isSelected ? 1.5 : 1,
                          ),
                        ),
                        child: RadioListTile<String>(
                          title: Text(
                            officer,
                            style: TextStyle(
                              fontSize: 13,
                              fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                              color: const Color(0xFF0F172A),
                            ),
                          ),
                          value: officer,
                          activeColor: const Color(0xFF4F46E5),
                        ),
                      ),
                    );
                  }).toList(),
                ),
              ),

              const SizedBox(height: 32),

              // Action Button
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF4F46E5),
                  ),
                  onPressed: _proceedToMunicipalDashboard,
                  icon: const Icon(Icons.admin_panel_settings_outlined),
                  label: const Text('ENTER MUNICIPAL OPERATIONS'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
