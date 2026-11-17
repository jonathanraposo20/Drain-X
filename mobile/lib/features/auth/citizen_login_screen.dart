import 'package:flutter/material.dart';
import '../../core/auth/auth_service.dart';
import '../../core/theme/app_theme.dart';
import '../../models/user_session.dart';
import '../citizen/citizen_dashboard_screen.dart';

class CitizenLoginScreen extends StatefulWidget {
  const CitizenLoginScreen({super.key});

  @override
  State<CitizenLoginScreen> createState() => _CitizenLoginScreenState();
}

class _CitizenLoginScreenState extends State<CitizenLoginScreen> {
  static const String _customIdentityMarker = '__CUSTOM__';

  final List<String> _demoIdentities = [
    'P. Fernandes (St. Inez Resident)',
    'R. Naik (Patto Plaza Commuter)',
    'M. Coutinho (Fontainhas Heritage Watch)',
    'Citizen Anonymous',
  ];

  late String _selectedOption;
  final TextEditingController _customNameController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _selectedOption = _demoIdentities[0];
  }

  void _proceedToCitizenDashboard() {
    final reporterName = (_selectedOption == _customIdentityMarker)
        ? (_customNameController.text.trim().isEmpty ? 'Citizen Anonymous' : _customNameController.text.trim())
        : _selectedOption;

    AuthService().loginDemo(
      role: UserRole.citizen,
      displayName: reporterName,
    );

    Navigator.pushReplacement(
      context,
      MaterialPageRoute(
        builder: (_) => CitizenDashboardScreen(reporterName: reporterName),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Citizen Demo Login'),
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
                      color: const Color(0xFFCFFAFE),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: const Icon(Icons.person_pin_circle, size: 28, color: Color(0xFF0891B2)),
                  ),
                  const SizedBox(width: 12),
                  const Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Citizen Reporting Identity',
                        style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Color(0xFF0F172A)),
                      ),
                      Text(
                        'Select a demo persona for competition testing',
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
                  color: const Color(0xFFF0FDF4),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFFBBF7D0)),
                ),
                child: const Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(Icons.info_outline, size: 16, color: Color(0xFF16A34A)),
                    SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'COMPETITION MVP NOTICE: Real user registration is deferred to production rollout. In demo mode, reports submitted are stored in memory and broadcasted live to the GIS map and Municipal Operations.',
                        style: TextStyle(fontSize: 11, color: Color(0xFF166534), height: 1.4),
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 24),

              const Text(
                'PREDEFINED DEMONSTRATION IDENTITIES',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Color(0xFF475569), letterSpacing: 0.5),
              ),
              const SizedBox(height: 8),

              RadioGroup<String>(
                groupValue: _selectedOption,
                onChanged: (val) {
                  if (val != null) {
                    setState(() {
                      _selectedOption = val;
                    });
                  }
                },
                child: Column(
                  children: [
                    ..._demoIdentities.map((identity) {
                      final isSelected = _selectedOption == identity;
                      return Padding(
                        padding: const EdgeInsets.only(bottom: 8),
                        child: Material(
                          color: isSelected ? const Color(0xFFECFEFF) : Colors.white,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(10),
                            side: BorderSide(
                              color: isSelected ? const Color(0xFF06B6D4) : const Color(0xFFE2E8F0),
                              width: isSelected ? 1.5 : 1,
                            ),
                          ),
                          child: RadioListTile<String>(
                            title: Text(
                              identity,
                              style: TextStyle(
                                fontSize: 13,
                                fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
                                color: const Color(0xFF0F172A),
                              ),
                            ),
                            value: identity,
                            activeColor: AppTheme.accentTeal,
                          ),
                        ),
                      );
                    }),
                    const SizedBox(height: 12),
                    // Custom Name Input Toggle
                    Material(
                      color: (_selectedOption == _customIdentityMarker) ? const Color(0xFFECFEFF) : Colors.white,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                        side: BorderSide(
                          color: (_selectedOption == _customIdentityMarker) ? const Color(0xFF06B6D4) : const Color(0xFFE2E8F0),
                          width: (_selectedOption == _customIdentityMarker) ? 1.5 : 1,
                        ),
                      ),
                      child: Column(
                        children: [
                          const RadioListTile<String>(
                            title: Text(
                              'Custom Reporter Name',
                              style: TextStyle(fontSize: 13, color: Color(0xFF0F172A)),
                            ),
                            value: _customIdentityMarker,
                            activeColor: AppTheme.accentTeal,
                          ),
                          if (_selectedOption == _customIdentityMarker)
                            Padding(
                              padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                              child: TextField(
                                controller: _customNameController,
                                decoration: const InputDecoration(
                                  labelText: 'Your Name or Resident Handle',
                                  hintText: 'e.g. Maria Fernandes',
                                ),
                              ),
                            ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 32),

              // Action Button
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: _proceedToCitizenDashboard,
                  icon: const Icon(Icons.login),
                  label: const Text('ENTER CITIZEN PORTAL'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
